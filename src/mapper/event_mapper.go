package mapper

import (
	"bpf-detect/config"
	"bpf-detect/patterns"
	"bpf-detect/resolver"
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Event struct {
	EventType string
	Pid       int
	Cid       uint64
	Comm      string
	Filename  string
}

type EventMapper struct {
	resolver  *resolver.CGroupResolver
	writers   map[string]*os.File
	eventChan chan Event
	wg        sync.WaitGroup
}

func NewEventMapper() *EventMapper {
	em := &EventMapper{
		resolver:  resolver.NewCGroupResolver(),
		writers:   make(map[string]*os.File),
		eventChan: make(chan Event, config.EventBufferSize),
	}

	// Start worker pool
	for i := 0; i < config.WorkerCount; i++ {
		em.wg.Add(1)
		go em.worker()
	}

	return em
}

func (e *EventMapper) Close() {
	close(e.eventChan)
	e.wg.Wait()
	for _, f := range e.writers {
		f.Close()
	}
}

func (e *EventMapper) worker() {
	defer e.wg.Done()
	for evt := range e.eventChan {
		e.handleEvent(evt)
	}
}

func (e *EventMapper) Run() {
	fmt.Println("Starting to read events...")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		e.processLine(strings.TrimSpace(scanner.Text()))
	}
}

func (e *EventMapper) ProcessEvent(eventType string, pid int, cid uint64, comm string, filename string) {
	select {
	case e.eventChan <- Event{
		EventType: eventType,
		Pid:       pid,
		Cid:       cid,
		Comm:      comm,
		Filename:  filename,
	}:
	default:
		if config.Debug {
			fmt.Println("WARNING: Event channel full, dropping event")
		}
	}
}

func (e *EventMapper) handleEvent(evt Event) {
	filename := evt.Filename
	pid := evt.Pid

	// Resolve relative paths to absolute paths
	if filename != "" && !filepath.IsAbs(filename) {
		if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid)); err == nil {
			filename = filepath.Join(cwd, filename)
		}
	}

	data := map[string]string{
		"pid":      strconv.Itoa(pid),
		"cid":      strconv.FormatUint(evt.Cid, 10),
		"comm":     evt.Comm,
		"filepath": filename,
	}

	meta := e.resolver.ResolveCgroupMetadata(evt.Cid, pid)

	if e.shouldIgnore(meta.Type, meta.Info, evt.Comm) {
		return
	}

	e.printEvent(evt.EventType, data, meta.Type, meta.Info)
}

func (e *EventMapper) processLine(line string) {
	var eventType string
	data := make(map[string]string)

	if m := patterns.ExecveLog.FindStringSubmatch(line); m != nil {
		eventType = "EXECVE"
		for i, name := range patterns.ExecveLog.SubexpNames() {
			if i != 0 && name != "" {
				data[name] = m[i]
			}
		}
	} else if m := patterns.OpenLog.FindStringSubmatch(line); m != nil {
		eventType = "OPEN"
		for i, name := range patterns.OpenLog.SubexpNames() {
			if i != 0 && name != "" {
				data[name] = m[i]
			}
		}
	}

	if eventType == "" {
		return
	}

	pid, _ := strconv.Atoi(data["pid"])
	cid, _ := strconv.ParseUint(data["cid"], 10, 64)

	// For legacy line processing, we can just construct an Event and send it to the channel
	// to benefit from the worker pool, or process directly.
	// Since Run() is single threaded reading stdin, sending to channel is fine.
	// However, processLine logic is slightly different (parsing regex).
	// Let's just keep processLine synchronous or adapt it.
	// The request was about ProcessEvent (BPF path).
	// But to be consistent, let's use the channel.
	// But wait, processLine parses data map which might have extra fields (argv) that Event struct doesn't have?
	// Event struct has: EventType, Pid, Cid, Comm, Filename.
	// processLine extracts these.
	// So we can map them.

	comm := data["comm"]
	filename := data["filepath"]

	e.ProcessEvent(eventType, pid, cid, comm, filename)
}

func (e *EventMapper) shouldIgnore(ctype string, info map[string]interface{}, comm string) bool {
	if !config.FilterSystemEvents {
		return false
	}
	if config.IgnoredCommands[comm] {
		return true
	}
	if strings.HasPrefix(comm, "runc:") {
		return true
	}
	if ctype == "k8s" {
		if ns, ok := info["namespace"].(string); ok {
			if config.IgnoreK8sNamespaces[ns] {
				return true
			}
		}
	}
	return false
}

func (e *EventMapper) getWriter(filename string) (*os.File, error) {
	if w, ok := e.writers[filename]; ok {
		return w, nil
	}
	fullPath := filepath.Join(config.OutputDir, filename)
	f, err := os.OpenFile(fullPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	e.writers[filename] = f
	return f, nil
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r == ':' || r == '/' || r == '\\' {
			return '_'
		}
		return r
	}, s)
}

func (e *EventMapper) printEvent(eventType string, data map[string]string, metaType string, metaInfo map[string]interface{}) {
	pid := data["pid"]
	comm := data["comm"]
	filename := filepath.Base(data["filepath"])
	fpath := data["filepath"]

	var logLine string
	var logFileName string

	// Determine log filename
	switch metaType {
	case "docker":
		image, _ := metaInfo["image"].(string)
		if image == "" {
			image = "unknown"
		}
		logFileName = fmt.Sprintf("detect_%s.log", sanitize(image))
	case "k8s":
		image, _ := metaInfo["images"].(string)
		if image == "" {
			image = "unknown"
		}
		logFileName = fmt.Sprintf("detect_%s.log", sanitize(image))
	case "host":
		if config.PrintHostEvents {
			logFileName = "detect_host.log"
		}
	default:
		logFileName = "detect_unknown.log"
	}

	if logFileName == "" {
		return
	}

	timestamp := time.Now().Format(time.RFC3339)

	if config.OutputFormat == "json" {
		entry := map[string]interface{}{
			"type":      metaType,
			"event":     eventType,
			"pid":       pid,
			"comm":      comm,
			"filename":  filename,
			"filepath":  fpath,
			"timestamp": timestamp,
		}
		for k, v := range metaInfo {
			entry[k] = v
		}
		bytes, _ := json.Marshal(entry)
		logLine = string(bytes) + "\n"
	} else {
		prefix := fmt.Sprintf("[%s][%s][%s]", timestamp, strings.ToUpper(metaType), eventType)

		switch metaType {
		case "docker":
			logLine = fmt.Sprintf("%s pid=%s comm=%s filename=%s filepath=%s container=%v image=%v cid=%v\n",
				prefix, pid, comm, filename, fpath, metaInfo["container_name"], metaInfo["image"], metaInfo["container_id"])
		case "k8s":
			logLine = fmt.Sprintf("%s pid=%s comm=%s filename=%s filepath=%s ns=%v pod=%v images=%v pod_uid=%v cid=%v\n",
				prefix, pid, comm, filename, fpath, metaInfo["namespace"], metaInfo["pod_name"], metaInfo["images"], metaInfo["pod_uid"], metaInfo["container_id"])
		case "host":
			cgroupPaths, _ := metaInfo["cgroup_paths"].([]string)
			logLine = fmt.Sprintf("%s pid=%s comm=%s filename=%s filepath=%s cgroup_path=%s\n",
				prefix, pid, comm, filename, fpath, strings.Join(cgroupPaths, ","))
		default:
			logLine = fmt.Sprintf("%s pid=%s comm=%s filename=%s filepath=%s cgroup_id=%s\n",
				prefix, pid, comm, filename, fpath, data["cid"])
		}
	}

	if logLine != "" {
		w, err := e.getWriter(logFileName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to %s: %v\n", logFileName, err)
			return
		}
		fmt.Fprint(w, logLine)
	}
}

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
	writersMu sync.Mutex
	eventChan chan Event
	wg        sync.WaitGroup
	selfPid   int
}

func NewEventMapper() *EventMapper {
	em := &EventMapper{
		resolver:  resolver.NewCGroupResolver(),
		writers:   make(map[string]*os.File),
		eventChan: make(chan Event, config.EventBufferSize),
		selfPid:   os.Getpid(),
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

	e.writersMu.Lock()
	defer e.writersMu.Unlock()

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

	originalFilename := filename
	meta := e.resolver.ResolveCgroupMetadata(evt.Cid, pid)

	if e.shouldIgnore(meta.Type, meta.Info, evt.Comm, pid, filename) {
		return
	}

	// First event: Original filename
	data := map[string]string{
		"pid":           strconv.Itoa(pid),
		"cid":           strconv.FormatUint(evt.Cid, 10),
		"comm":          evt.Comm,
		"filepath":      originalFilename,
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
	comm := data["comm"]
	filename := filepath.Base(data["filepath"])

	e.ProcessEvent(eventType, pid, cid, comm, filename)
}

func (e *EventMapper) shouldIgnore(ctype string, info map[string]interface{}, comm string, pid int, filename string) bool {
	// 1. Filter self
	if pid == e.selfPid {
		return true
	}

	if !config.FilterSystemEvents {
		return false
	}

	// 2. Dynamic Filtering
	for _, rule := range config.Filters {
		if e.matchRule(rule, ctype, info, comm, pid, filename) {
			return true
		}
	}

	return false
}

func (e *EventMapper) matchRule(rule config.FilterRule, ctype string, info map[string]interface{}, comm string, pid int, filename string) bool {
	for _, cond := range rule.Conditions {
		if !e.matchCondition(cond, ctype, info, comm, pid, filename) {
			return false // All conditions must match (AND)
		}
	}
	return true
}

func (e *EventMapper) matchCondition(cond config.FilterCondition, ctype string, info map[string]interface{}, comm string, pid int, filename string) bool {
	val := e.resolveValue(cond.Field, ctype, info, comm, pid, filename)
	if val == nil {
		return false
	}

	switch cond.Operator {
	case "equals":
		return e.opEquals(val, cond.Value)
	case "not_equals":
		return e.opNotEquals(val, cond.Value)
	case "prefix":
		return e.opPrefix(val, cond.Value)
	case "not_prefix":
		return e.opNotPrefix(val, cond.Value)
	case "suffix":
		return e.opSuffix(val, cond.Value)
	case "not_suffix":
		return e.opNotSuffix(val, cond.Value)
	case "contains":
		return e.opContains(val, cond.Value)
	case "not_contains":
		return e.opNotContains(val, cond.Value)
	case "in":
		return e.opIn(val, cond.Value)
	case "not_in":
		return e.opNotIn(val, cond.Value)
	}
	return false
}

func (e *EventMapper) resolveValue(field string, ctype string, info map[string]interface{}, comm string, pid int, filename string) interface{} {
	switch field {
	case "type":
		return ctype
	case "pid":
		return pid
	case "comm":
		return comm
	case "filepath":
		return filename
	case "cgroup_paths":
		if paths, ok := info["cgroup_paths"].([]string); ok {
			return paths
		}
		return nil
	default:
		if v, ok := info[field]; ok {
			return v
		}
		return nil
	}
}

func (e *EventMapper) getStringSlice(v interface{}) []string {
	if s, ok := v.([]string); ok {
		return s
	}
	if s, ok := v.([]interface{}); ok {
		var res []string
		for _, item := range s {
			if str, ok := item.(string); ok {
				res = append(res, str)
			}
		}
		return res
	}
	if s, ok := v.(string); ok {
		return []string{s}
	}
	return nil
}

func (e *EventMapper) opEquals(val, condVal interface{}) bool {
	if listVal, ok := val.([]string); ok {
		if s, ok := condVal.(string); ok {
			for _, item := range listVal {
				if item == s {
					return true
				}
			}
			return false
		}
		return false
	}
	if iVal, ok := val.(int); ok {
		if fVal, ok := condVal.(float64); ok {
			return iVal == int(fVal)
		}
		if iVal2, ok := condVal.(int); ok {
			return iVal == iVal2
		}
	}
	return val == condVal
}

func (e *EventMapper) opNotEquals(val, condVal interface{}) bool {
	if listVal, ok := val.([]string); ok {
		if s, ok := condVal.(string); ok {
			for _, item := range listVal {
				if item == s {
					return false
				}
			}
			return true
		}
		return true
	}
	if iVal, ok := val.(int); ok {
		if fVal, ok := condVal.(float64); ok {
			return iVal != int(fVal)
		}
		if iVal2, ok := condVal.(int); ok {
			return iVal != iVal2
		}
	}
	return val != condVal
}

func (e *EventMapper) opPrefix(val, condVal interface{}) bool {
	prefixes := e.getStringSlice(condVal)
	if prefixes == nil {
		return false
	}

	if listVal, ok := val.([]string); ok {
		for _, item := range listVal {
			for _, p := range prefixes {
				if strings.HasPrefix(item, p) {
					return true
				}
			}
		}
		return false
	}

	if strVal, ok := val.(string); ok {
		for _, p := range prefixes {
			if strings.HasPrefix(strVal, p) {
				return true
			}
		}
	}
	return false
}

func (e *EventMapper) opNotPrefix(val, condVal interface{}) bool {
	prefixes := e.getStringSlice(condVal)
	if prefixes == nil {
		return true
	}

	if listVal, ok := val.([]string); ok {
		for _, item := range listVal {
			for _, p := range prefixes {
				if strings.HasPrefix(item, p) {
					return false
				}
			}
		}
		return true
	}

	if strVal, ok := val.(string); ok {
		for _, p := range prefixes {
			if strings.HasPrefix(strVal, p) {
				return false
			}
		}
		return true
	}
	return true
}

func (e *EventMapper) opSuffix(val, condVal interface{}) bool {
	suffixes := e.getStringSlice(condVal)
	if suffixes == nil {
		return false
	}

	if listVal, ok := val.([]string); ok {
		for _, item := range listVal {
			for _, s := range suffixes {
				if strings.HasSuffix(item, s) {
					return true
				}
			}
		}
		return false
	}

	if strVal, ok := val.(string); ok {
		for _, s := range suffixes {
			if strings.HasSuffix(strVal, s) {
				return true
			}
		}
	}
	return false
}

func (e *EventMapper) opNotSuffix(val, condVal interface{}) bool {
	suffixes := e.getStringSlice(condVal)
	if suffixes == nil {
		return true
	}

	if listVal, ok := val.([]string); ok {
		for _, item := range listVal {
			for _, s := range suffixes {
				if strings.HasSuffix(item, s) {
					return false
				}
			}
		}
		return true
	}

	if strVal, ok := val.(string); ok {
		for _, s := range suffixes {
			if strings.HasSuffix(strVal, s) {
				return false
			}
		}
		return true
	}
	return true
}

func (e *EventMapper) opContains(val, condVal interface{}) bool {
	substrings := e.getStringSlice(condVal)
	if substrings == nil {
		return false
	}

	if listVal, ok := val.([]string); ok {
		for _, item := range listVal {
			for _, sub := range substrings {
				if strings.Contains(item, sub) {
					return true
				}
			}
		}
		return false
	}

	if strVal, ok := val.(string); ok {
		for _, sub := range substrings {
			if strings.Contains(strVal, sub) {
				return true
			}
		}
	}
	return false
}

func (e *EventMapper) opNotContains(val, condVal interface{}) bool {
	substrings := e.getStringSlice(condVal)
	if substrings == nil {
		return true
	}

	if listVal, ok := val.([]string); ok {
		for _, item := range listVal {
			for _, sub := range substrings {
				if strings.Contains(item, sub) {
					return false
				}
			}
		}
		return true
	}

	if strVal, ok := val.(string); ok {
		for _, sub := range substrings {
			if strings.Contains(strVal, sub) {
				return false
			}
		}
		return true
	}
	return true
}

func (e *EventMapper) opIn(val, condVal interface{}) bool {
	list := e.getStringSlice(condVal)
	if list == nil {
		return false
	}

	if listVal, ok := val.([]string); ok {
		for _, vItem := range listVal {
			for _, lItem := range list {
				if vItem == lItem {
					return true
				}
			}
		}
		return false
	}

	if strVal, ok := val.(string); ok {
		for _, item := range list {
			if strVal == item {
				return true
			}
		}
	}
	return false
}

func (e *EventMapper) opNotIn(val, condVal interface{}) bool {
	list := e.getStringSlice(condVal)
	if list == nil {
		return true
	}

	if listVal, ok := val.([]string); ok {
		for _, vItem := range listVal {
			for _, lItem := range list {
				if vItem == lItem {
					return false
				}
			}
		}
		return true
	}

	if strVal, ok := val.(string); ok {
		for _, item := range list {
			if strVal == item {
				return false
			}
		}
		return true
	}
	return true
}

func (e *EventMapper) getWriter(filename string) (*os.File, error) {
	e.writersMu.Lock()
	defer e.writersMu.Unlock()

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
			"type":          metaType,
			"event":         eventType,
			"pid":           pid,
			"comm":          comm,
			"filename":      filename,
			"filepath":      fpath,
			"timestamp":     timestamp,
		}
		for k, v := range metaInfo {
			// Exclude internal resolution paths from logs
			if k == "merged_dir" || k == "upper_dir" || k == "lower_dir" || k == "mounts" {
				continue
			}
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
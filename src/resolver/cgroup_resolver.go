package resolver

import (
	"bpf-detect/config"
	"bpf-detect/patterns"
	"bpf-detect/providers"
	"bpf-detect/utils"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

type CGroupResolver struct {
	cache        map[uint64]ResolvedMetadata
	cacheMu      sync.RWMutex
	runcProvider *providers.RuncProvider
}

type ResolvedMetadata struct {
	Type string                 `json:"type"`
	Info map[string]interface{} `json:"info"`
}

func NewCGroupResolver() *CGroupResolver {
	return &CGroupResolver{
		cache:        make(map[uint64]ResolvedMetadata),
		runcProvider: &providers.RuncProvider{},
	}
}

func (r *CGroupResolver) ResolveCgroupMetadata(cgroupId uint64, hintPid int) ResolvedMetadata {
	r.cacheMu.RLock()
	if meta, ok := r.cache[cgroupId]; ok {
		r.cacheMu.RUnlock()
		return meta
	}
	r.cacheMu.RUnlock()

	paths, pid := r.findCgroupPaths(cgroupId, hintPid)
	if len(paths) == 0 {
		return r.handleUnknown(cgroupId)
	}

	containerId, uid := r.extractIdsFromPaths(paths)

	// Attempt to resolve Container metadata
	if meta := r.resolveContainer(containerId, uid, pid, paths); meta != nil {
		r.cacheMu.Lock()
		r.cache[cgroupId] = *meta
		r.cacheMu.Unlock()
		return *meta
	}

	// If we identified a container ID but failed to resolve metadata, do not cache the fallback.
	// This allows retrying later when the metadata might be available (e.g. state.json created).
	if containerId != "" {
		return ResolvedMetadata{
			Type: "host",
			Info: map[string]interface{}{
				"pid":          pid,
				"cgroup_paths": paths,
			},
		}
	}

	// Fallback to Host
	meta := ResolvedMetadata{
		Type: "host",
		Info: map[string]interface{}{
			"pid":          pid,
			"cgroup_paths": paths,
		},
	}
	r.cacheMu.Lock()
	r.cache[cgroupId] = meta
	r.cacheMu.Unlock()
	return meta
}

func (r *CGroupResolver) findCgroupPaths(cgroupId uint64, hintPid int) ([]string, int) {
	// 1. Fast Path: Check hint_pid
	if hintPid != 0 && r.checkPidMatchesCgroup(hintPid, cgroupId) {
		return utils.GetCgroupPathsForPid(hintPid), hintPid
	}

	// 2. Scan /sys/fs/cgroup
	if config.UseCgroupFsScan {
		if path := r.scanCgroupFs(cgroupId); path != "" {
			return []string{path}, hintPid
		}
	}

	// 3. Scan /proc
	entries, err := os.ReadDir("/proc")
	if err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			if pid == hintPid {
				continue
			}
			if r.checkPidMatchesCgroup(pid, cgroupId) {
				return utils.GetCgroupPathsForPid(pid), pid
			}
		}
	}

	return nil, 0
}

func (r *CGroupResolver) checkPidMatchesCgroup(pid int, targetCgroupId uint64) bool {
	paths := utils.GetCgroupPathsForPid(pid)
	for _, path := range paths {
		fullPath := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(path, "/"))
		info, err := os.Stat(fullPath)
		if err == nil {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if ok && uint64(stat.Ino) == targetCgroupId {
				return true
			}
		}
	}
	return false
}

func (r *CGroupResolver) scanCgroupFs(targetCgroupId uint64) string {
	basePath := "/sys/fs/cgroup"
	
	// Check base path first
	info, err := os.Stat(basePath)
	if err == nil {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if ok && uint64(stat.Ino) == targetCgroupId {
			return "/"
		}
	}

	var foundPath string
	// Optimization: Use WalkDir instead of Walk for better performance
	err = filepath.WalkDir(basePath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return nil
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if ok && uint64(stat.Ino) == targetCgroupId {
				rel, err := filepath.Rel(basePath, path)
				if err == nil {
					if !strings.HasPrefix(rel, "/") {
						rel = "/" + rel
					}
					foundPath = rel
					return filepath.SkipAll
				}
			}
		}
		return nil
	})

	return foundPath
}

func (r *CGroupResolver) extractIdsFromPaths(paths []string) (string, string) {
	var containerId, uid string
	for _, p := range paths {
		if m := patterns.DockerCgroup.FindStringSubmatch(p); m != nil {
			containerId = m[patterns.DockerCgroup.SubexpIndex("cid")]
		}
		if m := patterns.CriCgroup.FindStringSubmatch(p); m != nil {
			containerId = m[patterns.CriCgroup.SubexpIndex("cid")]
		}
		if m := patterns.K8sCgroup.FindStringSubmatch(p); m != nil {
			containerId = m[patterns.K8sCgroup.SubexpIndex("cid")]
		}
		if m := patterns.PodUid.FindStringSubmatch(p); m != nil {
			uid = strings.ReplaceAll(m[1], "_", "-")
		}
	}
	return containerId, uid
}

func (r *CGroupResolver) resolveContainer(containerId, uid string, pid int, paths []string) *ResolvedMetadata {
	var metaData providers.Metadata

	// Try via Container ID
	if containerId != "" {
		provider := strings.ToLower(config.MetadataProvider)
		if provider == "all" || provider == "runc" {
			metaData = r.runcProvider.GetMetadata(containerId)
		}
		if metaData.PodUid != "" {
			uid = metaData.PodUid
		}
	}

	// Try via UID (reverse lookup)
	if uid != "" && metaData.Namespace == "" {
		ns, podName, cidFound, found := r.runcProvider.FindContainerByUid(uid)
		if found {
			containerId = cidFound
			metaData = r.runcProvider.GetMetadata(containerId)
			// Ensure we keep the found info if GetMetadata failed to return it (though it should)
			if metaData.Namespace == "" {
				metaData.Namespace = ns
				metaData.PodName = podName
			}
		}
	}

	// Determine type
	if metaData.Namespace != "" && uid != "" {
		return &ResolvedMetadata{
			Type: "k8s",
			Info: map[string]interface{}{
				"pid":          pid,
				"pod_uid":      uid,
				"namespace":    metaData.Namespace,
				"pod_name":     metaData.PodName,
				"images":       metaData.Image,
				"container_id": containerId,
				"cgroup_paths": paths,
			},
		}
	} else if containerId != "" && (metaData.Image != "" || metaData.ContainerId != "") {
		cName := metaData.Labels["container_name"]
		if cName == "" {
			cName = metaData.ContainerId
		}
		return &ResolvedMetadata{
			Type: "docker",
			Info: map[string]interface{}{
				"pid":            pid,
				"container_id":   containerId,
				"container_name": cName,
				"image":          metaData.Image,
				"cgroup_paths":   paths,
			},
		}
	}

	return nil
}

func (r *CGroupResolver) handleUnknown(cgroupId uint64) ResolvedMetadata {
	if cgroupId == 1 {
		meta := ResolvedMetadata{
			Type: "host",
			Info: map[string]interface{}{
				"cgroup_paths": []string{"/"},
			},
		}
		r.cache[cgroupId] = meta
		return meta
	}
	return ResolvedMetadata{Type: "unknown", Info: map[string]interface{}{}}
}

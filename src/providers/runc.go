package providers

import (
	"bpf-detect/config"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

type RuncProvider struct{}

type Metadata struct {
	Namespace   string            `json:"namespace,omitempty"`
	PodName     string            `json:"pod_name,omitempty"`
	PodUid      string            `json:"pod_uid,omitempty"`
	Image       string            `json:"image,omitempty"`
	ContainerId string            `json:"container_id,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
}

func (p *RuncProvider) GetMetadata(containerId string) Metadata {
	if containerId == "" {
		return Metadata{}
	}

	// 1. Check standard Runc paths
	for _, baseDir := range config.RuncTaskDirs {
		if meta := p.checkDir(baseDir, containerId); meta != nil {
			return *meta
		}
	}

	// 2. Check Rootless Docker paths
	if _, err := os.Stat(config.RootlessDockerBase); err == nil {
		entries, err := os.ReadDir(config.RootlessDockerBase)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					runcPath := filepath.Join(config.RootlessDockerBase, entry.Name(), "docker", "runtime-runc", "moby")
					if meta := p.checkDir(runcPath, containerId); meta != nil {
						return *meta
					}
				}
			}
		}
	}

	return Metadata{}
}

func (p *RuncProvider) checkDir(baseDir, containerId string) *Metadata {
	containerId = strings.TrimSpace(containerId)

	// Security: Validate containerId to prevent directory traversal
	if strings.ContainsAny(containerId, `/\`) || strings.Contains(containerId, "..") {
		return nil
	}

	// 1. Try state.json (runc)
	statePath := filepath.Join(baseDir, containerId, "state.json")
	if _, err := os.Stat(statePath); err == nil {
		if meta := p.parseStateJson(statePath, baseDir, containerId); meta != nil {
			return meta
		}
	}

	// 2. Try config.json (containerd v2 shim / OCI bundle)
	configPath := filepath.Join(baseDir, containerId, "config.json")
	if _, err := os.Stat(configPath); err == nil {
		if meta := p.parseConfigJson(configPath, containerId); meta != nil {
			return meta
		}
	}

	return nil
}

func (p *RuncProvider) parseStateJson(path, baseDir, containerId string) *Metadata {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var data stateData
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil
	}

	annotations := p.extractAnnotations(data.Config.Labels)
	
	// Merge root labels if any
	for k, v := range data.Labels {
		annotations[k] = v
	}

	ns, podName, podUid := p.resolveK8sMetadata(annotations)
	image := p.resolveImage(annotations, data, baseDir, containerId)

	finalId := data.Id
	if finalId == "" {
		finalId = containerId
	}

	return &Metadata{
		Namespace:   ns,
		PodName:     podName,
		PodUid:      podUid,
		Image:       image,
		ContainerId: finalId,
		Labels:      annotations,
	}
}

type stateData struct {
	Config struct {
		Labels interface{} `json:"labels"` // Can be list or dict
		Mounts []struct {
			Source      string `json:"source"`
			Destination string `json:"destination"`
		} `json:"mounts"`
	} `json:"config"`
	Bundle string            `json:"bundle"`
	Labels map[string]string `json:"labels"` // Root level labels
	Id     string            `json:"id"`
}

func (p *RuncProvider) extractAnnotations(labels interface{}) map[string]string {
	annotations := make(map[string]string)
	if labelsMap, ok := labels.(map[string]interface{}); ok {
		for k, v := range labelsMap {
			if strVal, ok := v.(string); ok {
				annotations[k] = strVal
			}
		}
	} else if labelsList, ok := labels.([]interface{}); ok {
		for _, l := range labelsList {
			if s, ok := l.(string); ok {
				parts := strings.SplitN(s, "=", 2)
				if len(parts) == 2 {
					annotations[parts[0]] = parts[1]
				}
			}
		}
	}
	return annotations
}

func (p *RuncProvider) resolveK8sMetadata(annotations map[string]string) (string, string, string) {
	ns := annotations["io.kubernetes.pod.namespace"]
	if ns == "" {
		ns = annotations["io.kubernetes.cri.sandbox-namespace"]
	}
	podName := annotations["io.kubernetes.pod.name"]
	if podName == "" {
		podName = annotations["io.kubernetes.cri.sandbox-name"]
	}
	podUid := annotations["io.kubernetes.pod.uid"]
	if podUid == "" {
		podUid = annotations["io.kubernetes.cri.sandbox-uid"]
	}
	return ns, podName, podUid
}

func (p *RuncProvider) resolveImageFromAnnotations(annotations map[string]string) string {
	image := annotations["io.kubernetes.cri.image-name"]
	if image == "" {
		image = annotations["io.kubernetes.cri.image-ref"]
	}
	if image == "" {
		image = annotations["org.opencontainers.image.ref.name"]
	}
	return image
}

func (p *RuncProvider) resolveImage(annotations map[string]string, data stateData, baseDir, containerId string) string {
	if image := p.resolveImageFromAnnotations(annotations); image != "" {
		return image
	}

	// 1. Try bundle config.json
	if img := p.resolveImageFromBundle(data); img != "" {
		return img
	}

	// 2. Try Docker config.v2.json
	if img := p.resolveImageFromDockerConfig(data, baseDir, containerId, annotations); img != "" {
		return img
	}

	return ""
}

func (p *RuncProvider) resolveImageFromBundle(data stateData) string {
	bundlePath := data.Bundle
	if bundlePath == "" {
		for k, v := range data.Labels {
			if k == "bundle" {
				bundlePath = v
				break
			}
		}
	}

	if bundlePath != "" {
		configJsonPath := filepath.Join(bundlePath, "config.json")
		if fBundle, err := os.Open(configJsonPath); err == nil {
			defer fBundle.Close()
			var cdata struct {
				Annotations map[string]string `json:"annotations"`
			}
			if err := json.NewDecoder(fBundle).Decode(&cdata); err == nil {
				if img := cdata.Annotations["io.kubernetes.cri.image-name"]; img != "" {
					return img
				}
				if img := cdata.Annotations["io.kubernetes.cri.image-ref"]; img != "" {
					return img
				}
				if img := cdata.Annotations["org.opencontainers.image.ref.name"]; img != "" {
					return img
				}
			}
		}
	}
	return ""
}

func (p *RuncProvider) resolveImageFromDockerConfig(data stateData, baseDir, containerId string, annotations map[string]string) string {
	for _, m := range data.Config.Mounts {
		if strings.Contains(m.Source, "/containers/") && strings.Contains(m.Source, containerId) {
			idx := strings.Index(m.Source, containerId)
			if idx != -1 {
				containerDir := m.Source[:idx+len(containerId)]
				
				// Handle Rootless Path Remapping
				if strings.HasPrefix(containerDir, "/var/lib/docker") && strings.Contains(baseDir, "/run/user/") {
					parts := strings.Split(baseDir, "/")
					for i, part := range parts {
						if part == "user" && i+1 < len(parts) {
							uidStr := parts[i+1]
							if u, err := user.LookupId(uidStr); err == nil {
								rel := strings.TrimPrefix(containerDir, "/var/lib/docker")
								containerDir = filepath.Join(u.HomeDir, ".local/share/docker", strings.TrimPrefix(rel, "/"))
							}
							break
						}
					}
				}

				dockCfg := filepath.Join(containerDir, "config.v2.json")
				if fDock, err := os.Open(dockCfg); err == nil {
					defer fDock.Close()
					var ddata struct {
						Config struct {
							Image string `json:"Image"`
						} `json:"Config"`
						Name string `json:"Name"`
					}
					if err := json.NewDecoder(fDock).Decode(&ddata); err == nil {
						if annotations["io.kubernetes.pod.name"] == "" {
							cName := strings.TrimPrefix(ddata.Name, "/")
							if cName != "" {
								annotations["container_name"] = cName
							}
						}
						return ddata.Config.Image
					}
				}
			}
		}
	}
	return ""
}

func (p *RuncProvider) parseConfigJson(path, containerId string) *Metadata {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var data struct {
		Annotations map[string]string `json:"annotations"`
	}
	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil
	}

	annotations := data.Annotations
	ns, podName, podUid := p.resolveK8sMetadata(annotations)
	image := p.resolveImageFromAnnotations(annotations)

	return &Metadata{
		Namespace:   ns,
		PodName:     podName,
		PodUid:      podUid,
		Image:       image,
		ContainerId: containerId,
		Labels:      annotations,
	}
}

func (p *RuncProvider) FindContainerByUid(targetUid string) (string, string, string, bool) {
	if targetUid == "" {
		return "", "", "", false
	}

	scanDir := func(basePath string) (string, string, string, bool) {
		entries, err := os.ReadDir(basePath)
		if err != nil {
			return "", "", "", false
		}
		for _, entry := range entries {
			if entry.IsDir() {
				containerId := entry.Name()
				meta := p.checkDir(basePath, containerId)
				if meta != nil && meta.PodUid == targetUid {
					return meta.Namespace, meta.PodName, containerId, true
				}
			}
		}
		return "", "", "", false
	}

	// 1. Scan standard Runc paths
	for _, baseDir := range config.RuncTaskDirs {
		if ns, pod, cid, found := scanDir(baseDir); found {
			return ns, pod, cid, true
		}
	}

	// 2. Scan Rootless paths
	if _, err := os.Stat(config.RootlessDockerBase); err == nil {
		entries, err := os.ReadDir(config.RootlessDockerBase)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					runcPath := filepath.Join(config.RootlessDockerBase, entry.Name(), "docker", "runtime-runc", "moby")
					if ns, pod, cid, found := scanDir(runcPath); found {
						return ns, pod, cid, true
					}
				}
			}
		}
	}

	return "", "", "", false
}

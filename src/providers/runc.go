package providers

import (
	"bpf-detect/config"
	"encoding/json"
	"fmt"
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
					if config.Debug {
						fmt.Printf("DEBUG: Checking rootless path: %s\n", runcPath)
					}
					if meta := p.checkDir(runcPath, containerId); meta != nil {
						return *meta
					}
				}
			}
		} else if config.Debug {
			fmt.Printf("DEBUG: Failed to read dir %s: %v\n", config.RootlessDockerBase, err)
		}
	} else if config.Debug {
		fmt.Printf("DEBUG: Failed to stat %s: %v\n", config.RootlessDockerBase, err)
	}

	return Metadata{}
}

func (p *RuncProvider) checkDir(baseDir, containerId string) *Metadata {
	containerId = strings.TrimSpace(containerId)

	// Security: Validate containerId to prevent directory traversal
	if strings.ContainsAny(containerId, `/\`) || strings.Contains(containerId, "..") {
		if config.Debug {
			fmt.Printf("DEBUG: Invalid container ID (potential traversal): %s\n", containerId)
		}
		return nil
	}

	if config.Debug {
		fmt.Printf("DEBUG: Checking dir: %s for container: '%s'\n", baseDir, containerId)
	}
	// 1. Try state.json (runc)
	statePath := filepath.Join(baseDir, containerId, "state.json")
	if _, err := os.Stat(statePath); err == nil {
		if config.Debug {
			fmt.Printf("DEBUG: Found state.json at: %s\n", statePath)
		}
		if meta := p.parseStateJson(statePath, baseDir, containerId); meta != nil {
			return meta
		}
	} else {
		if config.Debug {
			fmt.Printf("DEBUG: Failed to stat state.json at %s: %v\n", statePath, err)
			// Check if dir exists and list it
			containerDir := filepath.Join(baseDir, containerId)
			if info, err := os.Stat(containerDir); err == nil && info.IsDir() {
				entries, _ := os.ReadDir(containerDir)
				fmt.Printf("DEBUG: Directory %s exists. Contents:\n", containerDir)
				for _, e := range entries {
					fmt.Printf("  %s\n", e.Name())
				}
			} else {
				fmt.Printf("DEBUG: Container dir %s does not exist or is not a dir. Error: %v\n", containerDir, err)
			}
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

	var data struct {
		Config struct {
			Labels interface{} `json:"labels"` // Can be list or dict
			Mounts []struct {
				Source string `json:"source"`
			} `json:"mounts"`
		} `json:"config"`
		Bundle string            `json:"bundle"`
		Labels map[string]string `json:"labels"` // Root level labels
		Id     string            `json:"id"`
	}

	if err := json.NewDecoder(f).Decode(&data); err != nil {
		return nil
	}

	annotations := make(map[string]string)
	
	// Handle labels being list or dict
	if labelsMap, ok := data.Config.Labels.(map[string]interface{}); ok {
		for k, v := range labelsMap {
			if strVal, ok := v.(string); ok {
				annotations[k] = strVal
			}
		}
	} else if labelsList, ok := data.Config.Labels.([]interface{}); ok {
		for _, l := range labelsList {
			if s, ok := l.(string); ok {
				parts := strings.SplitN(s, "=", 2)
				if len(parts) == 2 {
					annotations[parts[0]] = parts[1]
				}
			}
		}
	}

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

	image := annotations["io.kubernetes.cri.image-name"]
	if image == "" {
		image = annotations["io.kubernetes.cri.image-ref"]
	}
	if image == "" {
		image = annotations["org.opencontainers.image.ref.name"]
	}

	if image == "" {
		// 1. Try bundle config.json
		bundlePath := data.Bundle
		if bundlePath == "" {
			for k, v := range data.Labels {
				if k == "bundle" {
					bundlePath = v
					break
				}
			}
			// Also check if labels are in "key=value" format in root labels if it was a list (but struct says map[string]string, so json decoder handles object. If it's a list in JSON, this struct field might fail or be empty if not matched. Python code iterates list. Let's assume map for root labels as per typical runc state.json, but check if we need to be more robust.)
			// Actually runc state.json root labels are usually map.
		}

		if bundlePath != "" {
			configJsonPath := filepath.Join(bundlePath, "config.json")
			if fBundle, err := os.Open(configJsonPath); err == nil {
				var cdata struct {
					Annotations map[string]string `json:"annotations"`
				}
				if err := json.NewDecoder(fBundle).Decode(&cdata); err == nil {
					image = cdata.Annotations["io.kubernetes.cri.image-name"]
					if image == "" {
						image = cdata.Annotations["io.kubernetes.cri.image-ref"]
					}
					if image == "" {
						image = cdata.Annotations["org.opencontainers.image.ref.name"]
					}
				}
				fBundle.Close()
			}
		}

		// 2. Try Docker config.v2.json
		if image == "" {
			for _, m := range data.Config.Mounts {
				if config.Debug {
					fmt.Printf("DEBUG: Checking mount: %s\n", m.Source)
				}
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
										if config.Debug {
											fmt.Printf("DEBUG: Remapped containerDir to: %s\n", containerDir)
										}
									} else if config.Debug {
										fmt.Printf("DEBUG: Failed to lookup user %s: %v\n", uidStr, err)
									}
									break
								}
							}
						}

						dockCfg := filepath.Join(containerDir, "config.v2.json")
						if config.Debug {
							fmt.Printf("DEBUG: Checking config.v2.json at: %s\n", dockCfg)
						}
						if fDock, err := os.Open(dockCfg); err == nil {
							var ddata struct {
								Config struct {
									Image string `json:"Image"`
								} `json:"Config"`
								Name string `json:"Name"`
							}
							if err := json.NewDecoder(fDock).Decode(&ddata); err == nil {
								image = ddata.Config.Image
								if config.Debug {
									fmt.Printf("DEBUG: Found image: %s\n", image)
								}
								if annotations["io.kubernetes.pod.name"] == "" {
									cName := strings.TrimPrefix(ddata.Name, "/")
									if cName != "" {
										annotations["container_name"] = cName
									}
								}
							} else if config.Debug {
								fmt.Printf("DEBUG: Failed to decode config.v2.json: %v\n", err)
							}
							fDock.Close()
							break
						} else if config.Debug {
							fmt.Printf("DEBUG: Failed to open config.v2.json: %v\n", err)
						}
					}
				}
			}
		}
	}

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

	image := annotations["io.kubernetes.cri.image-name"]
	if image == "" {
		image = annotations["io.kubernetes.cri.image-ref"]
	}
	if image == "" {
		image = annotations["org.opencontainers.image.ref.name"]
	}

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

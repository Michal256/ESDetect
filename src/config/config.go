package config

import (
	"encoding/json"
	"fmt"
	"os"
)

var (
	UseCgroupFsScan    = true
	PrintHostEvents    = false
	Debug              = false
	FilterSystemEvents = true
	MetadataProvider   = "all"

	// Dynamic Filtering Configuration
	Filters []FilterRule

	RuncTaskDirs = []string{
		// Standard Kubernetes (Containerd) - AWS EKS, Azure AKS, Google GKE
		"/run/containerd/io.containerd.runtime.v2.task/k8s.io",
		"/run/containerd/io.containerd.runtime.v1.linux/k8s.io",
		"/run/containerd/runc/k8s.io",
		
		// MicroK8s
		"/var/snap/microk8s/common/run/containerd/runc/k8s.io",
		"/var/snap/microk8s/common/run/containerd/io.containerd.runtime.v2.task/k8s.io",
		
		// Legacy/Other
		"/run/runc",
		"/run/docker/runtime-runc/moby",
	}

	RootlessDockerBase = "/run/user"
	DockerConfigBase   = "/var/lib/docker/containers"

	OutputDir    = "."
	OutputFormat = "text"

	// Performance tuning
	WorkerCount     = 4
	EventBufferSize = 10000
)

type FilterCondition struct {
	Field    string      `json:"field"`    // type, pid, comm, filepath, namespace, cgroup_paths
	Operator string      `json:"operator"` // equals, prefix, suffix, contains, in
	Value    interface{} `json:"value"`    // string, int, []string
}

type FilterRule struct {
	Description string            `json:"description"`
	Conditions  []FilterCondition `json:"conditions"`
}

func LoadFilters(path string) error {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read filter config: %v", err)
	}
	var loadedFilters []FilterRule
	if err := json.Unmarshal(data, &loadedFilters); err != nil {
		return fmt.Errorf("failed to parse filter config: %v", err)
	}
	// Overwrite default filters with loaded filters
	Filters = loadedFilters
	return nil
}

func Init() {
	if val, ok := os.LookupEnv("METADATA_PROVIDER"); ok {
		MetadataProvider = val
	}
	if val, ok := os.LookupEnv("BPF_DEBUG"); ok && val == "true" {
		Debug = true
	}

	// Initialize Default Filters
	Filters = []FilterRule{
		// 1. Host Init Process (PID 1)
		{
			Description: "Filter Host Init Process",
			Conditions: []FilterCondition{
				{Field: "type", Operator: "equals", Value: "host"},
				{Field: "pid", Operator: "equals", Value: 1},
			},
		},
		// 2. Host Noise Paths (Prefixes)
		{
			Description: "Filter Host Noise Paths (Prefixes)",
			Conditions: []FilterCondition{
				{Field: "type", Operator: "equals", Value: "host"},
				{Field: "filepath", Operator: "prefix", Value: []string{
					"/proc/", "/sys/", "/dev/", "/run/", "/tmp/", "/var/log/", "loop",
				}},
			},
		},
		// 3. Host Noise Paths (Exact)
		{
			Description: "Filter Host Noise Paths (Exact)",
			Conditions: []FilterCondition{
				{Field: "type", Operator: "equals", Value: "host"},
				{Field: "filepath", Operator: "in", Value: []string{
					"/etc/ld.so.cache", "..", ".", "/", "devices", "virtual", "block",
				}},
			},
		},
		// 4. Ignored Commands
		{
			Description: "Filter Ignored Commands",
			Conditions: []FilterCondition{
				{Field: "comm", Operator: "in", Value: []string{}},
			},
		},
		{
			Description: "Filter runc: commands",
			Conditions: []FilterCondition{
				{Field: "comm", Operator: "prefix", Value: "runc:"},
			},
		},
		// 5. Ignored K8s Namespaces
		{
			Description: "Filter System Namespaces",
			Conditions: []FilterCondition{
				{Field: "type", Operator: "equals", Value: "k8s"},
				{Field: "namespace", Operator: "in", Value: []string{
					"kube-system", "calico-system", "ingress-nginx", "microk8s", "local-path-storage",
				}},
			},
		},
	}
}

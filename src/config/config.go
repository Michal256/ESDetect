package config

import "os"

var (
	UseCgroupFsScan    = true
	PrintHostEvents    = false
	Debug              = false
	FilterSystemEvents = true
	MetadataProvider   = "all"

	IgnoreK8sNamespaces = map[string]bool{
		"kube-system":        true,
		"calico-system":      true,
		"ingress-nginx":      true,
		"microk8s":           true,
		"local-path-storage": true,
	}

	IgnoredCommands = map[string]bool{
		"calico-node":     true,
		"runc":            true,
		"iptables":        true,
		"iptables-legacy": true,
		"dockerd":         true,
		"containerd":      true,
		"kubelet":         true,
		"check-status":    true,
		"pause":           true,
		"coredns":         true,
		"hostpath-provis": true,
		"kube-controller": true,
		"kube-proxy":      true,
		"aws-k8s-agent":   true,
	}

	RuncTaskDirs = []string{
		"/run/containerd/io.containerd.runtime.v2.task/k8s.io",
		"/run/containerd/io.containerd.runtime.v1.linux/k8s.io",
		"/run/containerd/runc/k8s.io",
		"/var/snap/microk8s/common/run/containerd/runc/k8s.io",
		"/var/snap/microk8s/common/run/containerd/io.containerd.runtime.v2.task/k8s.io",
		"/run/runc",
		"/run/docker/runtime-runc/moby",
	}

	RootlessDockerBase = "/run/user"

	OutputDir    = "."
	OutputFormat = "text"

	// Performance tuning
	WorkerCount     = 4
	EventBufferSize = 10000
)

func Init() {
	if val, ok := os.LookupEnv("METADATA_PROVIDER"); ok {
		MetadataProvider = val
	}
	if val, ok := os.LookupEnv("BPF_DEBUG"); ok && val == "true" {
		Debug = true
	}
}

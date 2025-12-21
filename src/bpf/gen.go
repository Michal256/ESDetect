//go:build ignore
// +build ignore

package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type event_t Event probe.c -- -I.. -I/usr/include/x86_64-linux-gnu

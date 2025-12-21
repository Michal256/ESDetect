package main

import (
	"bpf-detect/bpf"
	"bpf-detect/config"
	"bpf-detect/mapper"
	"flag"
	"fmt"
	"os"
)

func main() {
	// Define flags
	outputDir := flag.String("output-dir", ".", "Directory to store log files")
	debug := flag.Bool("debug", false, "Enable debug logging")
	printHost := flag.Bool("print-host-events", false, "Print events from host processes")
	filterSystem := flag.Bool("filter-system-events", true, "Filter out system events (k8s system pods, common system commands)")
	metadataProvider := flag.String("metadata-provider", "all", "Metadata provider to use (all, runc)")
	useBpftrace := flag.Bool("use-bpftrace", false, "Use legacy bpftrace input mode (stdin)")
	outputFormat := flag.String("output-format", "text", "Output format (text, json)")
	workers := flag.Int("workers", 4, "Number of concurrent worker routines")
	bufferSize := flag.Int("buffer-size", 10000, "Size of the event buffer channel")

	flag.Parse()

	// Apply configuration
	config.Init() // Keep env var support if needed, or override below
	config.OutputDir = *outputDir
	config.Debug = *debug
	config.PrintHostEvents = *printHost
	config.FilterSystemEvents = *filterSystem
	config.MetadataProvider = *metadataProvider
	config.OutputFormat = *outputFormat
	config.WorkerCount = *workers
	config.EventBufferSize = *bufferSize

	// Ensure output directory exists
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error creating output directory: %v\n", err)
		os.Exit(1)
	}

	if os.Geteuid() != 0 {
		fmt.Fprintf(os.Stderr, "WARNING: bpf-detect is not running as root. CGroup resolution for other users' processes will fail.\n")
	}

	fmt.Printf("Starting bpf-detect...\n")
	fmt.Printf("Output Directory: %s\n", config.OutputDir)
	fmt.Printf("Debug: %v\n", config.Debug)

	m := mapper.NewEventMapper()
	defer m.Close()

	if *useBpftrace {
		fmt.Println("Using legacy bpftrace mode (reading from stdin)...")
		m.Run()
	} else {
		// Start BPF tracing
		err := bpf.RunBPF(func(eventType string, pid int, cid uint64, comm string, filename string) {
			m.ProcessEvent(eventType, pid, cid, comm, filename)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error running BPF: %v\n", err)
			os.Exit(1)
		}
	}
}

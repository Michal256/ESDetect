# ESDetect Source Code Overview

This document provides a technical overview of the ESDetect source code, explaining the architecture, directory structure, and key components.

## High-Level Architecture

ESDetect works by attaching eBPF probes to the kernel to capture file access and execution events. These events are sent to userspace, where they are correlated with container metadata (Kubernetes Pods, Docker Containers) to identify which application image is responsible for the activity.

The flow is as follows:
1.  **Kernel**: `trace_execve` and `trace_openat` probes capture events.
2.  **RingBuffer**: Events are pushed to a shared ring buffer.
3.  **Userspace (Go)**: `loader.go` reads events.
4.  **Mapper**: `event_mapper.go` enriches events with container metadata.
5.  **Resolver**: `cgroup_resolver.go` maps Cgroup IDs to Container IDs.
6.  **Provider**: `runc.go` reads container runtime state to get Image/Pod details.
7.  **Output**: Logs are written to `detect_<image>.log`.

## Directory Structure & Components

### 1. Entry Point (`src/main.go`)
The main entry point of the application.
-   Parses command-line flags (`-output-dir`, `-debug`, `-workers`, `-buffer-size`, etc.).
-   Initializes the global configuration.
-   Sets up the `EventMapper` with the configured worker count and buffer size.
-   Starts the BPF loader (`bpf.RunBPF`) and passes a callback function to handle incoming events.

### 2. eBPF Layer (`src/bpf/`)
This package handles all interaction with the Linux Kernel.

-   **`probe.c`**: The C source code for the eBPF program.
    -   Defines `tracepoint/syscalls/sys_enter_execve`, `sys_enter_openat`, `sys_enter_readlink`, and `sys_enter_readlinkat`.
    -   Captures PID, Cgroup ID, Command Name (`comm`), and Filename.
    -   Uses `bpf_ringbuf_submit` to send data to userspace.
    -   **Note**: It manually defines kernel structs to avoid dependency on `vmlinux.h` for broader compatibility.
-   **`loader.go`**: The Go userspace loader.
    -   Uses `cilium/ebpf` library.
    -   Loads the compiled BPF objects into the kernel.
    -   Attaches tracepoints (`execve`, `openat`, `readlink`, `readlinkat`).
    -   Reads from the `ringbuf` in a loop and decodes the binary data into Go structs.
-   **`gen.go`**: Contains the `//go:generate` directive.
    -   Uses `bpf2go` to compile `probe.c` into Go artifacts (`event_bpfel_amd64.go`, etc.).

### 3. Event Processing (`src/mapper/`)
This package is the "brain" of the application, coordinating data flow.

-   **`event_mapper.go`**:
    -   **Asynchronous Processing**: Implements a **Worker Pool** pattern with a buffered channel (`eventChan`, configurable size, default 10,000) to decouple event ingestion from processing.
    -   **`ProcessEvent`**: Pushes events to the channel. If the channel is full, events are dropped to prevent blocking the BPF reader.
    -   **`handleEvent`**: Consumed by workers (configurable count, default 4) to perform heavy lifting:
        -   **Path Resolution**: Resolves relative paths to absolute paths using `/proc/<pid>/cwd`.
        -   **Metadata Resolution**: Calls `resolver.ResolveCgroupMetadata` to find out who owns the process.
        -   **Filtering**: Checks `shouldIgnore` to filter out system events (e.g., `kubelet`, `calico`, `runc`) or ignored Kubernetes namespaces.
        -   **Logging**: Formats the event (JSON or Text) and writes it to the appropriate log file based on the resolved image name.

### 4. Metadata Resolution (`src/resolver/`)
This package maps the low-level Cgroup ID (from BPF) to high-level Container Metadata.

-   **`cgroup_resolver.go`**:
    -   **`ResolveCgroupMetadata`**:
        1.  Checks an internal cache to see if this Cgroup ID is already known.
        2.  **Find Paths**: Uses `findCgroupPaths` to locate the cgroup path in `/proc` or `/sys/fs/cgroup`.
        3.  **Extract ID**: Uses regex (from `patterns`) to extract the Container ID from the path (supports Docker, CRI, and K8s patterns).
        4.  **Resolve Container**: Calls the `providers` package to get details for the Container ID.
        5.  **Cache**: Stores the result (Image Name, Pod Name, etc.) in memory.

### 5. Metadata Providers (`src/providers/`)
This package interfaces with the Container Runtime (containerd/runc) to fetch details.

-   **`runc.go`**:
    -   **`GetMetadata`**: Takes a Container ID and searches for its runtime state.
    -   **Search Paths**: Looks in standard runc/containerd directories defined in `config.go` (e.g., `/run/containerd/io.containerd.runtime.v2.task/k8s.io`).
    -   **Parsing**: Reads `state.json` (runc) or `config.json` (OCI bundle) to extract:
        -   Image Name
        -   Pod Name
        -   Kubernetes Namespace
        -   Pod UID

### 6. Configuration (`src/config/`)
-   **`config.go`**: Defines global configuration variables and constants.
    -   `IgnoredCommands`: List of system processes to ignore.
    -   `IgnoreK8sNamespaces`: List of K8s namespaces to ignore (e.g., `kube-system`).
    -   `RuncTaskDirs`: List of directories to search for container state.

### 7. Utilities (`src/utils/` & `src/patterns/`)
-   **`utils.go`**: Helper functions for file system operations and reading `/proc`.
-   **`patterns.go`**: Centralized Regex definitions for parsing Cgroup paths.
    -   `DockerCgroup`: Matches `/docker/<cid>`.
    -   `K8sCgroup`: Matches `/kubepods/...`.

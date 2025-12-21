# ESDetect Program Flow & Dependency Analysis

This document provides a detailed technical description of the `ESDetect` program flow, corresponding to the diagram in `program_flow.mermaid`. It specifically highlights the architectural components and the external dependencies used to achieve runtime detection and metadata enrichment.

## 1. Kernel Space Interaction (Data Capture)

The foundation of `ESDetect` lies in the Linux Kernel, where it employs **eBPF (Extended Berkeley Packet Filter)** to observe system behavior with minimal overhead.

*   **Trigger Mechanism**: The system attaches probes to specific system calls:
    *   `sys_execve`: Triggered whenever a new program is executed.
    *   `sys_openat`: Triggered whenever a file is opened.
*   **BPF Probes (`probe.c`)**: Custom C code is compiled into eBPF bytecode. These probes run safely within the kernel context.
*   **Data Extraction**: When a probe triggers, it captures key context:
    *   **PID**: The Process ID.
    *   **Comm**: The command name (process name).
    *   **Filepath**: The path of the file or binary being accessed.
*   **Data Transfer (RingBuffer)**: Captured data is pushed into an **eBPF RingBuffer**. This is a shared memory structure that allows for high-performance, asynchronous data transfer from kernel space to user space, avoiding the performance penalties of traditional logging mechanisms.

## 2. Userspace Ingestion (Go Application)

The userspace component is a Go application responsible for loading the BPF programs and processing the incoming data stream.

### Key Dependency: `github.com/cilium/ebpf`
*   **Version**: v0.20.0
*   **Role**: This library is the core engine for the userspace application. It provides a pure Go implementation for interacting with the eBPF subsystem.
*   **Usage**:
    *   **Loading**: It loads the compiled eBPF bytecode (ELF files) into the kernel.
    *   **Attaching**: It attaches the programs to the kprobes/tracepoints.
    *   **Map/RingBuffer Management**: It manages the file descriptors for the BPF maps and RingBuffers, providing a safe API for reading data streams (`bpf/loader.go`).

## 3. Metadata Enrichment & Resolution

Raw kernel events only provide a PID. To map these events to specific software components (SBOMs), `ESDetect` must correlate the PID with Container and Kubernetes metadata.

### Key Dependency: `golang.org/x/sys`
*   **Version**: v0.39.0
*   **Role**: Provides access to low-level system primitives not available in the standard `syscall` package.
*   **Usage**: Used for specific system calls required for file descriptor manipulation and potentially for interacting with cgroup structures.

### Resolution Flow
1.  **Event Mapping (`mapper/event_mapper.go`)**: The mapper receives the raw event from the RingBuffer.
2.  **Cgroup Inspection (`resolver/cgroup_resolver.go`)**:
    *   The system reads `/proc/<pid>/cgroup` to identify the control group of the process.
    *   This path contains the Container ID (CID) for containerized processes.
3.  **Runtime State Inspection (`providers/runc.go`)**:
    *   Once the CID is obtained, the system acts as a "Provider" to fetch high-level details.
    *   It directly inspects the container runtime's state files (e.g., `state.json`, `config.json`) located in the runtime's storage directories (e.g., `/run/containerd/io.containerd.runtime.v2.task/...`).
    *   **Data Extracted**: Pod Name, Namespace, Image Name, and Image Digest.
4.  **Caching**: To prevent performance degradation from repeated I/O operations, resolved metadata is cached in memory.

## 4. Filtering & Output

The final stage involves refining the data and persisting it for analysis.

*   **Filtering**:
    *   **System Events**: Events from Kubernetes system pods (e.g., `kube-system`) or common infrastructure processes are filtered out by default to reduce noise.
    *   **Host Events**: Events from non-containerized processes are typically ignored unless explicitly enabled.
*   **Formatting**:
    *   **JSON**: Structured output suitable for programmatic consumption (e.g., by `ESVerdict`).
    *   **Text**: Human-readable format for debugging and manual inspection.
*   **Persistence**:
    *   Events are written to log files named after the detected container image (e.g., `detect_python-app.log`).
    *   This segregation allows for a 1:1 mapping between a runtime log file and an application's SBOM.

## 5. Limitations

1.  **Container Runtime Support**:
    *   The current metadata provider (`providers/runc.go`) is designed for **runc**-based runtimes (like Docker and containerd).
    *   It relies on accessing specific state files (e.g., `state.json`) in directories like `/run/containerd/io.containerd.runtime.v2.task/`.
    *   Runtimes that do not use `runc` or store state in different locations (e.g., CRI-O, Kata Containers) are not currently supported without code modifications.

2.  **Kernel Dependencies**:
    *   Requires a Linux kernel with eBPF support. For optimal portability (CO-RE), a kernel with **BTF (BPF Type Format)** is required (typically kernel 5.8+).

3.  **Event Loss Risks**:
    *   **RingBuffer Saturation**: If the userspace application is too slow to process the volume of incoming events, the kernel RingBuffer may fill up, causing subsequent events to be dropped.
    *   **Short-lived Processes**: There is a potential race condition where a process starts and exits immediately. While the BPF probe captures the event, the process might terminate before the userspace resolver can read `/proc/<pid>/cgroup`, resulting in an event with missing container metadata.

4.  **Privileges**:
    *   The tool requires **Root (CAP_SYS_ADMIN)** privileges to load BPF programs into the kernel and to access sensitive host directories (`/proc`, `/run/containerd`) for metadata resolution.

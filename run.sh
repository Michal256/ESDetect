#!/bin/bash
# Increase the string length limit for bpftrace.
# The default BPF stack size is 512 bytes.
# We set max_strlen to 200 to leave space for other variables (pid, comm, etc).
# export BPFTRACE_MAX_STRLEN=400

echo "Starting bpf-detect (Native Go + eBPF)..."
#sudo bpftrace trace.bt | sudo ./src/bpf-detect -output-dir ./logs -print-host-events=false

# New native execution
sudo ./src/bpf-detect -output-dir ./logs -print-host-events=false -output-format json -workers 4 -buffer-size 10000 -debug=false

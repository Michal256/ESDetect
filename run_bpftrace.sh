#!/bin/bash

# Increase the string length limit for bpftrace if needed
# export BPFTRACE_MAX_STRLEN=200

TRACE_FILE="${1:-trace.bt}"

if [ ! -f "$TRACE_FILE" ]; then
    echo "Error: Trace file '$TRACE_FILE' not found."
    exit 1
fi

echo "Starting bpf-detect (Legacy bpftrace mode) using $TRACE_FILE..."
sudo bpftrace "$TRACE_FILE" | sudo ./src/bpf-detect -output-dir ./logs -print-host-events=false -use-bpftrace -output-format json

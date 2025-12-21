#!/bin/bash
set -e

echo "=== Cgroup Resolution Debugger ==="
echo "This script simulates the steps taken by the Python BPF tool to resolve container metadata."
echo ""

# 1. Find a target PID
if [ -n "$1" ]; then
    TARGET_PID=$1
    echo "[1] Using provided PID: $TARGET_PID"
else
    echo "[1] Finding a target process inside a container..."
    # Use awk to check ONLY the cgroup column (field 2) to avoid matching command arguments.
    # We look for 'docker-' or 'docker/' followed by hex, or 'kubepods'.
    TARGET_PID=$(ps -eo pid,cgroup:512,cmd | awk '$2 ~ /docker[-/][0-9a-f]+/ || $2 ~ /kubepods/ { print $1 }' | head -n 1)
fi

if [ -z "$TARGET_PID" ]; then
    echo "Error: No container process found automatically."
    echo "Usage: ./debug_resolution.sh [PID]"
    echo "You can find a PID using: docker inspect -f '{{.State.Pid}}' <container_id>"
    exit 1
fi

echo "    Found PID: $TARGET_PID"
CMD=$(ps -p $TARGET_PID -o comm=)
echo "    Command: $CMD"
echo ""

# 2. Get Cgroup Path & Inode
echo "[2] Resolving Cgroup Path & Inode..."
# Read /proc/<pid>/cgroup. We assume cgroup v2 (unified) or pick the first relevant controller.
# For v2, the line is "0::/path/to/cgroup"
RAW_CGROUP=$(cat /proc/$TARGET_PID/cgroup | head -n 1)
echo "    Raw /proc entry: $RAW_CGROUP"

# Extract path (remove "0::" or "x:y:")
REL_PATH=$(echo "$RAW_CGROUP" | cut -d: -f3)
FULL_PATH="/sys/fs/cgroup${REL_PATH}"

echo "    Full Path: $FULL_PATH"

if [ ! -d "$FULL_PATH" ]; then
    echo "Error: Cgroup directory not found at $FULL_PATH"
    exit 1
fi

INODE=$(stat -c %i "$FULL_PATH")
echo "    Inode (cgroup_id): $INODE"
echo ""

# 3. Extract Container ID (Regex Simulation)
echo "[3] Extracting Container ID from Path..."
CID=""
POD_UID=""

# Simple bash regex matching (simulating Python patterns)
if [[ "$REL_PATH" =~ docker[-/]([0-9a-f]{12,64}) ]]; then
    CID="${BASH_REMATCH[1]}"
    echo "    Matched Docker pattern. CID: $CID"
elif [[ "$REL_PATH" =~ cri-containerd-([0-9a-f]{12,64}) ]]; then
    CID="${BASH_REMATCH[1]}"
    echo "    Matched CRI pattern. CID: $CID"
elif [[ "$REL_PATH" =~ /kubepods/.*pod([0-9a-f_-]+)/([0-9a-f]{64}) ]]; then
    POD_UID="${BASH_REMATCH[1]}"
    CID="${BASH_REMATCH[2]}"
    # Fix UID format (replace _ with -)
    POD_UID=${POD_UID//_/-}
    echo "    Matched K8s pattern. CID: $CID"
    echo "    Matched K8s pattern. UID: $POD_UID"
else
    echo "    No standard container pattern matched."
fi

if [ -z "$CID" ] && [ -z "$POD_UID" ]; then
    echo "    Could not extract ID. Stopping here."
    exit 0
fi
echo ""

# 4. Find Runc State
echo "[4] Searching for Runc State..."

# Define paths to check (sync with lib/config.py)
SEARCH_PATHS=(
    "/run/containerd/runc/k8s.io"
    "/var/snap/microk8s/common/run/containerd/runc/k8s.io"
    "/run/runc"
    "/run/docker/runtime-runc/moby"
)

# Add rootless paths
if [ -d "/run/user" ]; then
    for u in /run/user/*; do
        SEARCH_PATHS+=("$u/docker/runtime-runc/moby")
    done
fi

FOUND_STATE=""

# Function to check a dir for the CID
check_dir() {
    local base=$1
    local id=$2
    if [ -f "$base/$id/state.json" ]; then
        echo "$base/$id/state.json"
        return 0
    fi
    return 1
}

# Try by CID
if [ -n "$CID" ]; then
    echo "    Looking for CID: $CID"
    for p in "${SEARCH_PATHS[@]}"; do
        if res=$(check_dir "$p" "$CID"); then
            FOUND_STATE="$res"
            echo "    FOUND at: $FOUND_STATE"
            break
        fi
    done
fi

# Try by UID (Reverse lookup simulation)
if [ -z "$FOUND_STATE" ] && [ -n "$POD_UID" ]; then
    echo "    CID not found directly. Scanning for Pod UID: $POD_UID..."
    for p in "${SEARCH_PATHS[@]}"; do
        if [ -d "$p" ]; then
            # Scan all subdirs
            for container_dir in "$p"/*; do
                if [ -f "$container_dir/state.json" ]; then
                    # Grep for the UID in the file (simple check)
                    if grep -q "$POD_UID" "$container_dir/state.json"; then
                        FOUND_STATE="$container_dir/state.json"
                        echo "    FOUND via UID at: $FOUND_STATE"
                        break 2
                    fi
                fi
            done
        fi
    done
fi

if [ -z "$FOUND_STATE" ]; then
    echo "    State file not found in any configured path."
    exit 1
fi
echo ""

# 5. Read Metadata
echo "[5] Reading Metadata..."
if command -v jq >/dev/null; then
    echo "    Container ID: $(cat "$FOUND_STATE" | jq -r .id)"
    echo "    Bundle: $(cat "$FOUND_STATE" | jq -r .bundle)"
    echo "    Annotations (first 5):"
    cat "$FOUND_STATE" | jq .config.labels | head -n 5
else
    echo "    (jq not installed, dumping raw first 20 lines)"
    head -n 20 "$FOUND_STATE"
fi

echo ""
echo "=== Debugging Complete ==="

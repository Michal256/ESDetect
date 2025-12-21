#!/bin/bash
set -e

# Ensure we are in the right directory
cd "$(dirname "$0")"

echo "Building Builder Image..."
docker build -t bpf-detect-builder -f Dockerfile.build .

echo "Running Build..."
# We mount the current directory to /app/output to extract the binary
docker run --rm \
    -v $(pwd):/app/output \
    bpf-detect-builder \
    sh -c "cp bpf-detect /app/output/bpf-detect && chown $(id -u):$(id -g) /app/output/bpf-detect"

echo "Build complete! Binary is at src/bpf-detect"

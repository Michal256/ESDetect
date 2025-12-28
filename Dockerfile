FROM golang:1.25.5-trixie AS builder

# Install build dependencies for BPF
# clang, llvm: for compiling C to BPF
# bpftool: for generating vmlinux.h
# libbpf-dev: BPF library headers
# linux-headers-generic: Kernel headers
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    bpftool \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source code
COPY src/ .

# Download dependencies
RUN go mod tidy

# Generate BPF artifacts (Go bindings)
RUN cd bpf && go generate -x -v gen.go

# Build the binary statically
RUN CGO_ENABLED=0 go build -ldflags "-s -w" -o bpf-detect .

# Final stage
FROM alpine:3.22

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/bpf-detect .

# BPF requires root privileges
USER root

ENTRYPOINT ["./bpf-detect"]

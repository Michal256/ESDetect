// +build ignore

// We are not using vmlinux.h to avoid dependency on kernel headers/BTF during build.
// Instead we define the necessary structs manually.
// #include "vmlinux.h"

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Define the tracepoint struct manually
struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};

struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
};

char __license[] SEC("license") = "Dual MIT/GPL";

struct event_t {
    __u32 pid;
    __u32 type; // 1 = EXEC, 2 = OPEN
    __u64 cgroup_id;
    __u8 comm[16];
    __u8 filename[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Force emission of struct event_t into the ELF
const struct event_t *unused __attribute__((unused));

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->type = 1; // EXEC
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // The second argument of execve is the filename (const char *filename)
    // In trace_event_raw_sys_enter, args[0] is the first argument.
    // sys_enter_execve(const char *filename, const char *const *argv, const char *const *envp)
    // So filename is args[0].
    
    // Note: ctx->args is an array of unsigned long.
    // We need to read the string from user space.
    long ret = bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (const char *)ctx->args[0]);
    if (ret < 0) {
        e->filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->type = 2; // OPEN
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // sys_enter_openat(int dfd, const char *filename, int flags, umode_t mode)
    // filename is args[1]
    long ret = bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (const char *)ctx->args[1]);
    if (ret < 0) {
        e->filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlinkat")
int trace_readlinkat(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->type = 3; // READLINK
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // sys_enter_readlinkat(int dfd, const char *pathname, char *buf, int bufsiz)
    // pathname is args[1]
    long ret = bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (const char *)ctx->args[1]);
    if (ret < 0) {
        e->filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readlink")
int trace_readlink(struct trace_event_raw_sys_enter *ctx) {
    struct event_t *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->type = 3; // READLINK
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // sys_enter_readlink(const char *pathname, char *buf, int bufsiz)
    // pathname is args[0]
    long ret = bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (const char *)ctx->args[0]);
    if (ret < 0) {
        e->filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

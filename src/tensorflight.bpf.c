#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "tensorflight.h"

char LICENSE[] SEC("license") = "GPL";

// Temporary map for saving device classification between openat enter & exit
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);   // pid_tgid
    __type(value, __u8);  // enum gpu_dev_type
} inflight_opens SEC(".maps");

// (pid << 32 | fd) -> enum gpu_dev_type
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u8);
} gpu_fds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024); /* 16 MB circular ring buffer */
} events SEC(".maps");

// Stores the process IDs selected for monitoring.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u8);
} target_pids SEC(".maps");

// A helper for bounded prefix matching that is safe for the eBPF verifier
// Returns 1 if it matches up to `len` characters (and the string is not truncated before `len`)
static __always_inline int path_starts_with(const char *path, const char *prefix, int len)
{
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (i >= len) 
            return 1;
        if (path[i] == '\0' || path[i] != prefix[i])
            return 0;
    }
    return 1;
}

static __always_inline int is_ascii_digit(char c)
{
    return c >= '0' && c <= '9';
}

// Classify GPU/compute device nodes from the path read to the stack buffer.
// Ensure that `path` is at least 32 bytes in size and is null-terminated
static __always_inline __u8 classify_gpu_path(const char *path)
{
    if (!path || path[0] != '/')
        return GPU_DEV_UNKNOWN;

    /* /dev/nvidiactl (exact match: 14 chars) */
    if (path_starts_with(path, "/dev/nvidiactl", 14) && path[14] == '\0') {
        return GPU_DEV_NVIDIA_CTL;
    }

    /* /dev/nvidia-uvm dan /dev/nvidia-uvm-tools */
    if (path_starts_with(path, "/dev/nvidia-uvm", 15)) {
        if (path[15] == '\0' || path[15] == '-') {
            return GPU_DEV_NVIDIA_UVM;
        }
    }

    /* /dev/nvidia0, /dev/nvidia1, ... (11 chars + minimal 1 digit) */
    if (path_starts_with(path, "/dev/nvidia", 11) && is_ascii_digit(path[11])) {
        return GPU_DEV_NVIDIA_GPU;
    }

    /* /dev/dri/renderD128, renderD129, ... (16 chars + minimal 1 digit) */
    if (path_starts_with(path, "/dev/dri/renderD", 16) && is_ascii_digit(path[16])) {
        return GPU_DEV_DRI_RENDER;
    }

    return GPU_DEV_UNKNOWN;
}

// Attaches a tracing program to the ioctl syscall entry point.
SEC("tracepoint/syscalls/sys_enter_ioctl")
int handle_ioctl_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;
    __u32 fd  = (__u32)ctx->args[0];

    // Check if (pid, fd) listed as GPU device
    __u64 pid_fd = ((__u64)pid << 32) | fd;
    __u8 *dev_type = bpf_map_lookup_elem(&gpu_fds, &pid_fd);
    if (!dev_type) {
        return 0; 
    }

    struct gpu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts_ns = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();
    e->pid = pid;
    e->tid = tid;
    e->kind = EVENT_IOCTL_ENTER;
    e->fd = fd;
    e->cmd = (__u64)ctx->args[1];
    e->arg = (__u64)ctx->args[2];
    e->dev_type = *dev_type;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!bpf_map_lookup_elem(&target_pids, &pid))
        return 0;

    char filename[32] = {};
    const char *user_filename = (const char *)ctx->args[1];
    long n = bpf_probe_read_user_str(filename, sizeof(filename), user_filename);
    if (n <= 1) {
        /* n < 0: fault/error when read user memory;
         * n == 0 or n == 1: empty string/just '\0', not GPU device path */
        return 0;
    }

    __u8 dev_type = classify_gpu_path(filename);
    if (dev_type != GPU_DEV_UNKNOWN) {
        bpf_map_update_elem(&inflight_opens, &pid_tgid, &dev_type, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u8 *dev_type = bpf_map_lookup_elem(&inflight_opens, &pid_tgid);
    if (!dev_type)
        return 0;

    long ret_fd = ctx->ret;
    if (ret_fd >= 0) {
        __u32 pid = pid_tgid >> 32;
        __u64 pid_fd = ((__u64)pid << 32) | (__u32)ret_fd;
        bpf_map_update_elem(&gpu_fds, &pid_fd, dev_type, BPF_ANY);
    }

    bpf_map_delete_elem(&inflight_opens, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int handle_close_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!bpf_map_lookup_elem(&target_pids, &pid))
        return 0;

    __u32 fd = (__u32)ctx->args[0];
    __u64 pid_fd = ((__u64)pid << 32) | fd;
    bpf_map_delete_elem(&gpu_fds, &pid_fd);

    return 0;
}
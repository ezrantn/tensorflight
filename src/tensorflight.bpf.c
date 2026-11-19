// Defines a ring buffer used to transfer kernel events
// to the userspace collector.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "tensorflight.h"

char LICENSE[] SEC("license") = "GPL";

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

// Attaches a tracing program to the ioctl syscall entry point.
SEC("tracepoint/syscalls/sys_enter_ioctl")
int handle_ioctl_enter(struct trace_event_raw_sys_enter *ctx)
{
    // Extract the current process and thread identifiers.

    // Check whether the current process is registered
    // in the target PID map.

    // Retrieve the ioctl file descriptor, command, and argument.

    // Collect additional process metadata such as
    // timestamp, cgroup ID, and process name.

    // Construct a GPU event record using the shared event structure.

    // Submit the event to the ring buffer for userspace consumption.

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 tid = (__u32)pid_tgid;

    __u8 *tracked = bpf_map_lookup_elem(&target_pids, &pid);
    if (!tracked) {
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
    e->fd = (__u32)ctx->args[0];
    e->cmd = (__u64)ctx->args[1];
    e->arg = (__u64)ctx->args[2];
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
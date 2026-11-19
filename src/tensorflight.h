// gpu_event structure make aligned memory so there is no unexpected padding 
#ifndef __TENSORFLIGHT_H
#define __TENSORFLIGHT_H

#ifndef __BPF__
#include <linux/types.h>
#endif

#define TASK_COMM_LEN 16

// Defines the types of events that Tensorflight can observe.
enum event_kind {
    EVENT_IOCTL_ENTER = 1,
    EVENT_CUDA_LAUNCH = 2,
    EVENT_CUDA_MEMCPY = 3,
};

// Defines the event structure shared between kernel-space
// and userspace to ensure consistent data representation.
struct gpu_event {
    __u64 ts_ns;       // Timestamp in nanoseconds.
    __u64 cgroup_id;   // Identifier of the process control group.
    __u32 pid;         // Process identifier.
    __u32 tid;         // Thread identifier.
    __u32 kind;        // Event type.
    __u32 fd;          // File descriptor associated with the syscall.
    __u64 cmd;         // ioctl command identifier.
    __u64 arg;         // ioctl argument.
    char comm[TASK_COMM_LEN]; // Name of the process.
};
#endif
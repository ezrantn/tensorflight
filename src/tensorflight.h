// gpu_event structure make aligned memory so there is no unexpected padding 
#ifndef __TENSORFLIGHT_H
#define __TENSORFLIGHT_H

#ifndef __BPF__
#include <linux/types.h>
#endif

#define TASK_COMM_LEN 16

enum gpu_dev_type {
    GPU_DEV_UNKNOWN = 0,    // 
    GPU_DEV_NVIDIA_CTL = 1, // /dev/nvidiactl
    GPU_DEV_NVIDIA_UVM = 2, // /dev/nvidia-uvm
    GPU_DEV_NVIDIA_GPU = 3, // /dev/nvidia0, /dev/nvidia1, etc
    GPU_DEV_DRI_RENDER = 4, // /dev/dri/renderD*
};

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
    __u8 dev_type;
    char comm[TASK_COMM_LEN]; // Name of the process.
    __u8 _pad[7];
};
#endif
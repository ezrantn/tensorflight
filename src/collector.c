#include <stdio.h>
#include <string.h>
#include "collector.h"

static const char *dev_type_str(__u8 dev_type)
{
    switch (dev_type) {
    case GPU_DEV_NVIDIA_CTL:  return "nvidiactl";
    case GPU_DEV_NVIDIA_UVM:  return "nvidia-uvm";
    case GPU_DEV_NVIDIA_GPU:  return "nvidia-gpu";
    case GPU_DEV_DRI_RENDER:  return "dri-render";
    default:                 return "unknown";
    }
}

// Handles an event received from the BPF ring buffer.
int collector_handle_event(void *ctx, void *data, size_t data_sz)
{
    if (!ctx || !data || data_sz < sizeof(struct gpu_event))
        return -1;

    const struct gpu_event *e = data;
    struct collector_ctx *c = ctx;

    if (!c)
        return -1;

    c->event_count++;
    memcpy(&c->last_event, e, sizeof(*e));

    if (c->out) {
        fprintf(c->out,
            "[%llu] cgroup=%llu pid=%u tid=%u "
            "comm=%-16s dev=%s fd=%u cmd=0x%llx arg=0x%llx\n",
            (unsigned long long)e->ts_ns,
            (unsigned long long)e->cgroup_id,
            e->pid,
            e->tid,
            e->comm,
            dev_type_str(e->dev_type),
            e->fd,
            (unsigned long long)e->cmd,
            (unsigned long long)e->arg);

        fflush(c->out);
    }

    return 0;
}

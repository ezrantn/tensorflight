#include <stdio.h>
#include <string.h>
#include "collector.h"

// Handles an event received from the BPF ring buffer.
int collector_handle_event(void *ctx, void *data, size_t data_sz)
{
    // Reject invalid or incomplete event payloads.
    if (!data || data_sz < sizeof(struct gpu_event))
        return -1;

    // Interpret the received payload using the shared event structure.
    const struct gpu_event *e = data;

    // Retrieve the collector context.
    struct collector_ctx *c = ctx;

    if (c) {
        // Increment the number of successfully processed events.
        c->event_count++;

        // Preserve a copy of the latest received event.
        memcpy(&c->last_event, e, sizeof(*e));

        if (c->out) {
            // Print event metadata when an output stream is available.
            fprintf(c->out,
                "[%llu] cgroup=%llu pid=%u tid=%u comm=%-16s fd=%u cmd=0x%llx arg=0x%llx\n",
                (unsigned long long)e->ts_ns,
                (unsigned long long)e->cgroup_id,
                e->pid, e->tid, e->comm, e->fd,
                (unsigned long long)e->cmd,
                (unsigned long long)e->arg);
        }
    }

    return 0;
}
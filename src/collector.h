#ifndef __COLLECTOR_H
#define __COLLECTOR_H

#include <stddef.h>
#include <stdio.h>
#include "tensorflight.h"

// Maintains the state of the userspace event collector.
struct collector_ctx {
    FILE *out;                    // Output stream for event logging.
    size_t event_count;           // Number of events processed.
    struct gpu_event last_event;  // Stores the most recently received event.
};

int collector_handle_event(void *ctx, void *data, size_t data_sz);

#endif
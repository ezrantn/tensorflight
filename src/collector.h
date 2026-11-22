#ifndef __COLLECTOR_H
#define __COLLECTOR_H

#include "tensorflight.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define TASK_COMM_LEN 16

// Maintains the state of the userspace event collector.
struct collector_ctx {
  FILE *out;                   // Output stream for event logging.
  size_t event_count;          // Number of events processed.
  struct gpu_event last_event; // Stores the most recently received event.
};

struct ioctl_event {
  uint32_t pid;
  uint32_t cmd;
  uint8_t dir;
  uint8_t magic;
  uint8_t nr;
  uint8_t _pad;
  uint16_t size;
  uint16_t _pad2;
  uint64_t arg;
  char comm[TASK_COMM_LEN];
  char dev[32];
};

const char *tf_ioctl_cmd_name(__u8 dev_type, uint8_t nr);
int collector_handle_event(void *ctx, void *data, size_t data_sz);

#endif
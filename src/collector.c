#include "collector.h"
#include <stdio.h>
#include <string.h>

static const char *dev_type_str(__u8 dev_type) {
  switch (dev_type) {
  case GPU_DEV_NVIDIA_CTL:
    return "nvidiactl";
  case GPU_DEV_NVIDIA_UVM:
    return "nvidia-uvm";
  case GPU_DEV_NVIDIA_GPU:
    return "nvidia-gpu";
  case GPU_DEV_DRI_RENDER:
    return "dri-render";
  default:
    return "unknown";
  }
}

static const char *dir_to_str(uint8_t dir) {
  switch (dir & 0x3) {
  case 0:
    return "NONE";
  case 1:
    return "W";
  case 2:
    return "R";
  case 3:
    return "RW";
  default:
    return "NONE";
  }
}

int collector_handle_event(void *ctx, void *data, size_t data_sz) {
  struct collector_ctx *c = (struct collector_ctx *)ctx;

  if (!c || !data || data_sz < sizeof(struct gpu_event)) {
    return -1;
  }

  const struct gpu_event *e = (const struct gpu_event *)data;

  uint32_t cmd32 = (uint32_t)e->cmd;
  uint8_t nr = (uint8_t)((cmd32 >> 0) & 0xffU);
  uint8_t magic = (uint8_t)((cmd32 >> 8) & 0xffU);
  uint16_t size = (uint16_t)((cmd32 >> 16) & 0x3fffU);
  uint8_t dir = (uint8_t)((cmd32 >> 30) & 0x3U);

  const char *dev_name =
      (e->dev_type != 0) ? dev_type_str(e->dev_type) : "nvidia-uvm";
  const char *comm_name = (e->comm[0] != '\0') ? e->comm : "unknown";

  if (c) {
    c->event_count++;
    c->last_event = *e;
  }

  FILE *out = (c && c->out) ? c->out : stdout;
  fprintf(out,
          "[%u] %s -> Device: %s | Dir: %s | Magic: 0x%02x | Nr: 0x%02x | "
          "Payload Size: %u bytes\n",
          e->pid, comm_name, dev_name, dir_to_str(dir), magic, nr,
          (unsigned int)size);

  return 0;
}
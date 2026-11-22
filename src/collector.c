#include "collector.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct ioctl_nr_entry {
  uint8_t nr;
  const char *name;
};

// RM & Frontend ioctl numbers (nv_escape.h & nv-ioctl-numbers.h)
static const struct ioctl_nr_entry rm_ioctl_table[] = {
    {0x27, "NV_ESC_RM_ALLOC_MEMORY"},
    {0x28, "NV_ESC_RM_ALLOC_OBJECT"},
    {0x29, "NV_ESC_RM_FREE"},
    {0x2a, "NV_ESC_RM_CONTROL"},
    {0x2b, "NV_ESC_RM_ALLOC"},
    {0x34, "NV_ESC_RM_DUP_OBJECT"},
    {0x35, "NV_ESC_RM_SHARE"},
    {0x39, "NV_ESC_RM_I2C_ACCESS"},
    {0x41, "NV_ESC_RM_IDLE_CHANNELS"},
    {0x4a, "NV_ESC_RM_VID_HEAP_CONTROL"},
    {0x4d, "NV_ESC_RM_ACCESS_REGISTRY"},
    {0x4e, "NV_ESC_RM_MAP_MEMORY"},
    {0x4f, "NV_ESC_RM_UNMAP_MEMORY"},
    {0x52, "NV_ESC_RM_GET_EVENT_DATA"},
    {0x54, "NV_ESC_RM_ALLOC_CONTEXT_DMA2"},
    {0x56, "NV_ESC_RM_ADD_VBLANK_CALLBACK"},
    {0x57, "NV_ESC_RM_MAP_MEMORY_DMA"},
    {0x58, "NV_ESC_RM_UNMAP_MEMORY_DMA"},
    {0x59, "NV_ESC_RM_BIND_CONTEXT_DMA"},
    {0x5c, "NV_ESC_RM_EXPORT_OBJECT_TO_FD"},
    {0x5d, "NV_ESC_RM_IMPORT_OBJECT_FROM_FD"},
    {0x5e, "NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO"},
    {0x5f, "NV_ESC_RM_LOCKLESS_DIAGNOSTIC"},
    {0xc8, "NV_ESC_CARD_INFO"},           /* NV_IOCTL_BASE + 0  (200) */
    {0xc9, "NV_ESC_REGISTER_FD"},         /* NV_IOCTL_BASE + 1  (201) */
    {0xce, "NV_ESC_ALLOC_OS_EVENT"},      /* NV_IOCTL_BASE + 6  (206) */
    {0xcf, "NV_ESC_FREE_OS_EVENT"},       /* NV_IOCTL_BASE + 7  (207) */
    {0xd1, "NV_ESC_STATUS_CODE"},         /* NV_IOCTL_BASE + 9  (209) */
    {0xd2, "NV_ESC_CHECK_VERSION_STR"},   /* NV_IOCTL_BASE + 10 (210) */
    {0xd3, "NV_ESC_IOCTL_XFER_CMD"},      /* NV_IOCTL_BASE + 11 (211) */
    {0xd4, "NV_ESC_ATTACH_GPUS_TO_FD"},   /* NV_IOCTL_BASE + 12 (212) */
    {0xd5, "NV_ESC_QUERY_DEVICE_INTR"},   /* NV_IOCTL_BASE + 13 (213) */
    {0xd6, "NV_ESC_SYS_PARAMS"},          /* NV_IOCTL_BASE + 14 (214) */
    {0xd9, "NV_ESC_EXPORT_TO_DMABUF_FD"}, /* NV_IOCTL_BASE + 17 (217) */
    {0xda, "NV_ESC_WAIT_OPEN_COMPLETE"},  /* NV_IOCTL_BASE + 18 (218) */
};

/* UVM ioctl numbers (kernel-open/nvidia-uvm/uvm_ioctl.h, UVM_IOCTL_BASE(i) == i
 * on Linux) */
static const struct ioctl_nr_entry uvm_ioctl_table[] = {
    {0x01, "UVM_RESERVE_VA"},
    {0x02, "UVM_RELEASE_VA"},
    {0x03, "UVM_REGION_COMMIT"},
    {0x04, "UVM_REGION_DECOMMIT"},
    {0x05, "UVM_REGION_SET_STREAM"},
    {0x06, "UVM_SET_STREAM_RUNNING"},
    {0x07, "UVM_SET_STREAM_STOPPED"},
    {0x0a, "UVM_ADD_SESSION"},
    {0x0c, "UVM_ENABLE_COUNTERS"},
    {0x0d, "UVM_MAP_COUNTER"},
    {0x0e, "UVM_CREATE_EVENT_QUEUE"},
    {0x0f, "UVM_REMOVE_EVENT_QUEUE"},
    {0x10, "UVM_MAP_EVENT_QUEUE"},
    {0x11, "UVM_EVENT_CTRL"},
    {0x14, "UVM_GET_GPU_UUID_TABLE"},
    {0x15, "UVM_REGION_SET_BACKING"},
    {0x16, "UVM_REGION_UNSET_BACKING"},
    {0x19, "UVM_REGISTER_GPU_VASPACE"},
    {0x1a, "UVM_UNREGISTER_GPU_VASPACE"},
    {0x1b, "UVM_REGISTER_CHANNEL"},
    {0x1c, "UVM_UNREGISTER_CHANNEL"},
    {0x1d, "UVM_ENABLE_PEER_ACCESS"},
    {0x1e, "UVM_DISABLE_PEER_ACCESS"},
    {0x21, "UVM_MAP_EXTERNAL_ALLOCATION"},
    {0x22, "UVM_FREE"},
    {0x23, "UVM_MEM_MAP"},
    {0x25, "UVM_REGISTER_GPU"},
    {0x26, "UVM_UNREGISTER_GPU"},
    {0x27, "UVM_PAGEABLE_MEM_ACCESS"},
    {0x2a, "UVM_SET_PREFERRED_LOCATION"},
    {0x2b, "UVM_UNSET_PREFERRED_LOCATION"},
    {0x2c, "UVM_ENABLE_READ_DUPLICATION"},
    {0x2d, "UVM_DISABLE_READ_DUPLICATION"},
    {0x2e, "UVM_SET_ACCESSED_BY"},
    {0x2f, "UVM_UNSET_ACCESSED_BY"},
    {0x33, "UVM_MIGRATE"},
    {0x38, "UVM_TOOLS_INIT_EVENT_TRACKER"},
    {0x39, "UVM_TOOLS_SET_NOTIFICATION_THRESHOLD"},
    {0x3a, "UVM_TOOLS_EVENT_QUEUE_ENABLE_EVENTS"},
    {0x3b, "UVM_TOOLS_EVENT_QUEUE_DISABLE_EVENTS"},
    {0x3c, "UVM_TOOLS_ENABLE_COUNTERS"},
    {0x3d, "UVM_TOOLS_DISABLE_COUNTERS"},
    {0x3e, "UVM_TOOLS_READ_PROCESS_MEMORY"},
    {0x3f, "UVM_TOOLS_WRITE_PROCESS_MEMORY"},
    {0x40, "UVM_TOOLS_GET_PROCESSOR_UUID_TABLE"},
    {0x41, "UVM_MAP_DYNAMIC_PARALLELISM_REGION"},
    {0x42, "UVM_UNMAP_EXTERNAL"},
    {0x43, "UVM_TOOLS_FLUSH_EVENTS"},
    {0x44, "UVM_ALLOC_SEMAPHORE_POOL"},
    {0x45, "UVM_CLEAN_UP_ZOMBIE_RESOURCES"},
    {0x46, "UVM_PAGEABLE_MEM_ACCESS_ON_GPU"},
    {0x47, "UVM_POPULATE_PAGEABLE"},
    {0x48, "UVM_VALIDATE_VA_RANGE"},
    {0x49, "UVM_CREATE_EXTERNAL_RANGE"},
    {0x4a, "UVM_MAP_EXTERNAL_SPARSE"},
    {0x4b, "UVM_MM_INITIALIZE"},
    {0x4c, "UVM_TOOLS_INIT_EVENT_TRACKER_V2"},
    {0x4d, "UVM_TOOLS_GET_PROCESSOR_UUID_TABLE_V2"},
    {0x4e, "UVM_ALLOC_DEVICE_P2P"},
    {0x4f, "UVM_CLEAR_ALL_ACCESS_COUNTERS"},
    {0x50, "UVM_DISCARD"},
    {0x51, "UVM_QUERY_RESIDENCY"},
    {0x52, "UVM_IS_DMA_BUF_IMPORT_SUPPORTED"},
    {0x53, "UVM_IMPORT_DMA_BUF"},
    {0x54, "UVM_MAP_DMA_BUF"},
    {0x55, "UVM_UNMAP_DMA_BUF"},
};

static const char *lookup_nr(const struct ioctl_nr_entry *table, size_t len,
                             uint8_t nr) {
  for (size_t i = 0; i < len; i++) {
    if (table[i].nr == nr) {
      return table[i].name;
    }
  }
  return NULL;
}

const char *tf_ioctl_cmd_name(__u8 dev_type, uint8_t nr) {
  if (dev_type == GPU_DEV_NVIDIA_UVM) {
    const char *found =
        lookup_nr(uvm_ioctl_table,
                  sizeof(uvm_ioctl_table) / sizeof(uvm_ioctl_table[0]), nr);
    return found ? found : "UVM_UNKNOWN";
  }

  const char *found = lookup_nr(
      rm_ioctl_table, sizeof(rm_ioctl_table) / sizeof(rm_ioctl_table[0]), nr);
  return found ? found : "NV_ESC_UNKNOWN";
}

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

  const char *dev_name = dev_type_str(e->dev_type);
  const char *comm_name = (e->comm[0] != '\0') ? e->comm : "unknown";
  const char *cmd_name = tf_ioctl_cmd_name(e->dev_type, nr);

  if (c) {
    c->event_count++;
    c->last_event = *e;
  }

  FILE *out = (c && c->out) ? c->out : stdout;
  fprintf(out,
          "[%u] %s -> Device: %s | Cmd: %s (Nr: 0x%02x) | Dir: %s | "
          "Magic: 0x%02x | Payload Size: %u bytes\n",
          e->pid, comm_name, dev_name, cmd_name, nr, dir_to_str(dir), magic,
          (unsigned int)size);

  return 0;
}
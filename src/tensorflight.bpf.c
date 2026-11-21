#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "tensorflight.h"

char LICENSE[] SEC("license") = "GPL";

/* Standard asm-generic/ioctl.h bit layout (32-bit cmd) */
#define TF_IOC_NRBITS 8
#define TF_IOC_TYPEBITS 8
#define TF_IOC_SIZEBITS 14
#define TF_IOC_DIRBITS 2

#define TF_IOC_NRSHIFT 0
#define TF_IOC_TYPESHIFT (TF_IOC_NRSHIFT + TF_IOC_NRBITS)     /* 8  */
#define TF_IOC_SIZESHIFT (TF_IOC_TYPESHIFT + TF_IOC_TYPEBITS) /* 16 */
#define TF_IOC_DIRSHIFT (TF_IOC_SIZESHIFT + TF_IOC_SIZEBITS)  /* 30 */

#define TF_IOC_NRMASK ((1U << TF_IOC_NRBITS) - 1)     /* 0x00ff */
#define TF_IOC_TYPEMASK ((1U << TF_IOC_TYPEBITS) - 1) /* 0x00ff */
#define TF_IOC_SIZEMASK ((1U << TF_IOC_SIZEBITS) - 1) /* 0x3fff */
#define TF_IOC_DIRMASK ((1U << TF_IOC_DIRBITS) - 1)   /* 0x0003 */

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24); /* 16 MB */
} events SEC(".maps");

// Temporary map for saving device classification between openat enter & exit
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 10240);
  __type(key, __u64);  // pid_tgid
  __type(value, __u8); // enum gpu_dev_type
} inflight_opens SEC(".maps");

// (pid << 32 | fd) -> enum gpu_dev_type
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 65536);
  __type(key, __u64);
  __type(value, __u8);
} gpu_fds SEC(".maps");

static __always_inline int path_starts_with(const char *path,
                                            const char *prefix, int len) {
#pragma unroll
  for (int i = 0; i < 32; i++) {
    if (i >= len)
      return 1;
    if (path[i] == '\0' || path[i] != prefix[i])
      return 0;
  }
  return 1;
}

static __always_inline int is_ascii_digit(char c) {
  return c >= '0' && c <= '9';
}

// Classify full path (/dev/nvidiactl, /dev/nvidia-uvm, /dev/nvidia0,
// /dev/dri/renderD128)
static __always_inline __u8 classify_gpu_path(const char *path) {
  if (!path || path[0] != '/')
    return GPU_DEV_UNKNOWN;

  if (path_starts_with(path, "/dev/nvidiactl", 14) && path[14] == '\0')
    return GPU_DEV_NVIDIA_CTL;

  if (path_starts_with(path, "/dev/nvidia-uvm", 15)) {
    if (path[15] == '\0' || path[15] == '-')
      return GPU_DEV_NVIDIA_UVM;
  }

  if (path_starts_with(path, "/dev/nvidia", 11) && is_ascii_digit(path[11]))
    return GPU_DEV_NVIDIA_GPU;

  if (path_starts_with(path, "/dev/dri/renderD", 16) &&
      is_ascii_digit(path[16]))
    return GPU_DEV_DRI_RENDER;

  return GPU_DEV_UNKNOWN;
}

// Classify basename from dentry->d_name (nvidiactl, nvidia-uvm, nvidia0,
// renderD128)
static __always_inline __u8 classify_dentry_name(const char *name) {
  if (!name || name[0] == '\0')
    return GPU_DEV_UNKNOWN;

  if (path_starts_with(name, "nvidiactl", 9) && name[9] == '\0')
    return GPU_DEV_NVIDIA_CTL;

  if (path_starts_with(name, "nvidia-uvm", 10)) {
    if (name[10] == '\0' || name[10] == '-')
      return GPU_DEV_NVIDIA_UVM;
  }

  if (path_starts_with(name, "nvidia", 6) && is_ascii_digit(name[6]))
    return GPU_DEV_NVIDIA_GPU;

  if (path_starts_with(name, "renderD", 7) && is_ascii_digit(name[7]))
    return GPU_DEV_DRI_RENDER;

  return GPU_DEV_UNKNOWN;
}

static __always_inline __u8 resolve_dev_from_fd(unsigned int fd) {
  char name[32] = {0};
  struct task_struct *task = (struct task_struct *)bpf_get_current_task();
  struct files_struct *files = BPF_CORE_READ(task, files);
  if (!files)
    return GPU_DEV_UNKNOWN;

  struct fdtable *fdt = BPF_CORE_READ(files, fdt);
  if (!fdt)
    return GPU_DEV_UNKNOWN;

  unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
  if (fd >= max_fds)
    return GPU_DEV_UNKNOWN;

  struct file **fd_array = BPF_CORE_READ(fdt, fd);
  struct file *f = NULL;
  bpf_probe_read_kernel(&f, sizeof(f), &fd_array[fd]);
  if (!f)
    return GPU_DEV_UNKNOWN;

  struct dentry *dentry = BPF_CORE_READ(f, f_path.dentry);
  if (!dentry)
    return GPU_DEV_UNKNOWN;

  const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
  if (!name_ptr)
    return GPU_DEV_UNKNOWN;

  bpf_probe_read_kernel_str(name, sizeof(name), name_ptr);
  return classify_dentry_name(name);
}

SEC("tracepoint/syscalls/sys_enter_ioctl")
int handle_ioctl_enter(struct trace_event_raw_sys_enter *ctx) {
  unsigned int fd = (unsigned int)ctx->args[0];
  unsigned int cmd = (unsigned int)ctx->args[1];
  unsigned long arg = (unsigned long)ctx->args[2];

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = (__u32)(pid_tgid >> 32);
  __u32 tid = (__u32)pid_tgid;
  __u64 pid_fd = ((__u64)pid << 32) | fd;

  __u8 dev_type = GPU_DEV_UNKNOWN;
  __u8 *mapped_dev = bpf_map_lookup_elem(&gpu_fds, &pid_fd);
  if (mapped_dev) {
    dev_type = *mapped_dev;
  } else {
    dev_type = resolve_dev_from_fd(fd);
    if (dev_type != GPU_DEV_UNKNOWN) {
      bpf_map_update_elem(&gpu_fds, &pid_fd, &dev_type, BPF_ANY);
    }
  }

  if (dev_type != GPU_DEV_NVIDIA_CTL && dev_type != GPU_DEV_NVIDIA_UVM &&
      dev_type != GPU_DEV_NVIDIA_GPU) {
    return 0;
  }

  struct gpu_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;

  __builtin_memset(e, 0, sizeof(*e));
  e->ts_ns = bpf_ktime_get_ns();
  e->cgroup_id = bpf_get_current_cgroup_id();
  e->pid = pid;
  e->tid = tid;
  e->kind = EVENT_IOCTL_ENTER;
  e->fd = fd;
  e->cmd = (__u64)cmd;
  e->arg = (__u64)arg;
  e->dev_type = dev_type;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  bpf_ringbuf_submit(e, 0);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();

  char filename[32] = {};
  const char *user_filename = (const char *)ctx->args[1];
  long n = bpf_probe_read_user_str(filename, sizeof(filename), user_filename);
  if (n <= 1)
    return 0;

  __u8 dev_type = classify_gpu_path(filename);
  if (dev_type != GPU_DEV_UNKNOWN) {
    bpf_map_update_elem(&inflight_opens, &pid_tgid, &dev_type, BPF_ANY);
  }

  return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx) {
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
int handle_close_enter(struct trace_event_raw_sys_enter *ctx) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u32 fd = (__u32)ctx->args[0];
  __u64 pid_fd = ((__u64)pid << 32) | fd;

  bpf_map_delete_elem(&gpu_fds, &pid_fd);
  return 0;
}
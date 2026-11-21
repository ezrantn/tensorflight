#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "tensorflight.h"

char LICENSE[] SEC("license") = "GPL";

/* Standard asm-generic/ioctl.h bit layout (32-bit cmd) */
#define TF_IOC_NRBITS    8
#define TF_IOC_TYPEBITS  8
#define TF_IOC_SIZEBITS  14
#define TF_IOC_DIRBITS   2

#define TF_IOC_NRSHIFT   0
#define TF_IOC_TYPESHIFT (TF_IOC_NRSHIFT + TF_IOC_NRBITS)     /* 8  */
#define TF_IOC_SIZESHIFT (TF_IOC_TYPESHIFT + TF_IOC_TYPEBITS) /* 16 */
#define TF_IOC_DIRSHIFT  (TF_IOC_SIZESHIFT + TF_IOC_SIZEBITS) /* 30 */

#define TF_IOC_NRMASK    ((1U << TF_IOC_NRBITS) - 1)    /* 0x00ff */
#define TF_IOC_TYPEMASK  ((1U << TF_IOC_TYPEBITS) - 1)  /* 0x00ff */
#define TF_IOC_SIZEMASK  ((1U << TF_IOC_SIZEBITS) - 1)  /* 0x3fff */
#define TF_IOC_DIRMASK   ((1U << TF_IOC_DIRBITS) - 1)   /* 0x0003 */

#define TF_IOC_NONE      0U
#define TF_IOC_WRITE     1U
#define TF_IOC_READ      2U

#define NVIDIA_IOCTL_MAGIC 0x46U

struct ioctl_event {
    u32 pid;
    u32 cmd;
    u8  dir;       /* 0=NONE, 1=W, 2=R, 3=RW */
    u8  magic;     /* _IOC_TYPE */
    u8  nr;        /* _IOC_NR */
    u8  _pad;
    u16 size;      /* _IOC_SIZE (max 16383) */
    u16 _pad2;
    u64 arg;
    char comm[TASK_COMM_LEN];
    char dev[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16 MB */
} events SEC(".maps");

static __always_inline void parse_cmd(u32 cmd, u8 *dir, u8 *magic, u8 *nr, u16 *size) {
    *nr    = (u8)((cmd >> TF_IOC_NRSHIFT) & TF_IOC_NRMASK);
    *magic = (u8)((cmd >> TF_IOC_TYPESHIFT) & TF_IOC_TYPEMASK);
    *size  = (u16)((cmd >> TF_IOC_SIZESHIFT) & TF_IOC_SIZEMASK);
    *dir   = (u8)((cmd >> TF_IOC_DIRSHIFT) & TF_IOC_DIRMASK);
}

// Temporary map for saving device classification between openat enter & exit
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);   // pid_tgid
    __type(value, __u8);  // enum gpu_dev_type
} inflight_opens SEC(".maps");

// (pid << 32 | fd) -> enum gpu_dev_type
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u8);
} gpu_fds SEC(".maps");

// Stores the process IDs selected for monitoring.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u8);
} target_pids SEC(".maps");

// A helper for bounded prefix matching that is safe for the eBPF verifier
// Returns 1 if it matches up to `len` characters (and the string is not truncated before `len`)
static __always_inline int path_starts_with(const char *path, const char *prefix, int len)
{
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (i >= len) 
            return 1;
        if (path[i] == '\0' || path[i] != prefix[i])
            return 0;
    }
    return 1;
}

static __always_inline int is_ascii_digit(char c)
{
    return c >= '0' && c <= '9';
}

// Classify GPU/compute device nodes from the path read to the stack buffer.
// Ensure that `path` is at least 32 bytes in size and is null-terminated
static __always_inline __u8 classify_gpu_path(const char *path)
{
    if (!path || path[0] != '/')
        return GPU_DEV_UNKNOWN;

    /* /dev/nvidiactl (exact match: 14 chars) */
    if (path_starts_with(path, "/dev/nvidiactl", 14) && path[14] == '\0') {
        return GPU_DEV_NVIDIA_CTL;
    }

    /* /dev/nvidia-uvm dan /dev/nvidia-uvm-tools */
    if (path_starts_with(path, "/dev/nvidia-uvm", 15)) {
        if (path[15] == '\0' || path[15] == '-') {
            return GPU_DEV_NVIDIA_UVM;
        }
    }

    /* /dev/nvidia0, /dev/nvidia1, ... (11 chars + minimal 1 digit) */
    if (path_starts_with(path, "/dev/nvidia", 11) && is_ascii_digit(path[11])) {
        return GPU_DEV_NVIDIA_GPU;
    }

    /* /dev/dri/renderD128, renderD129, ... (16 chars + minimal 1 digit) */
    if (path_starts_with(path, "/dev/dri/renderD", 16) && is_ascii_digit(path[16])) {
        return GPU_DEV_DRI_RENDER;
    }

    return GPU_DEV_UNKNOWN;
}

static __always_inline void extract_dev_name(struct file *file, char *buf, int buf_sz) {
    __builtin_memset(buf, 0, buf_sz);
    if (!file)
        return;

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return;

    const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);
    if (name_ptr) {
        bpf_probe_kernel_read_str(buf, buf_sz, name_ptr);
    }
}

// Attaches a tracing program to the ioctl syscall entry point.
SEC("tracepoint/syscalls/sys_enter_ioctl")
int handle_ioctl_enter(struct trace_event_raw_sys_enter *ctx)
{
    unsigned int fd  = (unsigned int)ctx->args[0];
    unsigned int cmd = (unsigned int)ctx->args[1];
    unsigned long arg = (unsigned long)ctx->args[2];
    (void)fd;

    u8 dir = 0, magic = 0, nr = 0;
    u16 size = 0;
    parse_cmd((u32)cmd, &dir, &magic, &nr, &size);

    /* Retrieve the device name from task->files->fdt->fd[fd], if available. */
    char dev[32] = {0};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (files) {
        struct fdtable *fdt = BPF_CORE_READ(files, fdt);
        if (fdt) {
            unsigned int max_fds = BPF_CORE_READ(fdt, max_fds);
            if (fd < max_fds) {
                struct file **fd_array = BPF_CORE_READ(fdt, fd);
                struct file *f = NULL;
                bpf_probe_read_kernel(&f, sizeof(f), &fd_array[fd]);
                if (f) {
                    extract_dev_name(f, dev, sizeof(dev));
                }
            }
        }
    }

    /* Focus to NVIDIA / nvidia-uvm (magic 0x46 or dev name nvidia*) */
    bool is_nvidia_magic = (magic == NVIDIA_IOCTL_MAGIC);
    bool is_nvidia_dev   = (dev[0] == 'n' && dev[1] == 'v' && dev[2] == 'i' &&
                            dev[3] == 'd' && dev[4] == 'i' && dev[5] == 'a');

    if (!is_nvidia_magic && !is_nvidia_dev)
        return 0;

    struct ioctl_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid   = (u32)(pid_tgid >> 32);
    e->cmd   = (u32)cmd;
    e->dir   = dir;
    e->magic = magic;
    e->nr    = nr;
    e->size  = size;
    e->arg   = (u64)arg;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    if (dev[0] != '\0') {
        __builtin_memcpy(e->dev, dev, sizeof(e->dev));
    } else {
        /* Fallback if dentry label empty */
        const char fallback[] = "nvidia-uvm";
        __builtin_memcpy(e->dev, fallback, sizeof(fallback));
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!bpf_map_lookup_elem(&target_pids, &pid))
        return 0;

    char filename[32] = {};
    const char *user_filename = (const char *)ctx->args[1];
    long n = bpf_probe_read_user_str(filename, sizeof(filename), user_filename);
    if (n <= 1) {
        /* n < 0: fault/error when read user memory;
         * n == 0 or n == 1: empty string/just '\0', not GPU device path */
        return 0;
    }

    __u8 dev_type = classify_gpu_path(filename);
    if (dev_type != GPU_DEV_UNKNOWN) {
        bpf_map_update_elem(&inflight_opens, &pid_tgid, &dev_type, BPF_ANY);
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
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
int handle_close_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;

    if (!bpf_map_lookup_elem(&target_pids, &pid))
        return 0;

    __u32 fd = (__u32)ctx->args[0];
    __u64 pid_fd = ((__u64)pid << 32) | fd;
    bpf_map_delete_elem(&gpu_fds, &pid_fd);

    return 0;
}
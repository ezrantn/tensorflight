#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "tensorflight.h"
#include "collector.h"
#include "tensorflight.skel.h"

// Verifies that the GPU event structure has the expected size
// and field offsets to maintain kernel/userspace compatibility.
static void test_struct_layout(void)
{
    assert(sizeof(struct gpu_event) == 64);
    assert(offsetof(struct gpu_event, ts_ns) == 0);
    assert(offsetof(struct gpu_event, cgroup_id) == 8);
    assert(offsetof(struct gpu_event, pid) == 16);
    assert(offsetof(struct gpu_event, tid) == 20);
    assert(offsetof(struct gpu_event, kind) == 24);
    assert(offsetof(struct gpu_event, fd) == 28);
    assert(offsetof(struct gpu_event, cmd) == 32);
    assert(offsetof(struct gpu_event, arg) == 40);
    assert(offsetof(struct gpu_event, comm) == 48);
    printf("[PASS] test_struct_layout\n");
}

// Verifies event validation, payload processing,
// and collector state management.
static void test_collector_handle_event(void)
{
    struct collector_ctx ctx = { .out = NULL, .event_count = 0 };

    /* Payload too small */
    char tiny_buf[8] = {0};
    assert(collector_handle_event(&ctx, tiny_buf, sizeof(tiny_buf)) == -1);
    assert(ctx.event_count == 0);

    /* Payload valid */
    struct gpu_event mock = {
        .ts_ns = 123456789ULL,
        .cgroup_id = 42ULL,
        .pid = 1337,
        .tid = 1338,
        .kind = EVENT_IOCTL_ENTER,
        .fd = 7,
        .cmd = 0xdeadbeefULL,
        .arg = 0xcafebabeULL,
        .comm = "python3"
    };

    assert(collector_handle_event(&ctx, &mock, sizeof(mock)) == 0);
    assert(ctx.event_count == 1);
    assert(ctx.last_event.pid == 1337);
    assert(ctx.last_event.cmd == 0xdeadbeefULL);
    assert(strcmp(ctx.last_event.comm, "python3") == 0);

    printf("[PASS] test_collector_handle_event\n");
}

// Verifies BPF program loading, kernel attachment,
// and real ioctl event delivery through the ring buffer.
static void test_bpf_load_and_ioctl_capture(void)
{
    if (geteuid() != 0) {
        printf("[SKIP] test_bpf_load_and_ioctl_capture (requires root / CAP_BPF)\n");
        return;
    }

    struct tensorflight_bpf *skel = tensorflight_bpf__open_and_load();
    assert(skel != NULL && "BPF verifier rejected program");

    __u32 my_pid = (__u32)getpid();
    __u8 val = 1;
    int map_fd = bpf_map__fd(skel->maps.target_pids);
    assert(bpf_map_update_elem(map_fd, &my_pid, &val, BPF_ANY) == 0);

    assert(tensorflight_bpf__attach(skel) == 0);

    struct collector_ctx ctx = { .out = NULL, .event_count = 0 };
    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events), collector_handle_event, &ctx, NULL);
    assert(rb != NULL);

    int dummy_fd = open("/dev/null", O_RDONLY);
    assert(dummy_fd >= 0);

    const unsigned long magic_cmd = 0x54464C54; /* "TFLT" */
    const unsigned long magic_arg = 0x11223344;
    ioctl(dummy_fd, magic_cmd, magic_arg); /* Will return -1 ENOTTY, but syscall still inside kernel */
    close(dummy_fd);

    for (int i = 0; i < 10 && ctx.event_count == 0; i++) {
        ring_buffer__poll(rb, 50);
    }

    assert(ctx.event_count >= 1);
    assert(ctx.last_event.pid == my_pid);
    assert(ctx.last_event.kind == EVENT_IOCTL_ENTER);
    assert(ctx.last_event.cmd == magic_cmd);
    assert(ctx.last_event.arg == magic_arg);

    ring_buffer__free(rb);
    tensorflight_bpf__destroy(skel);
    printf("[PASS] test_bpf_load_and_ioctl_capture\n");
}

int main(void)
{
    test_struct_layout();
    test_collector_handle_event();
    test_bpf_load_and_ioctl_capture();
    printf("All tests finished.\n");
    return 0;
}
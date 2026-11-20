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
    assert(sizeof(struct gpu_event) == 72);
    assert(offsetof(struct gpu_event, ts_ns) == 0);
    assert(offsetof(struct gpu_event, cgroup_id) == 8);
    assert(offsetof(struct gpu_event, pid) == 16);
    assert(offsetof(struct gpu_event, tid) == 20);
    assert(offsetof(struct gpu_event, kind) == 24);
    assert(offsetof(struct gpu_event, fd) == 28);
    assert(offsetof(struct gpu_event, cmd) == 32);
    assert(offsetof(struct gpu_event, arg) == 40);
    assert(offsetof(struct gpu_event, comm) == 49);
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

    const unsigned long magic_cmd = 0x54464C54; /* "TFLT" */
    const unsigned long magic_arg = 0x11223344;

    int dummy_fd = open("/dev/null", O_RDONLY);
    assert(dummy_fd >= 0);
    errno = 0;
    assert(ioctl(dummy_fd, magic_cmd, magic_arg) == -1);
    assert(errno == ENOTTY);
    close(dummy_fd);

    for (int i = 0; i < 5; i++) {
        int ret = ring_buffer__poll(rb, 20);
        assert(ret >= 0 || ret == -EINTR);
    }
    assert(ctx.event_count == 0);

    const char *gpu_devs[] = {
        "/dev/nvidiactl",
        "/dev/nvidia-uvm",
        "/dev/nvidia0",
        "/dev/dri/renderD128",
        NULL
    };

    int gpu_fd = -1;
    for (int i = 0; gpu_devs[i] != NULL; i++) {
        gpu_fd = open(gpu_devs[i], O_RDWR);
        if (gpu_fd >= 0)
            break;
    }

    if (gpu_fd < 0) {
        printf("[SKIP] no accessible GPU device node found for live ioctl test\n");
        ring_buffer__free(rb);
        tensorflight_bpf__destroy(skel);
        return;
    }

    errno = 0;
    ioctl(gpu_fd, magic_cmd, magic_arg);
    close(gpu_fd);

    for (int i = 0; i < 10 && ctx.event_count == 0; i++) {
        int ret = ring_buffer__poll(rb, 50);
        assert(ret >= 0 || ret == -EINTR);
    }

    assert(ctx.event_count >= 1);
    assert(ctx.last_event.pid == my_pid);
    assert(ctx.last_event.kind == EVENT_IOCTL_ENTER);
    assert(ctx.last_event.cmd == magic_cmd);
    assert(ctx.last_event.arg == magic_arg);
    assert(ctx.last_event.dev_type != GPU_DEV_UNKNOWN);
}

static void test_collector_invalid_input(void)
{
    struct collector_ctx ctx = {
        .out = NULL,
        .event_count = 0
    };

    struct gpu_event mock = {0};

    assert(collector_handle_event(NULL, &mock, sizeof(mock)) == -1);
    assert(collector_handle_event(&ctx, NULL, sizeof(mock)) == -1);
    assert(collector_handle_event(&ctx, &mock, 0) == -1);

    assert(ctx.event_count == 0);

    printf("[PASS] test_collector_invalid_input\n");
}


static void test_collector_output(void)
{
    FILE *tmp = tmpfile();
    assert(tmp != NULL);

    struct collector_ctx ctx = {
        .out = tmp,
        .event_count = 0
    };

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

    fflush(tmp);
    rewind(tmp);

    char buffer[512] = {0};

    assert(fgets(buffer, sizeof(buffer), tmp) != NULL);

    assert(strstr(buffer, "pid=1337") != NULL);
    assert(strstr(buffer, "tid=1338") != NULL);
    assert(strstr(buffer, "python3") != NULL);
    assert(strstr(buffer, "cmd=0xdeadbeef") != NULL);

    fclose(tmp);

    printf("[PASS] test_collector_output\n");
}

int main(void)
{
    test_struct_layout();
    test_collector_handle_event();
    test_bpf_load_and_ioctl_capture();
    test_collector_invalid_input();
    test_collector_output();
    printf("All tests finished.\n");
    return 0;
}
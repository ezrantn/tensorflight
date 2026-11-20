
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "tensorflight.h"
#include "tensorflight.skel.h"
#include "collector.h"

static volatile sig_atomic_t exiting = 0;

// Handles termination signals.
static void sig_handler(int sig)
{
    exiting = 1;
}

int main(int argc, char **argv)
{
    struct tensorflight_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    struct collector_ctx collector = {
        .out = stdout,
        .event_count = 0,
    };

    int err;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target_pid>\n", argv[0]);
        return 1;
    }

    __u32 target_pid = (__u32)atoi(argv[1]);
    __u8 val = 1;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Load the BPF object and initialize its resources.
    skel = tensorflight_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Register the target PID in the BPF map.
    int map_fd = bpf_map__fd(skel->maps.target_pids);

    if (bpf_map_update_elem(map_fd, &target_pid, &val, BPF_ANY) != 0) {
        perror("bpf_map_update_elem");
        goto cleanup;
    }

    // Attach BPF programs to their respective kernel hooks.
    err = tensorflight_bpf__attach(skel);
    if (err) {
        char err_buf[256];
        libbpf_strerror(err, err_buf, sizeof(err_buf));

        fprintf(stderr, "Failed to attach BPF programs: %s\n", err_buf);
        goto cleanup;
    }

    // Initialize the userspace event collector.
    rb = ring_buffer__new(
        bpf_map__fd(skel->maps.events),
        collector_handle_event,
        &collector,
        NULL
    );

    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("TensorFlight recording PID %u... Ctrl+C to stop.\n", target_pid);

    // Continuously consume events from the BPF ring buffer.
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);

        if (err == -EINTR)
            break;

        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

    printf("\nTensorFlight recording stopped.\n");
    printf("Total events: %zu\n", collector.event_count);

cleanup:
    ring_buffer__free(rb);
    tensorflight_bpf__destroy(skel);

    return 0;
}

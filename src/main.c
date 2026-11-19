#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tensorflight.h"
#include "tensorflight.skel.h"

static volatile sig_atomic_t exiting = 0;

static void sig_handler(int sig)
{
    exiting = 1;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct gpu_event *e = data;

    printf("[%llu] cgroup=%llu pid=%u tid=%u comm=%-16s fd=%u cmd=0x%llx arg=0x%llx\n",
           e->ts_ns, e->cgroup_id, e->pid, e->tid,
           e->comm, e->fd, e->cmd, e->arg);

    return 0;
}

int main(int argc, char **argv)
{
    struct tensorflight_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <target_pid>\n", argv[0]);
        return 1;
    }

    __u32 target_pid = (__u32)atoi(argv[1]);
    __u8 val = 1;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    skel = tensorflight_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Daftarkan PID target ke BPF map */
    int map_fd = bpf_map__fd(skel->maps.target_pids);
    if (bpf_map_update_elem(map_fd, &target_pid, &val, BPF_ANY) != 0) {
        perror("bpf_map_update_elem");
        goto cleanup;
    }

    err = tensorflight_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs\n");
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Tensorflight recording PID %u... Ctrl+C to stop.\n", target_pid);

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err == -EINTR)
            break;
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    tensorflight_bpf__destroy(skel);
    return 0;
}
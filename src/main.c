#include "collector.h"
#include "tensorflight.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

static volatile sig_atomic_t exiting = 0;

// Handles termination signals.
static void sig_handler(int sig) {
  (void)sig;
  exiting = 1;
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;

  struct tensorflight_bpf *skel = NULL;
  struct ring_buffer *rb = NULL;
  int err = 0;

  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  skel = tensorflight_bpf__open_and_load();
  if (!skel) {
    fprintf(stderr, "Failed to open and load BPF skeleton\n");
    return 1;
  }

  err = tensorflight_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
    goto cleanup;
  }

  int map_fd = bpf_map__fd(skel->maps.events);
  if (map_fd < 0) {
    fprintf(stderr, "Failed to get ringbuf map fd 'events': %d\n", map_fd);
    err = map_fd;
    goto cleanup;
  }

  struct collector_ctx ctx = {
      .out = stdout,
      .event_count = 0,
  };

  rb = ring_buffer__new(map_fd, collector_handle_event, &ctx, NULL);
  if (!rb) {
    err = errno ? -errno : -1;
    fprintf(stderr, "Failed to create ring buffer: %d\n", err);
    goto cleanup;
  }

  fprintf(stderr,
          "Tensorflight active — monitoring NVIDIA ioctl commands...\n");

  while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* ms */);
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      fprintf(stderr, "Error polling ring buffer: %d\n", err);
      break;
    }
    err = 0;
  }

  if (rb && err == 0) {
    (void)ring_buffer__consume(rb);
  }

  fprintf(stderr, "\nTensorflight stopped — total events processed: %zu\n",
          ctx.event_count);

cleanup:
  ring_buffer__free(rb);
  tensorflight_bpf__destroy(skel);
  return err < 0 ? 1 : 0;
}
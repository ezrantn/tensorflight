CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)
CFLAGS := -g -O2 -Wall -Isrc -I.output
LDFLAGS := -lbpf -lelf -lz
TEST_BIN := .output/test_tensorflight

all: .output/tensorflight

.output:
	mkdir -p .output

.output/vmlinux.h: | .output
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

.output/tensorflight.bpf.o: src/tensorflight.bpf.c src/tensorflight.h .output/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -I.output -c $< -o $@

.output/tensorflight.skel.h: .output/tensorflight.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

.output/tensorflight: src/main.c src/collector.c src/collector.h src/tensorflight.h .output/tensorflight.skel.h
	$(CC) $(CFLAGS) src/main.c src/collector.c -o $@ $(LDFLAGS)

clean:
	rm -rf .output

$(TEST_BIN): tests/test_tensorflight.c src/collector.c src/tensorflight.h .output/tensorflight.skel.h
	$(CC) $(CFLAGS) tests/test_tensorflight.c src/collector.c -o $@ $(LDFLAGS)

test: $(TEST_BIN)
	./$(TEST_BIN)

test-root: $(TEST_BIN)
	sudo ./$(TEST_BIN)

.PHONY: all clean
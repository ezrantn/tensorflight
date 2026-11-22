# Tensorflight

> Status: *Research Prototype*

**Tensorflight** is a non-instrumented, low-overhead GPU runtime flight recorder built with **Pure C** and **libbpf (CO-RE)** for Linux. It aims to capture kernel-level (`ioctl`) and userspace runtime events to support post-incident forensic reconstruction, runtime visibility, and integrity verification for GPU workloads.

My NVIDIA driver version is **620.70.06**.
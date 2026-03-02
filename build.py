#!/usr/bin/env python3
"""CaptainOS build system entry point.

Usage:
    ./build.py              # Build the image (stages: kernel → tools → initramfs)
    ./build.py build        # Same as above
    ./build.py kernel       # Build only the kernel + modules
    ./build.py tools        # Download tools (containerd, runc, nerdctl, CNI)
    ./build.py initramfs    # Build only the initramfs via mkosi
    ./build.py shell        # Drop into an interactive shell inside the builder
    ./build.py clean        # Remove build artifacts
    ./build.py summary      # Print mkosi configuration summary
    ./build.py qemu-test    # Boot the built image in QEMU for testing

Environment variables:
    ARCH            Target architecture: amd64 (default) or arm64
    KERNEL_MODE     Kernel build mode: docker (default), native, or skip
    MKOSI_MODE      mkosi build mode: docker (default), native, or skip
    KERNEL_SRC      Path to a local kernel source tree (optional, avoids download)
    KERNEL_VERSION  Kernel version to build (default: 6.12.69)
    NO_CACHE        Set to 1 to force Docker image rebuild without cache
    BUILDER_IMAGE   Override the builder Docker image name (default: captainos-builder)
    FORCE_KERNEL    Set to 1 to force kernel rebuild
    FORCE_TOOLS     Set to 1 to re-download tools
    QEMU_APPEND     Extra kernel cmdline args for qemu-test
    QEMU_MEM        QEMU RAM size (default: 2G)
    QEMU_SMP        QEMU CPU count (default: 2)

Tinkerbell kernel cmdline (qemu-test only, passed via /proc/cmdline):
    TINK_GRPC_AUTHORITY       tink-server gRPC endpoint (host:port)
    TINK_DOCKER_REGISTRY      Registry host (triggers tink-agent services)
    TINK_WORKER_IMAGE         Full image ref (overrides TINK_DOCKER_REGISTRY)
    TINK_WORKER_ID            Machine / worker ID (auto-detected when empty)
    TINK_TLS                  Enable TLS to tink-server (default: false)
    TINK_INSECURE_TLS         Allow insecure TLS (default: true)
    TINK_INSECURE_REGISTRIES  Comma-separated insecure registries
    TINK_REGISTRY_USERNAME    Registry auth username
    TINK_REGISTRY_PASSWORD    Registry auth password
    TINK_SYSLOG_HOST          Remote syslog host
    TINK_FACILITY             Facility code

Requires: Python >= 3.10, Docker (unless all stages use native or skip)
"""

import sys

if sys.version_info < (3, 10):
    print("ERROR: Python >= 3.10 is required.", file=sys.stderr)
    sys.exit(1)

from captain.cli import main

if __name__ == "__main__":
    main()

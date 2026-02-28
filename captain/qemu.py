"""QEMU boot testing."""

from __future__ import annotations

import sys

from captain.config import Config
from captain.log import err, log
from captain.util import run


def run_qemu(cfg: Config) -> None:
    """Boot the built image in QEMU for quick testing."""
    kernel = cfg.output_dir / f"vmlinuz-{cfg.arch}"
    initrd = cfg.output_dir / f"initramfs-{cfg.arch}.cpio.zst"

    if not kernel.is_file() or not initrd.is_file():
        err("Build artifacts not found. Run './build.py' first.")
        sys.exit(1)

    log("Booting CaptainOS in QEMU (Ctrl-A X to exit)...")

    qemu_cmd = cfg.arch_info.qemu_binary
    append = f"console=ttyS0 audit=0 {cfg.qemu_append}".strip()

    log(f"Kernel cmdline: {append}")
    run(
        [
            qemu_cmd,
            "-kernel",
            str(kernel),
            "-initrd",
            str(initrd),
            "-append",
            append,
            "-nographic",
            "-m",
            cfg.qemu_mem,
            "-smp",
            cfg.qemu_smp,
            "-nic",
            "user,model=virtio-net-pci",
            "-no-reboot",
        ],
    )

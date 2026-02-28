"""Shared utilities: subprocess wrapper, path helpers, architecture mapping."""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from captain.log import err


@dataclass(slots=True)
class ArchInfo:
    """Architecture-specific build parameters."""

    arch: str  # canonical name: amd64 | arm64
    kernel_arch: str  # kernel ARCH value
    cross_compile: str  # CROSS_COMPILE prefix (empty for native)
    image_target: str  # kernel image make target
    kernel_image_path: str  # relative path to built kernel image
    dl_arch: str  # architecture name in download URLs
    mkosi_arch: str  # mkosi --architecture value
    qemu_binary: str  # QEMU system emulator binary
    strip_prefix: str  # prefix for strip command


def get_arch_info(arch: str) -> ArchInfo:
    """Return architecture-specific parameters for the given arch string."""
    match arch:
        case "amd64" | "x86_64":
            return ArchInfo(
                arch="amd64",
                kernel_arch="x86_64",
                cross_compile="",
                image_target="bzImage",
                kernel_image_path="arch/x86/boot/bzImage",
                dl_arch="amd64",
                mkosi_arch="x86-64",
                qemu_binary="qemu-system-x86_64",
                strip_prefix="",
            )
        case "arm64" | "aarch64":
            return ArchInfo(
                arch="arm64",
                kernel_arch="arm64",
                cross_compile="aarch64-linux-gnu-",
                image_target="Image",
                kernel_image_path="arch/arm64/boot/Image",
                dl_arch="arm64",
                mkosi_arch="arm64",
                qemu_binary="qemu-system-aarch64",
                strip_prefix="aarch64-linux-gnu-",
            )
        case _:
            err(f"Unsupported architecture: {arch}")
            sys.exit(1)


def run(
    cmd: list[str],
    *,
    check: bool = True,
    capture: bool = False,
    env: dict[str, str] | None = None,
    cwd: Path | str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a command, optionally merging extra env vars with the current environment."""
    run_env: dict[str, str] | None = None
    if env is not None:
        run_env = {**os.environ, **env}
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True,
        env=run_env,
        cwd=cwd,
    )


def ensure_dir(path: Path) -> Path:
    """Create a directory (and parents) if it doesn't exist, return the path."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def check_dependencies(arch: str) -> list[str]:
    """Check that all required host tools are available for a native (no-Docker) build.

    Returns a list of missing command names (empty if all found).
    """
    import shutil as _shutil

    # Core tools needed for kernel build + mkosi image assembly
    required = [
        "make",
        "gcc",
        "flex",
        "bison",
        "bc",
        "rsync",
        "strip",
        "mkosi",
        "zstd",
        "cpio",
        "bwrap",       # bubblewrap — used by mkosi
        "mksquashfs",  # squashfs-tools — used by mkosi
        "kmod",
    ]

    # Cross-compilation toolchain for arm64-on-x86_64
    if arch in ("arm64", "aarch64"):
        required.append("aarch64-linux-gnu-gcc")
        required.append("aarch64-linux-gnu-strip")

    return [cmd for cmd in required if _shutil.which(cmd) is None]

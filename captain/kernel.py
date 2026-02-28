"""Kernel download, configuration, compilation, and installation.

This module replaces scripts/build-kernel.sh.  Heavy lifting (make, strip)
is still done via subprocess — only the orchestration moves to Python.
"""

from __future__ import annotations

import os
import re
import shutil
import tarfile
import tempfile
import urllib.request
from pathlib import Path

from captain.config import Config
from captain.log import log, warn
from captain.util import ensure_dir, run


def _progress_hook(block_num: int, block_size: int, total_size: int) -> None:
    """Simple download progress indicator."""
    downloaded = block_num * block_size
    if total_size > 0:
        pct = min(100, downloaded * 100 // total_size)
        mb = downloaded / (1024 * 1024)
        total_mb = total_size / (1024 * 1024)
        print(f"\r    {mb:.1f}/{total_mb:.1f} MB ({pct}%)", end="", flush=True)
    else:
        mb = downloaded / (1024 * 1024)
        print(f"\r    {mb:.1f} MB", end="", flush=True)


def download_kernel(version: str, dest_dir: Path) -> Path:
    """Download and extract a kernel tarball.  Returns the source directory."""
    src_dir = dest_dir / f"linux-{version}"
    if src_dir.is_dir():
        log(f"Using cached kernel source at {src_dir}")
        return src_dir

    major = version.split(".")[0]
    url = f"https://cdn.kernel.org/pub/linux/kernel/v{major}.x/linux-{version}.tar.xz"
    tarball = dest_dir / f"linux-{version}.tar.xz"

    log(f"Downloading kernel {version}...")
    ensure_dir(dest_dir)
    urllib.request.urlretrieve(url, tarball, reporthook=_progress_hook)
    print()  # newline after progress

    log("Extracting kernel source...")
    with tarfile.open(tarball, "r:xz") as tf:
        tf.extractall(path=dest_dir, filter="data")
    tarball.unlink()

    return src_dir


def configure_kernel(cfg: Config, src_dir: Path) -> None:
    """Apply defconfig and run olddefconfig."""
    ai = cfg.arch_info
    defconfig = cfg.project_dir / "config" / f"defconfig.{ai.arch}"

    make_env = {"ARCH": ai.kernel_arch}
    if ai.cross_compile:
        make_env["CROSS_COMPILE"] = ai.cross_compile

    if defconfig.is_file():
        log(f"Using defconfig: {defconfig}")
        shutil.copy2(defconfig, src_dir / ".config")
        run(["make", "olddefconfig"], env=make_env, cwd=src_dir)
        # Save the resolved config for debugging
        resolved = cfg.project_dir / "config" / f".config.resolved.{ai.arch}"
        shutil.copy2(src_dir / ".config", resolved)
        log(f"Resolved config saved to config/.config.resolved.{ai.arch}")
    else:
        log(f"No defconfig found at {defconfig}, using default")
        run(["make", "defconfig"], env=make_env, cwd=src_dir)

    # Increase COMMAND_LINE_SIZE on x86_64 (Tinkerbell needs large cmdlines)
    if ai.kernel_arch == "x86_64":
        log("Increasing COMMAND_LINE_SIZE to 4096 (x86_64)...")
        setup_h = src_dir / "arch" / "x86" / "include" / "asm" / "setup.h"
        text = setup_h.read_text()
        text = re.sub(
            r"#define COMMAND_LINE_SIZE\s+2048",
            "#define COMMAND_LINE_SIZE 4096",
            text,
        )
        setup_h.write_text(text)


def build_kernel(cfg: Config, src_dir: Path) -> str:
    """Compile the kernel image and modules.  Returns the built kernel version string."""
    ai = cfg.arch_info
    nproc = os.cpu_count() or 1

    make_env = {"ARCH": ai.kernel_arch}
    if ai.cross_compile:
        make_env["CROSS_COMPILE"] = ai.cross_compile

    log(f"Building kernel with {nproc} jobs...")
    run(
        ["make", f"-j{nproc}", ai.image_target, "modules"],
        env=make_env,
        cwd=src_dir,
    )

    # Determine actual kernel version from build
    result = run(
        ["make", "-s", "kernelrelease"],
        env={"ARCH": ai.kernel_arch},
        capture=True,
        cwd=src_dir,
    )
    built_kver = result.stdout.strip()
    log(f"Built kernel version: {built_kver}")
    return built_kver


def install_kernel(cfg: Config, src_dir: Path, built_kver: str) -> None:
    """Install modules and kernel image into mkosi.output/kernel/."""
    ai = cfg.arch_info
    kernel_output = cfg.kernel_output

    make_env = {"ARCH": ai.kernel_arch}
    if ai.cross_compile:
        make_env["CROSS_COMPILE"] = ai.cross_compile

    # Install modules
    log("Installing modules...")
    run(
        ["make", f"INSTALL_MOD_PATH={kernel_output}", "modules_install"],
        env=make_env,
        cwd=src_dir,
    )

    # Strip debug symbols from modules
    log("Stripping debug symbols from modules...")
    strip_cmd = f"{ai.strip_prefix}strip"
    for ko in kernel_output.rglob("*.ko"):
        run([strip_cmd, "--strip-unneeded", str(ko)], check=False)

    # Clean up build/source symlinks
    mod_base = kernel_output / "lib" / "modules" / built_kver
    (mod_base / "build").unlink(missing_ok=True)
    (mod_base / "source").unlink(missing_ok=True)

    # Move modules from /lib/modules to /usr/lib/modules (merged-usr)
    usr_moddir = ensure_dir(kernel_output / "usr" / "lib" / "modules" / built_kver)
    if mod_base.is_dir():
        for item in mod_base.iterdir():
            dest = usr_moddir / item.name
            if dest.exists():
                if dest.is_dir():
                    shutil.rmtree(dest)
                else:
                    dest.unlink()
            shutil.move(str(item), str(dest))
        # Remove /lib tree
        shutil.rmtree(kernel_output / "lib", ignore_errors=True)

    # Copy kernel image
    kernel_image = src_dir / ai.kernel_image_path
    shutil.copy2(kernel_image, usr_moddir / "vmlinuz")

    # Also place a copy at a well-known location for easy extraction
    boot_dir = ensure_dir(kernel_output / "boot")
    shutil.copy2(kernel_image, boot_dir / f"vmlinuz-{built_kver}")

    log("Kernel build complete:")
    vmlinuz = usr_moddir / "vmlinuz"
    vmlinuz_size = vmlinuz.stat().st_size / (1024 * 1024)
    log(f"    Image:   {usr_moddir}/vmlinuz ({vmlinuz_size:.1f}M)")
    log(f"    Modules: {usr_moddir}/")
    log(f"    Version: {built_kver}")
    log(f"    Output:  {kernel_output}")


def build(cfg: Config) -> None:
    """Full kernel build pipeline — download, configure, build, install.

    This is called from inside the Docker builder container via build-kernel.py,
    or can be invoked directly when running natively.
    """
    # Clean previous output to ensure idempotency
    if cfg.kernel_output.exists():
        shutil.rmtree(cfg.kernel_output)
    ensure_dir(cfg.kernel_output)

    build_dir = Path("/var/tmp/kernel-build")

    # Obtain kernel source
    if cfg.kernel_src and Path(cfg.kernel_src).is_dir():
        log(f"Using provided kernel source at {cfg.kernel_src}")
        src_dir = Path(cfg.kernel_src)
    else:
        src_dir = download_kernel(cfg.kernel_version, build_dir)

    configure_kernel(cfg, src_dir)
    built_kver = build_kernel(cfg, src_dir)
    install_kernel(cfg, src_dir, built_kver)

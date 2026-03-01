"""CLI entry point — argparse subcommands mirroring build.sh interface."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from argparse import ArgumentParser
from pathlib import Path

from captain import artifacts, docker, kernel, qemu, tools
from captain.config import Config
from captain.log import err, log
from captain.util import check_kernel_dependencies, check_mkosi_dependencies, run


# ---------------------------------------------------------------------------
# Build helpers
# ---------------------------------------------------------------------------

def _build_kernel_stage(cfg: Config) -> None:
    """Run the kernel + tools build stage according to *cfg.kernel_mode*."""
    match cfg.kernel_mode:
        case "skip":
            log("KERNEL_MODE=skip — skipping kernel & tools")
            return
        case "native":
            missing = check_kernel_dependencies(cfg.arch)
            if missing:
                err(f"Missing kernel build tools: {', '.join(missing)}")
                err("Install them or set KERNEL_MODE=docker.")
                raise SystemExit(1)
            # Kernel
            modules_dir = cfg.kernel_output / "usr" / "lib" / "modules"
            if modules_dir.is_dir() and not cfg.force_kernel:
                log("Kernel already built (set FORCE_KERNEL=1 to rebuild)")
            else:
                log("Building kernel (native)...")
                kernel.build(cfg)
            # Tools
            log("Downloading tools (nerdctl, containerd, etc.)...")
            tools.download_all(cfg)
        case "docker":
            docker.build_builder(cfg)
            # Kernel
            modules_dir = cfg.kernel_output / "usr" / "lib" / "modules"
            if modules_dir.is_dir() and not cfg.force_kernel:
                log("Kernel already built (set FORCE_KERNEL=1 to rebuild)")
            else:
                log("Building kernel (docker)...")
                docker.run_in_builder(
                    cfg,
                    "--entrypoint",
                    "python3",
                    cfg.builder_image,
                    "/work/scripts/build-kernel.py",
                )
            # Tools
            log("Downloading tools (nerdctl, containerd, etc.)...")
            docker.run_in_builder(
                cfg,
                "--entrypoint",
                "python3",
                cfg.builder_image,
                "/work/scripts/download-tools.py",
            )
            # The Docker container runs as root, so files it creates inside
            # the bind-mounted mkosi.output/ are owned by root.  If the next
            # stage runs natively (MKOSI_MODE=native), mkosi won't be able to
            # write to that directory.  Fix ownership now.
            if cfg.mkosi_mode == "native":
                uid = os.getuid()
                gid = os.getgid()
                log("Fixing ownership of mkosi.output/ for native mkosi...")
                run(
                    [
                        "docker", "run", "--rm",
                        "-v", f"{cfg.project_dir}:/work",
                        "-w", "/work",
                        "debian:trixie",
                        "chown", "-R", f"{uid}:{gid}", "/work/mkosi.output",
                    ],
                )


def _build_mkosi_stage(cfg: Config, extra_args: list[str]) -> None:
    """Run the mkosi image-assembly stage according to *cfg.mkosi_mode*."""
    match cfg.mkosi_mode:
        case "skip":
            log("MKOSI_MODE=skip — skipping image assembly")
            return
        case "native":
            missing = check_mkosi_dependencies()
            if missing:
                err(f"Missing mkosi tools: {', '.join(missing)}")
                err("Install them or set MKOSI_MODE=docker.")
                raise SystemExit(1)
            log("Building initrd with mkosi (native)...")
            mkosi_args = list(cfg.mkosi_args) + list(extra_args)
            run(
                [
                    "mkosi",
                    f"--architecture={cfg.arch_info.mkosi_arch}",
                    "build",
                    *mkosi_args,
                ],
                cwd=cfg.project_dir,
            )
        case "docker":
            if cfg.kernel_mode != "docker":
                # Builder image may not have been built yet
                docker.build_builder(cfg)
            log("Building initrd with mkosi (docker)...")
            mkosi_args = list(cfg.mkosi_args) + list(extra_args)
            docker.run_mkosi(cfg, "build", *mkosi_args)


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def _cmd_build(cfg: Config, extra_args: list[str]) -> None:
    """Full build: kernel → tools → mkosi → artifacts."""
    _build_kernel_stage(cfg)
    _build_mkosi_stage(cfg, extra_args)
    artifacts.collect(cfg)
    log("Build complete!")


def _cmd_shell(cfg: Config, _extra_args: list[str]) -> None:
    """Interactive shell inside the builder container."""
    if not cfg.needs_docker:
        err("'shell' requires at least one stage using Docker.")
        err("Set KERNEL_MODE=docker or MKOSI_MODE=docker.")
        raise SystemExit(1)
    docker.build_builder(cfg)
    log("Entering builder shell (type 'exit' to leave)...")
    docker.run_in_builder(cfg, "-it", "--entrypoint", "/bin/bash", cfg.builder_image)


def _cmd_clean(cfg: Config, _extra_args: list[str]) -> None:
    """Remove all build artifacts."""
    log("Cleaning build artifacts...")
    mkosi_output = cfg.mkosi_output
    mkosi_cache = cfg.project_dir / "mkosi.cache"

    has_docker = shutil.which("docker") is not None
    if has_docker:
        # Use Docker to remove root-owned files from mkosi
        if mkosi_output.exists() or mkosi_cache.exists():
            run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "-v",
                    f"{cfg.project_dir}:/work",
                    "-w",
                    "/work",
                    "debian:trixie",
                    "sh",
                    "-c",
                    "rm -rf /work/mkosi.output/image* /work/mkosi.output/image.vmlinuz /work/mkosi.output/vmlinuz /work/mkosi.cache",
                ],
            )
    else:
        # No Docker available — remove directly (may need sudo for root-owned mkosi files)
        for pattern in ("image*", "image.vmlinuz", "vmlinuz"):
            for p in mkosi_output.glob(pattern):
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    p.unlink(missing_ok=True)
        if mkosi_cache.exists():
            shutil.rmtree(mkosi_cache, ignore_errors=True)

    if cfg.output_dir.exists():
        shutil.rmtree(cfg.output_dir)
    log("Clean complete.")


def _cmd_summary(cfg: Config, _extra_args: list[str]) -> None:
    """Print mkosi configuration summary."""
    match cfg.mkosi_mode:
        case "docker":
            docker.build_builder(cfg)
            docker.run_mkosi(cfg, "summary")
        case "native":
            run(
                ["mkosi", f"--architecture={cfg.arch_info.mkosi_arch}", "summary"],
                cwd=cfg.project_dir,
            )
        case "skip":
            err("Cannot show mkosi summary when MKOSI_MODE=skip.")
            raise SystemExit(1)


def _cmd_qemu_test(cfg: Config, _extra_args: list[str]) -> None:
    """Boot the image in QEMU for testing."""
    qemu.run_qemu(cfg)


def main(project_dir: Path | None = None) -> None:
    """Main CLI entry point."""
    # Require Python >= 3.10
    if sys.version_info < (3, 10):
        print("ERROR: Python >= 3.10 is required.", file=sys.stderr)
        sys.exit(1)

    env_help = """\

environment variables:
  ARCH            Target architecture: amd64 (default) or arm64
  KERNEL_MODE     Kernel build mode: docker (default), native, or skip
  MKOSI_MODE      mkosi build mode: docker (default), native, or skip
  KERNEL_SRC      Path to local kernel source tree
  KERNEL_VERSION  Kernel version to build (default: 6.12.69)
  FORCE_KERNEL    Set to 1 to force kernel rebuild
  FORCE_TOOLS     Set to 1 to re-download tools
  NO_CACHE        Set to 1 to rebuild builder image without cache
  BUILDER_IMAGE   Override builder Docker image name
  QEMU_APPEND     Extra kernel cmdline args for qemu-test
  QEMU_MEM        QEMU RAM size (default: 2G)
  QEMU_SMP        QEMU CPU count (default: 2)

examples:
  ./build.py                                  Build with defaults (all Docker)
  ARCH=arm64 ./build.py                       Build for ARM64
  KERNEL_SRC=~/linux ./build.py               Use local kernel source
  FORCE_KERNEL=1 ./build.py                   Force kernel rebuild
  KERNEL_MODE=skip MKOSI_MODE=native build.py Skip kernel, native mkosi
  KERNEL_MODE=native ./build.py               Native kernel, Docker mkosi
  ./build.py shell                            Debug inside builder
  ./build.py qemu-test                        Boot test with QEMU"""

    parser = ArgumentParser(
        prog="build.py",
        description="Build CaptainOS images using mkosi inside Docker.",
        epilog=env_help,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("build", help="Build the CaptainOS image (default)")
    sub.add_parser("shell", help="Interactive shell inside the builder container")
    sub.add_parser("clean", help="Remove all build artifacts")
    sub.add_parser("summary", help="Print mkosi configuration summary")
    sub.add_parser("qemu-test", help="Boot the image in QEMU for testing")

    # Parse known args — anything unknown is passed through to mkosi
    args, extra = parser.parse_known_args()

    # Handle --force as a global flag (passed through to mkosi)
    mkosi_args: list[str] = []
    remaining: list[str] = []
    for a in extra:
        if a == "--force":
            mkosi_args.append("--force")
        elif a == "--force-kernel":
            # Treat as env-var equivalent
            import os

            os.environ["FORCE_KERNEL"] = "1"
        else:
            remaining.append(a)

    # Determine project directory
    if project_dir is None:
        project_dir = Path(__file__).resolve().parent.parent

    cfg = Config.from_env(project_dir)
    cfg.mkosi_args = mkosi_args

    command = args.command or "build"

    dispatch = {
        "build": _cmd_build,
        "shell": _cmd_shell,
        "clean": _cmd_clean,
        "summary": _cmd_summary,
        "qemu-test": _cmd_qemu_test,
    }

    handler = dispatch.get(command)
    if handler is not None:
        handler(cfg, remaining)
    else:
        # Pass through to mkosi
        match cfg.mkosi_mode:
            case "docker":
                docker.build_builder(cfg)
                docker.run_mkosi(cfg, command, *remaining)
            case "native":
                run(
                    ["mkosi", f"--architecture={cfg.arch_info.mkosi_arch}", command, *remaining],
                    cwd=cfg.project_dir,
                )
            case "skip":
                err(f"Cannot pass '{command}' to mkosi when MKOSI_MODE=skip.")
                raise SystemExit(1)

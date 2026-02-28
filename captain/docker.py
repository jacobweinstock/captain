"""Docker builder image management and container execution."""

from __future__ import annotations

import json
import os
import platform
from datetime import datetime, timezone
from pathlib import Path

from captain.config import Config
from captain.log import err, log, warn
from captain.util import run


def _image_exists(image: str) -> bool:
    """Check if a Docker image exists locally."""
    result = run(
        ["docker", "image", "inspect", image],
        check=False,
        capture=True,
    )
    return result.returncode == 0


def _image_created_epoch(image: str) -> int:
    """Return the creation timestamp of a Docker image as a Unix epoch, or 0."""
    result = run(
        ["docker", "image", "inspect", image, "--format", "{{.Created}}"],
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        return 0
    try:
        # Docker returns RFC 3339 timestamps like "2024-01-15T10:30:00.123456789Z"
        created_str = result.stdout.strip()
        # Parse ISO format, handling nanosecond precision by truncating
        if "." in created_str:
            base, frac = created_str.split(".", 1)
            # Keep only up to 6 decimal places (microseconds)
            frac = frac.rstrip("Z")[:6]
            created_str = f"{base}.{frac}+00:00"
        elif created_str.endswith("Z"):
            created_str = created_str[:-1] + "+00:00"
        dt = datetime.fromisoformat(created_str)
        return int(dt.timestamp())
    except (ValueError, OSError):
        return 0


def build_builder(cfg: Config) -> None:
    """Build the Docker builder image if it doesn't exist or the Dockerfile is newer."""
    dockerfile = cfg.project_dir / "Dockerfile"
    needs_build = False

    if not _image_exists(cfg.builder_image):
        needs_build = True
    else:
        dockerfile_mtime = int(dockerfile.stat().st_mtime)
        image_epoch = _image_created_epoch(cfg.builder_image)
        if dockerfile_mtime > image_epoch:
            needs_build = True

    if not needs_build and not cfg.no_cache:
        log(f"Docker image '{cfg.builder_image}' is up to date.")
        return

    log(f"Building Docker image '{cfg.builder_image}'...")
    cmd = ["docker", "build"]
    if cfg.no_cache:
        cmd.append("--no-cache")
    cmd.extend(["-t", cfg.builder_image, str(cfg.project_dir)])
    run(cmd)


def run_in_builder(cfg: Config, *extra_args: str) -> None:
    """Run a command inside the Docker builder container.

    *extra_args* are appended after the docker run flags and image name.
    Typical usage::

        run_in_builder(cfg, "--entrypoint", "bash", cfg.builder_image, "/work/scripts/foo.sh")
    """
    docker_args: list[str] = [
        "docker",
        "run",
        "--rm",
        "--privileged",
        "-v",
        f"{cfg.project_dir}:/work",
        "-w",
        "/work",
        "-e",
        f"ARCH={cfg.arch}",
        "-e",
        f"KERNEL_VERSION={cfg.kernel_version}",
        "-e",
        f"FORCE_TOOLS={int(cfg.force_tools)}",
        "-e",
        f"FORCE_KERNEL={int(cfg.force_kernel)}",
    ]

    # Mount kernel source if provided
    if cfg.kernel_src is not None:
        kernel_src_path = Path(cfg.kernel_src).resolve()
        if not kernel_src_path.is_dir():
            err(f"KERNEL_SRC={cfg.kernel_src} does not exist")
            raise SystemExit(1)
        docker_args.extend(["-v", f"{kernel_src_path}:/work/kernel-src:ro"])
        docker_args.extend(["-e", "KERNEL_SRC=/work/kernel-src"])

    docker_args.extend(extra_args)
    run(docker_args)


def run_mkosi(cfg: Config, *mkosi_args: str) -> None:
    """Run mkosi inside the builder container."""
    ensure_binfmt(cfg)
    run_in_builder(
        cfg,
        cfg.builder_image,
        f"--architecture={cfg.arch_info.mkosi_arch}",
        *mkosi_args,
    )


def ensure_binfmt(cfg: Config) -> None:
    """Register binfmt_misc handlers if doing a cross-architecture build."""
    host_arch = platform.machine()  # e.g. "x86_64" or "aarch64"
    need_binfmt = False

    match (host_arch, cfg.arch):
        case ("x86_64", "arm64" | "aarch64"):
            need_binfmt = True
        case ("aarch64", "amd64" | "x86_64"):
            need_binfmt = True

    if not need_binfmt:
        return

    log(f"Registering binfmt_misc handlers for cross-architecture build ({host_arch} -> {cfg.arch})...")
    result = run(
        [
            "docker",
            "run",
            "--rm",
            "--privileged",
            "tonistiigi/binfmt",
            "--install",
            "all",
        ],
        check=False,
        capture=True,
    )
    if result.returncode != 0:
        warn("Could not auto-register binfmt handlers.")
        warn("Run manually: docker run --privileged --rm tonistiigi/binfmt --install all")

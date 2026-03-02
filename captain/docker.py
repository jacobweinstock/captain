"""Docker builder image management and container execution."""

from __future__ import annotations

import hashlib
import os
import platform
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


def _dockerfile_hash(cfg: Config) -> str:
    """Return the SHA-256 hex digest of the Dockerfile content.

    This is used as an image tag so that Dockerfile changes are detected
    automatically.  The value intentionally matches what GitHub Actions
    ``hashFiles('Dockerfile')`` produces, allowing the CI
    ``docker/build-push-action`` step to pre-load an image with the same
    tag that ``build_builder`` will look for.
    """
    dockerfile = cfg.project_dir / "Dockerfile"
    return hashlib.sha256(dockerfile.read_bytes()).hexdigest()


def build_builder(cfg: Config) -> None:
    """Build the Docker builder image when the Dockerfile has changed.

    The image is tagged with a content hash of the Dockerfile so that
    changes are detected even when the base image name stays the same.
    When the matching tag already exists locally (e.g. pre-loaded by a CI
    ``docker/build-push-action`` step with ``load: true``), we skip the
    build entirely.  Use ``NO_CACHE=1`` to force a full rebuild.
    """
    tag = _dockerfile_hash(cfg)
    tagged_image = f"{cfg.builder_image}:{tag}"

    if not cfg.no_cache and _image_exists(tagged_image):
        log(f"Docker image '{cfg.builder_image}' is up to date.")
        return

    log(f"Building Docker image '{cfg.builder_image}'...")
    cmd = ["docker", "build"]
    if cfg.no_cache:
        cmd.append("--no-cache")
    cmd.extend(["-t", tagged_image, "-t", cfg.builder_image, str(cfg.project_dir)])
    run(cmd)


def run_in_builder(cfg: Config, *extra_args: str) -> None:
    """Run a command inside the Docker builder container.

    *extra_args* are appended after the docker run flags and image name.
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

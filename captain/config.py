"""Build configuration populated from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from captain.util import ArchInfo, get_arch_info


@dataclass(slots=True)
class Config:
    """All build configuration, loaded once from environment variables."""

    # Paths
    project_dir: Path
    output_dir: Path

    # Target
    arch: str = "amd64"
    kernel_version: str = "6.12.69"
    kernel_src: str | None = None

    # Docker
    builder_image: str = "captainos-builder"
    no_cache: bool = False

    # Force flags
    force_kernel: bool = False
    force_tools: bool = False

    # QEMU
    qemu_append: str = ""
    qemu_mem: str = "2G"
    qemu_smp: str = "2"

    # mkosi passthrough
    mkosi_args: list[str] = field(default_factory=list)

    # Derived (set in __post_init__)
    arch_info: ArchInfo = field(init=False)

    def __post_init__(self) -> None:
        self.arch_info = get_arch_info(self.arch)

    @classmethod
    def from_env(cls, project_dir: Path) -> Config:
        """Create a Config from environment variables, matching build.sh defaults."""
        return cls(
            project_dir=project_dir,
            output_dir=project_dir / "out",
            arch=os.environ.get("ARCH", "amd64"),
            kernel_version=os.environ.get("KERNEL_VERSION", "6.12.69"),
            kernel_src=os.environ.get("KERNEL_SRC") or None,
            builder_image=os.environ.get("BUILDER_IMAGE", "captainos-builder"),
            no_cache=os.environ.get("NO_CACHE") == "1",
            force_kernel=os.environ.get("FORCE_KERNEL") == "1",
            force_tools=os.environ.get("FORCE_TOOLS") == "1",
            qemu_append=os.environ.get("QEMU_APPEND", ""),
            qemu_mem=os.environ.get("QEMU_MEM", "2G"),
            qemu_smp=os.environ.get("QEMU_SMP", "2"),
        )

    @property
    def kernel_output(self) -> Path:
        return self.project_dir / "mkosi.output" / "kernel"

    @property
    def mkosi_output(self) -> Path:
        return self.project_dir / "mkosi.output"

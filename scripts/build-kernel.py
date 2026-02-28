#!/usr/bin/env python3
"""Build the Linux kernel — runs inside the Docker builder container.

This is the in-container entry point that replaces scripts/build-kernel.sh.
It reuses the captain.kernel module for the actual logic.
"""

import sys
from pathlib import Path

# The project is mounted at /work inside the container
sys.path.insert(0, "/work")

from captain.config import Config
from captain.kernel import build

cfg = Config.from_env(Path("/work"))
build(cfg)

#!/usr/bin/env python3
"""Build the Linux kernel — in-container entry point.

Runs inside the Docker builder container.  Delegates to captain.kernel.build().
"""

import sys
from pathlib import Path

# The project is mounted at /work inside the container
sys.path.insert(0, "/work")

from captain.config import Config
from captain.kernel import build

cfg = Config.from_env(Path("/work"))
build(cfg)

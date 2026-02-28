#!/usr/bin/env python3
"""Download binary tools — runs inside the Docker builder container.

This is the in-container entry point that replaces scripts/download-tools.sh.
It reuses the captain.tools module for the actual logic.
"""

import sys
from pathlib import Path

# The project is mounted at /work inside the container
sys.path.insert(0, "/work")

from captain.config import Config
from captain.tools import download_all

cfg = Config.from_env(Path("/work"))
download_all(cfg)

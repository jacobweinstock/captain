#!/usr/bin/env python3
"""Download binary tools — in-container entry point.

Runs inside the Docker builder container.  Delegates to captain.tools.download_all().
"""

import sys
from pathlib import Path

# The project is mounted at /work inside the container
sys.path.insert(0, "/work")

from captain.config import Config
from captain.tools import download_all

cfg = Config.from_env(Path("/work"))
download_all(cfg)

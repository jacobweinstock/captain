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


def main() -> int:
    """Entry point for downloading tools inside the container."""
    cfg = Config.from_env(Path("/work"))
    download_all(cfg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

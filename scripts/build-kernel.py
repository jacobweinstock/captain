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


def main() -> int:
    """Entry point for building the Linux kernel inside the container."""
    cfg = Config.from_env(Path("/work"))
    result = build(cfg)
    return 0 if result is None else result


if __name__ == "__main__":
    raise SystemExit(main())

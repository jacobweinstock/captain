#!/usr/bin/env python3
"""CaptainOS build system entry point.

Requires: Python >= 3.10, Docker (unless all stages use native or skip)
"""

import sys

if sys.version_info < (3, 10):
    print("ERROR: Python >= 3.10 is required.", file=sys.stderr)
    sys.exit(1)

from captain.cli import main

if __name__ == "__main__":
    main()

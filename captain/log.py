"""Colored logging helpers matching the original build.sh output style."""

import sys

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
NC = "\033[0m"


def log(*args: object) -> None:
    print(f"{GREEN}[captainos]{NC}", *args, flush=True)


def warn(*args: object) -> None:
    print(f"{YELLOW}[captainos]{NC}", *args, flush=True)


def err(*args: object) -> None:
    print(f"{RED}[captainos]{NC}", *args, file=sys.stderr, flush=True)

"""Colored logging helpers matching the original build.sh output style.

Use :func:`for_stage` to create a stage-scoped logger whose prefix
includes the stage name (e.g. ``[captainos-kernel]``).  The module-level
:func:`log`, :func:`warn`, and :func:`err` convenience functions use a
plain ``[captainos]`` prefix for cross-cutting messages.
"""

from __future__ import annotations

import sys

RED = "\033[0;31m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
NC = "\033[0m"


class StageLogger:
    """Logger that tags output with an optional stage name."""

    __slots__ = ("_prefix",)

    def __init__(self, stage: str = "") -> None:
        tag = f"captainos-{stage}" if stage else "captainos"
        self._prefix = f"[{tag}]"

    def log(self, *args: object) -> None:
        print(f"{GREEN}{self._prefix}{NC}", *args, flush=True)

    def warn(self, *args: object) -> None:
        print(f"{YELLOW}{self._prefix}{NC}", *args, flush=True)

    def err(self, *args: object) -> None:
        print(f"{RED}{self._prefix}{NC}", *args, file=sys.stderr, flush=True)


def for_stage(stage: str) -> StageLogger:
    """Return a :class:`StageLogger` whose prefix includes *stage*."""
    return StageLogger(stage)


# Module-level convenience functions (un-staged [captainos] prefix).
_default = StageLogger()

log = _default.log
warn = _default.warn
err = _default.err

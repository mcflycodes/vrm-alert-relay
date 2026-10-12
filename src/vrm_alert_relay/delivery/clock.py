"""Time sources: wall-clock time for records, monotonic time for in-process windows."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Protocol, runtime_checkable

__all__ = ["Clock", "SystemClock"]


@runtime_checkable
class Clock(Protocol):
    """Wall-clock time is stored; monotonic time decides windows and backoff in-process."""

    def wall(self) -> datetime: ...

    def monotonic(self) -> float: ...


class SystemClock:
    """The real clocks."""

    def wall(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()

"""The global send cap and the retry backoff policy."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    import random
    from collections.abc import Iterable
    from datetime import datetime

__all__ = ["DAY", "HOUR", "RateLimiter", "RetryPolicy"]

HOUR: Final = timedelta(hours=1)
DAY: Final = timedelta(days=1)


class RateLimiter:
    """A global cap over sliding one-hour and 24-hour windows.

    Every provider call (first attempts, retries, and summaries) consumes one
    slot. An attempt at time ``t`` occupies the windows ``(t, t + 1 h]`` and
    ``(t, t + 24 h]``, so no 60-minute or 24-hour interval ever holds more
    than the configured number of attempts, including across restarts when the
    attempts are reloaded from the store. Only the newest ``per_hour`` and
    ``per_day`` attempts are kept, which is all the decision needs.
    """

    def __init__(self, per_hour: int, per_day: int, attempts: Iterable[datetime] = ()) -> None:
        if per_hour < 1 or per_day < 1:
            raise ValueError("rate limits must be positive")  # noqa: TRY003  # per-check validation message
        self._per_hour = per_hour
        self._per_day = per_day
        ordered = sorted(attempts)
        self._hour: deque[datetime] = deque(ordered, maxlen=per_hour)
        self._day: deque[datetime] = deque(ordered, maxlen=per_day)

    def _expire(self, now: datetime) -> None:
        while self._hour and self._hour[0] <= now - HOUR:
            self._hour.popleft()
        while self._day and self._day[0] <= now - DAY:
            self._day.popleft()

    def available(self, now: datetime) -> bool:
        self._expire(now)
        return len(self._hour) < self._per_hour and len(self._day) < self._per_day

    def consume(self, now: datetime) -> None:
        self._hour.append(now)
        self._day.append(now)

    def counts(self, now: datetime) -> tuple[int, int]:
        """Attempts in the current one-hour and 24-hour windows."""
        self._expire(now)
        return len(self._hour), len(self._day)


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Bounded retries with exponential backoff and equal jitter."""

    max_retries: int = 3
    base_delay: timedelta = timedelta(seconds=30)
    max_delay: timedelta = timedelta(minutes=15)

    def __post_init__(self) -> None:
        if not 0 <= self.max_retries <= 10:  # noqa: PLR2004  # matches RateLimitsConfig.retries
            raise ValueError("max_retries must be between 0 and 10")  # noqa: TRY003  # per-check validation message
        if self.base_delay <= timedelta(0) or self.max_delay < self.base_delay:
            raise ValueError("delays must be positive and max_delay >= base_delay")  # noqa: TRY003  # per-check validation message

    @property
    def max_attempts(self) -> int:
        return 1 + self.max_retries

    def delay(self, attempt: int, rng: random.Random) -> timedelta:
        """Delay after the ``attempt``-th attempt (1-based): half fixed, half random."""
        exponent = min(max(attempt, 1) - 1, 30)
        ceiling = min(self.max_delay, self.base_delay * (1 << exponent))
        return ceiling / 2 + (ceiling / 2) * rng.random()

"""The global send cap and the retry backoff policy."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    import random
    from collections.abc import Iterable

    from vrm_alert_relay.state import AttemptKey

__all__ = ["DAY", "HOUR", "MAX_EXPIRED", "RateLimiter", "RetryPolicy"]

HOUR: Final = timedelta(hours=1)
DAY: Final = timedelta(days=1)
MAX_EXPIRED: Final = 10_000


class RateLimiter:
    """A cap over sliding one-hour and 24-hour windows of monotonic time.

    Each send at time ``t`` occupies the windows ``(t, t + 1 h]`` and
    ``(t, t + 24 h]``, so no 60-minute or 24-hour interval holds more than
    the configured number. Monotonic time cannot jump, so changing the wall
    clock never frees a slot. Keys that leave the 24-hour window are kept
    (bounded) for :meth:`take_expired`, so their stored evidence can be pruned.
    """

    def __init__(
        self,
        per_hour: int,
        per_day: int,
        restored: Iterable[tuple[float, AttemptKey]] = (),
    ) -> None:
        if per_hour < 1 or per_day < 1:
            raise ValueError("rate limits must be positive")  # noqa: TRY003  # per-check validation message
        self._per_hour = per_hour
        self._per_day = per_day
        ordered = sorted(restored)
        self._hour: deque[float] = deque(at for at, _ in ordered)
        self._day: deque[tuple[float, AttemptKey]] = deque(ordered)
        self._expired: deque[AttemptKey] = deque(maxlen=MAX_EXPIRED)

    def _expire(self, now: float) -> None:
        hour, day = HOUR.total_seconds(), DAY.total_seconds()
        while self._hour and self._hour[0] <= now - hour:
            self._hour.popleft()
        while self._day and self._day[0][0] <= now - day:
            self._expired.append(self._day.popleft()[1])

    def available(self, now: float) -> bool:
        self._expire(now)
        return len(self._hour) < self._per_hour and len(self._day) < self._per_day

    def consume(self, key: AttemptKey, now: float) -> None:
        self._hour.append(now)
        self._day.append((now, key))

    def counts(self, now: float) -> tuple[int, int]:
        """Sends in the current one-hour and 24-hour windows."""
        self._expire(now)
        return len(self._hour), len(self._day)

    def take_expired(self) -> list[AttemptKey]:
        expired = list(self._expired)
        self._expired.clear()
        return expired


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

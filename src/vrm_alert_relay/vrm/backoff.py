"""Pure backoff policy and per-installation retry state for VRM polling.

Nothing here sleeps or reads a clock: callers pass monotonic ``now`` values in
seconds and the tracker answers when each installation may next be fetched.

- Transient failures (5xx, timeouts, connection failures, bad responses) back
  off exponentially from ``base_delay``, capped at ``max_delay``, with up to
  ``jitter`` of each delay removed at random so restarts do not synchronise.
- 429 applies to the whole token: every installation waits until the
  ``Retry-After`` delay (bounded by ``max_retry_after``) has passed, or, with
  no ``Retry-After``, at least ``rate_limit_delay`` or the exponential delay,
  whichever is longer.
- Non-transient failures (401, 403, other 4xx) are not retried as transient:
  they wait a fixed ``non_transient_delay`` that does not grow, so a revoked
  token is retried rarely and the failure stays visible.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from vrm_alert_relay.vrm.errors import VrmError, VrmRateLimitedError

if TYPE_CHECKING:
    from collections.abc import Callable

_MAX_EXPONENT: Final = 32


@dataclass(frozen=True, slots=True)
class BackoffPolicy:
    """Delays in seconds. All must be positive and finite; ``jitter`` in [0, 1)."""

    base_delay: float = 30.0
    max_delay: float = 900.0
    jitter: float = 0.2
    rate_limit_delay: float = 60.0
    max_retry_after: float = 3600.0
    non_transient_delay: float = 3600.0

    def __post_init__(self) -> None:
        for name in (
            "base_delay",
            "max_delay",
            "rate_limit_delay",
            "max_retry_after",
            "non_transient_delay",
        ):
            if not _positive(getattr(self, name)):
                raise ValueError(f"{name} must be a positive finite number")  # noqa: TRY003  # message is specific to this check
        if self.max_delay < self.base_delay:
            raise ValueError("max_delay must not be less than base_delay")  # noqa: TRY003  # message is specific to this check
        if (
            isinstance(self.jitter, bool)
            or not isinstance(self.jitter, int | float)
            or not 0 <= self.jitter < 1
        ):
            raise ValueError("jitter must be at least 0 and less than 1")  # noqa: TRY003  # message is specific to this check

    def transient_delay(self, failures: int, unit: float) -> float:
        """Delay after ``failures`` consecutive failures; ``unit`` is a draw in [0, 1)."""
        exponent = min(max(failures, 1) - 1, _MAX_EXPONENT)
        delay = min(self.base_delay * 2.0**exponent, self.max_delay)
        return delay * (1.0 - self.jitter * _unit(unit))

    def delay_for(self, error: VrmError, failures: int, unit: float) -> float:
        """Delay before the next attempt after ``error``."""
        if isinstance(error, VrmRateLimitedError):
            if error.retry_after is None:
                return max(self.rate_limit_delay, self.transient_delay(failures, unit))
            return min(max(error.retry_after, 0.0), self.max_retry_after)
        if error.transient:
            return self.transient_delay(failures, unit)
        return self.non_transient_delay


@dataclass(frozen=True, slots=True)
class BackoffState:
    """Retry state of one installation. ``next_attempt_at`` is a monotonic time."""

    failures: int = 0
    next_attempt_at: float | None = None
    last_error: VrmError | None = None


_CLEAR = BackoffState()


class Backoff:
    """Per-installation retry state plus the token-wide rate-limit gate."""

    __slots__ = ("_policy", "_rate_limit", "_rng", "_states")

    def __init__(
        self, policy: BackoffPolicy | None = None, *, rng: Callable[[], float] | None = None
    ) -> None:
        self._policy = policy if policy is not None else BackoffPolicy()
        self._rng = rng if rng is not None else random.SystemRandom().random
        self._states: dict[str, BackoffState] = {}
        self._rate_limit: tuple[float, VrmRateLimitedError] | None = None

    @property
    def policy(self) -> BackoffPolicy:
        return self._policy

    @property
    def rate_limited_until(self) -> float | None:
        """When the last 429's delay ends, or ``None`` if none is recorded."""
        return None if self._rate_limit is None else self._rate_limit[0]

    def state(self, installation: str) -> BackoffState:
        return self._states.get(installation, _CLEAR)

    def retry_at(self, installation: str) -> float | None:
        """Earliest time ``installation`` may be fetched, or ``None`` if any time."""
        times = [self.state(installation).next_attempt_at, self.rate_limited_until]
        pending = [t for t in times if t is not None]
        return max(pending) if pending else None

    def blocking_error(self, installation: str, now: float) -> VrmError | None:
        """The failure that defers ``installation`` at ``now``, or ``None`` if it may run."""
        if self._rate_limit is not None and now < self._rate_limit[0]:
            return self._rate_limit[1]
        state = self.state(installation)
        if state.next_attempt_at is not None and now < state.next_attempt_at:
            return state.last_error
        return None

    def record_success(self, installation: str) -> None:
        """Clear ``installation``'s state; a success also ends any rate-limit gate."""
        self._states.pop(installation, None)
        self._rate_limit = None

    def record_failure(self, installation: str, error: VrmError, now: float) -> float:
        """Record ``error`` at ``now`` and return when ``installation`` may retry."""
        failures = self.state(installation).failures + 1
        delay = self._policy.delay_for(error, failures, self._rng())
        until = now + delay
        self._states[installation] = BackoffState(failures, until, error)
        if isinstance(error, VrmRateLimitedError):
            self._rate_limit = (until, error)
        if self._rate_limit is not None:
            until = max(until, self._rate_limit[0])
        return until


def _positive(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, int | float)
        and math.isfinite(value)
        and value > 0
    )


def _unit(value: float) -> float:
    if not math.isfinite(value):
        return 0.0
    return min(max(value, 0.0), 1.0)

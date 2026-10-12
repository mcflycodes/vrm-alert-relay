"""The main loop: run a cycle, wait a jittered interval, repeat until stopped.

The wait between cycle starts is the configured poll interval plus up to
:data:`JITTER` of it at random, so it is never shorter than the interval
(and so never below the 30-second minimum) and restarts do not line up.
VRM backoff is per site and enforced by the adapter: while a site is backing
off, a cycle skips its request but still evaluates staleness, monitoring and
pending deliveries. A cycle that raises is logged and the loop carries on.

The stop signal is checked between cycles and wakes the wait at once, so a
shutdown finishes the cycle in progress (its HTTP calls are bounded by
timeouts) and then returns.
"""

from __future__ import annotations

import logging
import random
import time
from typing import TYPE_CHECKING, Final, Protocol

if TYPE_CHECKING:
    from collections.abc import Callable

__all__ = ["JITTER", "Scheduler", "Stopper"]

logger = logging.getLogger(__name__)

JITTER: Final = 0.1


class Stopper(Protocol):
    """The subset of :class:`threading.Event` the loop uses."""

    def is_set(self) -> bool: ...

    def wait(self, timeout: float | None = None) -> bool: ...


class Scheduler:
    """Calls ``cycle`` every jittered ``interval`` seconds until ``stop`` is set."""

    def __init__(  # noqa: PLR0913  # keyword-only collaborators, injectable for tests
        self,
        cycle: Callable[[], object],
        *,
        interval: float,
        stop: Stopper,
        clock: Callable[[], float] = time.monotonic,
        rng: Callable[[], float] | None = None,
        after_cycle: Callable[[], object] | None = None,
    ) -> None:
        if interval <= 0:
            raise ValueError("interval must be positive")  # noqa: TRY003  # per-check validation message
        self._cycle = cycle
        self._interval = interval
        self._stop = stop
        self._clock = clock
        self._rng = rng if rng is not None else random.SystemRandom().random
        self._after_cycle = after_cycle

    def next_delay(self) -> float:
        """Seconds from one cycle's start to the next: the interval plus jitter."""
        unit = min(max(self._rng(), 0.0), 1.0)
        return self._interval * (1.0 + JITTER * unit)

    def run(self, *, max_cycles: int | None = None) -> int:
        """Run until stopped, or ``max_cycles`` cycles; returns the cycles run."""
        cycles = 0
        while not self._stop.is_set():
            started = self._clock()
            self._run_one()
            cycles += 1
            if max_cycles is not None and cycles >= max_cycles:
                break
            wait = max(0.0, started + self.next_delay() - self._clock())
            if self._stop.wait(wait):
                break
        return cycles

    def _run_one(self) -> None:
        try:
            self._cycle()
        except Exception:
            logger.exception(
                "poll cycle failed; continuing with the next cycle",
                extra={"event": "relay.cycle_error"},
            )
        if self._after_cycle is not None:
            try:
                self._after_cycle()
            except Exception:
                logger.exception(
                    "post-cycle update failed", extra={"event": "relay.after_cycle_error"}
                )

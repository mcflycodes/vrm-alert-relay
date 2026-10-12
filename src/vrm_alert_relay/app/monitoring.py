"""Monitoring degraded and restored notifications (R10, R18).

Each configured installation has a monitor: a one-level rising rule that the
pure rules engine evaluates once per cycle, with the sample 1 while the
installation counts as degraded and 0 otherwise. Its rule state is stored by
the delivery engine like any rule's, under the key ``monitoring:<id>`` (a
colon never appears in a configured rule id). The engine therefore supplies
the guarantees: one escalation ("monitoring degraded") per outage, one
recovery ("monitoring restored") when it ends, stable event identities so a
restart mid-outage neither resends nor forgets, and a cooldown that bounds a
flapping connection.

The failure streak (how many consecutive polls failed, and when the first of
them did) is stored too, under ``monitoring-streak:<id>``, so a restart
between failed polls neither loses the outage nor its start time. It is kept
in a :class:`~vrm_alert_relay.engine.RuleState` record that the engine never
evaluates: ``newest_value`` holds the count (bounded by :data:`MAX_STREAK`)
and ``newest_sample_time`` the time of the first failure. A streak record
that cannot be read while the monitor itself has state counts as one failure
already seen, so the next failed poll reports the outage (failures favour
alerting).

**What counts as a failed poll** (failures favour alerting, ADR 0002): any
failure to fetch the installation's Diagnostics (authentication, rate
limiting, unavailability, a bad or rejected response), including cycles in
which the adapter skips the request because the installation is still backing
off, and any configured measurement that produced no usable sample
(missing, ambiguous, non-numeric, or with an unusable timestamp).

**When it is degraded:** after :data:`DEGRADED_AFTER_CYCLES` consecutive
failed polls, so one blip does not page anyone; at once for an
authentication failure or a rejected request, which do not heal by
themselves; and, while a stored outage is still open (for example after a
restart), on every failed poll. The first fully successful poll restores it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Final

from vrm_alert_relay.delivery import Notification, SystemTarget
from vrm_alert_relay.engine import (
    Direction,
    EventKind,
    LevelSpec,
    RuleSpec,
    RuleState,
    Sample,
    evaluate,
)
from vrm_alert_relay.templates import NotificationKind, TemplateFields, render_notification
from vrm_alert_relay.vrm import FailureKind

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from datetime import datetime

    from vrm_alert_relay.vrm import InstallationOutcome

__all__ = [
    "DEGRADED_AFTER_CYCLES",
    "MAX_STREAK",
    "MONITOR_COOLDOWN",
    "MONITOR_PREFIX",
    "STREAK_PREFIX",
    "MonitorCycle",
    "MonitoringTracker",
    "PollHealth",
    "Streak",
    "assess",
    "monitor_id",
    "monitor_spec",
    "streak_id",
]

logger = logging.getLogger(__name__)

MONITOR_PREFIX: Final = "monitoring:"
STREAK_PREFIX: Final = "monitoring-streak:"
MAX_STREAK: Final = 1_000_000
DEGRADED_LEVEL: Final = "degraded"
DEGRADED_AFTER_CYCLES: Final = 2
MONITOR_COOLDOWN: Final = timedelta(minutes=15)
"""A new outage within this time of the last "degraded" waits until it ends."""
_IMMEDIATE_KINDS: Final = frozenset({FailureKind.AUTH, FailureKind.REJECTED})
# A monitor's sample is always the cycle's own time, so it is never stale;
# the bound only has to be valid.
_NEVER_STALE: Final = timedelta(days=7)


def monitor_id(installation: str) -> str:
    return f"{MONITOR_PREFIX}{installation}"


def streak_id(installation: str) -> str:
    return f"{STREAK_PREFIX}{installation}"


def monitor_spec(installation: str) -> RuleSpec:
    return RuleSpec(
        rule_id=monitor_id(installation),
        direction=Direction.RISING,
        levels=(LevelSpec(DEGRADED_LEVEL, 1.0),),
        recovery_notify=True,
        cooldown=MONITOR_COOLDOWN,
        reminder_max=0,
        stale_after=_NEVER_STALE,
    )


@dataclass(frozen=True, slots=True)
class PollHealth:
    """How one installation's poll went in one cycle."""

    failed: bool
    immediate: bool = False
    """A failure that does not heal by itself: report it without waiting for a streak."""
    reason: str | None = None
    """A short, fixed description of the failure for logs."""


HEALTHY: Final = PollHealth(failed=False)


@dataclass(frozen=True, slots=True)
class Streak:
    """Consecutive failed polls of one installation, and when the first failed."""

    count: int = 0
    since: datetime | None = None

    def to_state(self) -> RuleState:
        return RuleState(newest_value=float(self.count), newest_sample_time=self.since)

    @classmethod
    def read(cls, stored: RuleState, monitor: RuleState, now: datetime) -> Streak:
        """Decode a stored streak; an unreadable one counts as one failure seen."""
        value = stored.newest_value
        if value is None and monitor.generation is None:
            return cls()  # Nothing stored yet: a fresh installation.
        if value is None or not value.is_integer() or not 0 <= value <= MAX_STREAK:
            logger.warning(
                "stored monitoring streak is unreadable; counting one failure as seen",
                extra={"event": "monitoring.streak_unreadable"},
            )
            return cls(1, now)
        count = int(value)
        if count == 0:
            return cls()
        since = stored.newest_sample_time
        return cls(count, since if since is not None and since <= now else now)

    def after(self, poll: PollHealth, now: datetime) -> Streak:
        if not poll.failed:
            return Streak()
        return Streak(min(self.count + 1, MAX_STREAK), self.since or now)


@dataclass(frozen=True, slots=True)
class MonitorCycle:
    """One cycle's monitor results, keyed by installation id."""

    states: dict[str, RuleState]
    streaks: dict[str, RuleState]
    notifications: list[Notification]


def assess(outcome: InstallationOutcome | None) -> PollHealth:
    """Classify an installation's outcome; ``None`` means the poll itself failed."""
    if outcome is None:
        return PollHealth(failed=True, reason="poll_error")
    if outcome.error is not None:
        kind = outcome.error.kind
        return PollHealth(failed=True, immediate=kind in _IMMEDIATE_KINDS, reason=kind.value)
    reading = outcome.reading
    problems = reading.problems if reading is not None else ()
    if problems:
        problem = problems[0].problem
        return PollHealth(failed=True, reason=f"measurement_{problem}")
    return HEALTHY


class MonitoringTracker:
    """Turns each cycle's poll health into monitor rule states and notifications.

    The open outage lives in the monitor's stored rule state and the failure
    streak in its stored streak record, so a restart keeps both.
    """

    def __init__(self, installations: Iterable[str]) -> None:
        self._specs = {name: monitor_spec(name) for name in installations}
        self._degraded: set[str] = set()
        self._failing: set[str] = set()

    @property
    def installations(self) -> tuple[str, ...]:
        return tuple(self._specs)

    @property
    def degraded(self) -> frozenset[str]:
        """Installations with an open outage, as of the last cycle."""
        return frozenset(self._degraded)

    @property
    def failing(self) -> frozenset[str]:
        """Installations whose last poll failed."""
        return frozenset(self._failing)

    def observe(
        self,
        health: Mapping[str, PollHealth],
        states: Mapping[str, RuleState],
        streaks: Mapping[str, RuleState],
        now: datetime,
    ) -> MonitorCycle:
        """Evaluate every monitor for this cycle.

        Every mapping is keyed by installation id. An installation missing
        from ``health`` counts as a failed poll; one missing from ``states``
        or ``streaks`` has nothing stored.
        """
        result = MonitorCycle(states={}, streaks={}, notifications=[])
        for name, spec in self._specs.items():
            poll = health.get(name, PollHealth(failed=True, reason="no_outcome"))
            state = states.get(name, RuleState())
            streak = Streak.read(streaks.get(name, RuleState()), state, now).after(poll, now)
            degraded = poll.failed and (
                poll.immediate
                or state.active_level is not None
                or streak.count >= DEGRADED_AFTER_CYCLES
            )
            new_state, events = evaluate(spec, state, Sample(1.0 if degraded else 0.0, now), now)
            result.states[name] = new_state
            result.streaks[name] = streak.to_state()
            self._track(self._failing, name, active=poll.failed)
            self._track(self._degraded, name, active=new_state.active_level is not None)
            for event in events:
                since = streak.since or now
                notification = self._notification(
                    name, event.kind, event.event_id, since=since, now=now, poll=poll
                )
                if notification is not None:
                    result.notifications.append(notification)
        return result

    @staticmethod
    def _track(names: set[str], name: str, *, active: bool) -> None:
        if active:
            names.add(name)
        else:
            names.discard(name)

    @staticmethod
    def _notification(  # noqa: PLR0913  # every field of the message is explicit
        name: str,
        kind: EventKind,
        event_id: str,
        *,
        since: datetime,
        now: datetime,
        poll: PollHealth,
    ) -> Notification | None:
        if kind is EventKind.ESCALATED:
            fields = TemplateFields(
                kind=NotificationKind.MONITORING_DEGRADED,
                installation=name,
                time=since,
            )
            logger.error(
                "monitoring is degraded",
                extra={
                    "event": "monitoring.degraded",
                    "installation": name,
                    "reason": poll.reason,
                },
            )
        elif kind is EventKind.RECOVERED:
            fields = TemplateFields(
                kind=NotificationKind.MONITORING_RESTORED, installation=name, time=now
            )
            logger.warning(
                "monitoring is restored",
                extra={"event": "monitoring.restored", "installation": name},
            )
        else:
            # A monitor has no reminders and is never stale; nothing else is sent.
            return None
        return Notification(
            event_id=event_id, text=render_notification(fields), target=SystemTarget()
        )

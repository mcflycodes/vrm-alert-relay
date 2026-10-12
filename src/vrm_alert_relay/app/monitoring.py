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
from vrm_alert_relay.engine import Direction, EventKind, LevelSpec, RuleSpec, Sample, evaluate
from vrm_alert_relay.templates import NotificationKind, TemplateFields, render_notification
from vrm_alert_relay.vrm import FailureKind

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping
    from datetime import datetime

    from vrm_alert_relay.engine import RuleState
    from vrm_alert_relay.vrm import InstallationOutcome

__all__ = [
    "DEGRADED_AFTER_CYCLES",
    "MONITOR_COOLDOWN",
    "MONITOR_PREFIX",
    "MonitoringTracker",
    "PollHealth",
    "assess",
    "monitor_id",
    "monitor_spec",
]

logger = logging.getLogger(__name__)

MONITOR_PREFIX: Final = "monitoring:"
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

    Failure streaks live in memory; the open outage itself lives in the
    monitor's stored rule state, so a restart keeps it.
    """

    def __init__(self, installations: Iterable[str]) -> None:
        self._specs = {name: monitor_spec(name) for name in installations}
        self._streaks: dict[str, int] = dict.fromkeys(self._specs, 0)
        self._since: dict[str, datetime] = {}
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
        now: datetime,
    ) -> tuple[dict[str, RuleState], list[Notification]]:
        """Evaluate every monitor for this cycle.

        ``health`` and ``states`` are keyed by installation id; an installation
        missing from ``health`` counts as a failed poll.
        """
        new_states: dict[str, RuleState] = {}
        notifications: list[Notification] = []
        for name, spec in self._specs.items():
            poll = health.get(name, PollHealth(failed=True, reason="no_outcome"))
            state = states[name]
            degraded = self._update_streak(
                name, poll, now, open_outage=state.active_level is not None
            )
            new_state, events = evaluate(spec, state, Sample(1.0 if degraded else 0.0, now), now)
            new_states[name] = new_state
            if new_state.active_level is not None:
                self._degraded.add(name)
            else:
                self._degraded.discard(name)
            for event in events:
                notification = self._notification(name, event.kind, event.event_id, now, poll)
                if notification is not None:
                    notifications.append(notification)
        return new_states, notifications

    def _update_streak(
        self, name: str, poll: PollHealth, now: datetime, *, open_outage: bool
    ) -> bool:
        if not poll.failed:
            self._streaks[name] = 0
            self._since.pop(name, None)
            self._failing.discard(name)
            return False
        self._streaks[name] += 1
        self._since.setdefault(name, now)
        self._failing.add(name)
        return poll.immediate or open_outage or self._streaks[name] >= DEGRADED_AFTER_CYCLES

    def _notification(
        self, name: str, kind: EventKind, event_id: str, now: datetime, poll: PollHealth
    ) -> Notification | None:
        if kind is EventKind.ESCALATED:
            fields = TemplateFields(
                kind=NotificationKind.MONITORING_DEGRADED,
                installation=name,
                time=self._since.get(name, now),
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

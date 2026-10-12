"""One poll cycle: poll, evaluate, render, hand over to delivery, deliver.

:meth:`Relay.run_cycle` never sleeps; the scheduler decides when it runs.
A rule that has never had a usable sample is not evaluated without one, and
an evaluation that still leaves it unobserved is discarded, so it reports
neither stale data nor its restoration: until its first sample, acquisition
problems are reported by the installation's monitor instead. Once a rule has
had a sample (``newest_sample_time`` in its stored state), it is evaluated
every cycle and stale data is reported as the rules engine defines it.

A failure in one stage is contained so the rest of the cycle still alerts:
an exception from the poll counts as a failed poll of every installation,
and an exception while evaluating or rendering one rule is retried with
fresh state or the default template rather than dropping the rule.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from vrm_alert_relay.delivery import Notification
from vrm_alert_relay.engine import RuleState, evaluate
from vrm_alert_relay.templates import fields_for_event, render_notification

from .monitoring import MonitoringTracker, PollHealth, assess, monitor_id, streak_id
from .rules import RuleBinding, bind_rules, poll_targets

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime

    from vrm_alert_relay.config import Installation, Measurement, RelayConfig
    from vrm_alert_relay.delivery import Clock, DeliveryEngine, RunReport
    from vrm_alert_relay.engine import Event
    from vrm_alert_relay.vrm import InstallationOutcome, PollResult

__all__ = ["CycleReport", "Poller", "Relay", "RelayStatus"]

logger = logging.getLogger(__name__)


class Poller(Protocol):
    """What the relay needs from the VRM adapter."""

    def poll(self, targets: Sequence[tuple[Installation, Sequence[Measurement]]]) -> PollResult: ...


@dataclass(frozen=True, slots=True)
class CycleReport:
    """What one cycle did."""

    at: datetime
    fetched: int
    failed: int
    events: int
    queued: int
    delivery: RunReport


@dataclass(frozen=True, slots=True)
class RelayStatus:
    """Monitoring status for the health endpoint. Holds no recipient data."""

    started_at: datetime
    cycles: int = 0
    last_cycle_at: datetime | None = None
    last_successful_poll_at: datetime | None = None
    """The last cycle in which every installation was fetched."""
    installations: int = 0
    failing: int = 0
    degraded: int = 0
    events_total: int = 0


@dataclass(slots=True)
class _CycleState:
    rule_states: dict[str, RuleState] = field(default_factory=dict)
    notifications: list[Notification] = field(default_factory=list)
    events: int = 0


class Relay:
    """Runs poll cycles for one configuration."""

    def __init__(
        self,
        config: RelayConfig,
        *,
        poller: Poller,
        delivery: DeliveryEngine,
        clock: Clock,
    ) -> None:
        self._poller = poller
        self._delivery = delivery
        self._clock = clock
        self._bindings = bind_rules(config)
        self._targets = poll_targets(config)
        self._monitoring = MonitoringTracker(inst.id for inst in config.vrm.installations)
        self._labels: dict[str, str] = {}
        self._status = RelayStatus(
            started_at=clock.wall(), installations=len(config.vrm.installations)
        )

    @property
    def status(self) -> RelayStatus:
        return self._status

    def run_cycle(self) -> CycleReport:
        outcomes = self._poll()
        now = self._clock.wall()
        cycle = _CycleState()
        for binding in self._bindings:
            self._evaluate_rule(binding, outcomes.get(binding.rule.installation), now, cycle)
        self._evaluate_monitors(outcomes, now, cycle)
        queued = self._delivery.accept_cycle(
            rule_states=cycle.rule_states, notifications=cycle.notifications
        )
        report = self._delivery.run_due()
        fetched = sum(1 for outcome in outcomes.values() if outcome is not None and outcome.ok)
        failed = len(self._targets) - fetched
        self._status = RelayStatus(
            started_at=self._status.started_at,
            cycles=self._status.cycles + 1,
            last_cycle_at=now,
            last_successful_poll_at=now if failed == 0 else self._status.last_successful_poll_at,
            installations=len(self._targets),
            failing=len(self._monitoring.failing),
            degraded=len(self._monitoring.degraded),
            events_total=self._status.events_total + cycle.events,
        )
        logger.info(
            "poll cycle finished",
            extra={
                "event": "relay.cycle",
                "fetched": fetched,
                "failed": failed,
                "events": cycle.events,
                "queued": queued,
                "sent": report.sent,
                "dry_run_sent": report.dry_run_sent,
                "suppressed": report.suppressed,
            },
        )
        return CycleReport(
            at=now,
            fetched=fetched,
            failed=failed,
            events=cycle.events,
            queued=queued,
            delivery=report,
        )

    def _poll(self) -> dict[str, InstallationOutcome | None]:
        """Every installation's outcome; ``None`` for all of them if the poll raised."""
        try:
            result = self._poller.poll(self._targets)
        except Exception:
            logger.exception(
                "the VRM poll failed unexpectedly; treating every installation as failed",
                extra={"event": "relay.poll_error"},
            )
            return dict.fromkeys((inst.id for inst, _ in self._targets), None)
        return {outcome.installation.id: outcome for outcome in result.outcomes}

    def _evaluate_rule(
        self,
        binding: RuleBinding,
        outcome: InstallationOutcome | None,
        now: datetime,
        cycle: _CycleState,
    ) -> None:
        rule_id = binding.rule.id
        reading = outcome.reading if outcome is not None else None
        result = reading.result_for(binding.rule.measurement) if reading is not None else None
        sample = result.sample if result is not None else None
        if result is not None and result.label is not None:
            self._labels[rule_id] = result.label
        state = self._delivery.rule_state(rule_id)
        observed = _observed(state)
        if sample is None and not observed:
            return
        try:
            new_state, events = evaluate(binding.spec, state, sample, now)
        except Exception:
            # Fresh state re-raises an active condition rather than dropping the rule.
            logger.exception(
                "rule evaluation failed; evaluating again from fresh state",
                extra={"event": "relay.evaluation_error", "rule_id": rule_id},
            )
            try:
                new_state, events = evaluate(binding.spec, RuleState(), sample, now)
            except Exception:
                logger.exception(
                    "rule evaluation failed again; skipping the rule this cycle",
                    extra={"event": "relay.evaluation_error", "rule_id": rule_id},
                )
                return
        if not observed and not _observed(new_state):
            return  # The sample was unusable; the rule is still unobserved.
        cycle.rule_states[rule_id] = new_state
        for event in events:
            text = self._render(binding, event)
            cycle.notifications.append(Notification.for_event(event, text))
            cycle.events += 1

    def _render(self, binding: RuleBinding, event: Event) -> str:
        label = self._labels.get(binding.rule.id)
        try:
            return binding.render(event, label)
        except Exception:
            logger.exception(
                "rendering a level message failed; sending the default text",
                extra={"event": "relay.render_error", "rule_id": binding.rule.id},
            )
            fields = fields_for_event(
                event,
                installation=binding.rule.installation,
                measurement=binding.rule.measurement.code,
                label=label,
            )
            return render_notification(fields)

    def _evaluate_monitors(
        self,
        outcomes: dict[str, InstallationOutcome | None],
        now: datetime,
        cycle: _CycleState,
    ) -> None:
        names = self._monitoring.installations
        health: dict[str, PollHealth] = {name: assess(outcomes.get(name)) for name in names}
        result = self._monitoring.observe(
            health,
            {name: self._delivery.rule_state(monitor_id(name)) for name in names},
            {name: self._delivery.rule_state(streak_id(name)) for name in names},
            now,
        )
        for name in names:
            cycle.rule_states[monitor_id(name)] = result.states[name]
            cycle.rule_states[streak_id(name)] = result.streaks[name]
        cycle.notifications.extend(result.notifications)
        cycle.events += len(result.notifications)


def _observed(state: RuleState) -> bool:
    """Whether a rule's state shows that it has had a usable sample."""
    return state.newest_sample_time is not None or state.last_evaluated_sample_time is not None

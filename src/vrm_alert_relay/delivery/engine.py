"""The delivery engine: identity, durable attempts, the global cap, retries, summaries.

Life of a delivery, one per (event_id, recipient):

* :meth:`DeliveryEngine.accept_cycle` resolves each notification's recipients
  from configuration, creates ``PENDING`` records for new pairs (pairs it has
  already seen are ignored), stores the cycle's rule states, and commits both
  in one transaction.
* :meth:`DeliveryEngine.run_due` processes due records. A real provider call
  needs a free slot in the global cap and an ``IN_FLIGHT`` record that is
  durable first, in SQLite or else in the fallback journal. Without either,
  nothing is sent (see "no durable accounting" below). The provider's result
  moves the record to ``DELIVERED``, ``FAILED``, back to ``PENDING`` with a
  backoff (a retryable failure), or ``AMBIGUOUS``.
* An ``AMBIGUOUS`` record, or an ``IN_FLIGHT`` one found at startup (a crash
  mid-send), is reconciled with the provider before any retry when the
  provider supports a lookup; otherwise, or when the lookup cannot tell, it is
  retried. A rare duplicate after a crash is accepted.
* When the cap has no free slot, a real delivery becomes ``SUPPRESSED`` and is
  counted. When no real alert is due and the cap allows, one aggregate
  "N alerts held back" summary goes to the system recipients, at most one per
  ``summary_interval``. The count is reduced only once a summary is delivered.

Only real provider calls use the cap. Dry-run sends go to the dry-run sink and
are counted against a separate "would send" cap that is only reported.

**No durable accounting.** If neither SQLite nor the journal can record an
attempt, the engine sends nothing except one "state storage unavailable"
notice per process, to one system recipient, and logs an error every run
until storage works again. Provider-side limits are the final backstop.

Windows and backoff use monotonic time. Wall-clock time is only stored; see
:meth:`DeliveryEngine.__init__` for how it is interpreted after a restart.
"""

from __future__ import annotations

import hashlib
import logging
import random
from collections import deque
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from vrm_alert_relay.config import DeliveryMode
from vrm_alert_relay.engine import RuleState
from vrm_alert_relay.state import (
    AttemptMark,
    Changes,
    DeliveryKind,
    DeliveryRecord,
    DeliveryStatus,
    JournalEntry,
    is_identifier,
)
from vrm_alert_relay.state.models import MAX_COUNTER, encode_time, is_message_id
from vrm_alert_relay.state.store import MAX_ATTEMPT_ROWS, MAX_RULE_STATES

from .limits import DAY, HOUR, MAX_EXPIRED, RateLimiter, RetryPolicy
from .protocol import (
    Message,
    Provider,
    ReconcileQuery,
    ReconcileStatus,
    ReconcilingProvider,
    SendResult,
    SendStatus,
    delivery_id,
    sanitize_text,
)
from .routing import Notification, Route, Routing, RuleTarget, UnknownTargetError

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from vrm_alert_relay.config import ProviderName, RateLimitsConfig, Recipient, RelayConfig
    from vrm_alert_relay.state import AttemptKey, Snapshot, StateStore

    from .clock import Clock

__all__ = [
    "STORAGE_NOTICE_TEXT",
    "DeliveryEngine",
    "DeliveryHealth",
    "DeliveryLimits",
    "RunReport",
]

logger = logging.getLogger(__name__)

type DeliveryKey = tuple[str, str]

DEFAULT_MAX_QUEUE: Final = 1000
STORAGE_NOTICE_TEXT: Final = (
    "VRM Alert Relay: state storage is unavailable, so alerting is degraded and "
    "further alerts are held until storage recovers. Check the relay."
)


@dataclass(frozen=True, slots=True)
class DeliveryLimits:
    """Bounds on the engine's working set."""

    max_queue: int = DEFAULT_MAX_QUEUE
    """Records awaiting work; more are held back and counted as suppressed."""
    max_records: int = 5000
    """Records kept in memory; the oldest finished records are dropped first."""
    summary_interval: timedelta = HOUR
    """Minimum time between two suppression summaries."""

    def __post_init__(self) -> None:
        if self.max_queue < 1 or self.max_records < self.max_queue:
            raise ValueError("limits need max_queue >= 1 and max_records >= max_queue")  # noqa: TRY003  # per-check validation message
        if self.summary_interval <= timedelta(0):
            raise ValueError("summary_interval must be positive")  # noqa: TRY003  # per-check validation message


@dataclass(slots=True)
class RunReport:
    """What one :meth:`DeliveryEngine.run_due` call did."""

    sent: int = 0
    """Real provider calls."""
    dry_run_sent: int = 0
    delivered: int = 0
    reconciled: int = 0
    retrying: int = 0
    ambiguous: int = 0
    failed: int = 0
    suppressed: int = 0
    held_for_storage: int = 0
    """Real sends not attempted because no attempt record could be made durable."""
    storage_notice_sent: bool = False


@dataclass(frozen=True, slots=True)
class DeliveryHealth:
    """Informational health data; contains no recipient data or secrets."""

    persistence_healthy: bool
    persistence_error: str | None
    durable_accounting: bool
    queued: int
    suppressed_pending: int
    suppressed_total: int
    sent_last_hour: int
    sent_last_day: int
    dry_run_sent_last_hour: int
    dry_run_sent_last_day: int
    dry_run_over_cap_total: int
    """Dry-run sends that the global cap would have held back."""


def _untrusted(value: object) -> object:
    """Widen a provider's return value so that it is validated, not trusted."""
    return value


def _summary_text(count: int, since: datetime) -> str:
    noun = "alert" if count == 1 else "alerts"
    stamp = since.astimezone(UTC).strftime("%Y-%m-%d %H:%M")
    return f"VRM Alert Relay: {count} {noun} held back by the global rate limit since {stamp} UTC."


def _seconds(delta: timedelta) -> float:
    return delta.total_seconds()


class DeliveryEngine:
    """Delivers notifications to configured recipients under the global cap."""

    def __init__(  # noqa: PLR0913  # keyword-only collaborators and settings
        self,
        *,
        routing: Routing,
        providers: Mapping[ProviderName, Provider],
        dry_run: Provider,
        store: StateStore,
        rate_limits: RateLimitsConfig,
        clock: Clock,
        rng: random.Random | None = None,
        retry_policy: RetryPolicy | None = None,
        limits: DeliveryLimits | None = None,
    ) -> None:
        """Load state, interpreting stored wall-clock times conservatively.

        Stored attempts become monotonic slots by their age; an attempt
        stamped later than now counts as happening now. A stored retry time
        further ahead than the maximum backoff is due immediately. The time
        since the last summary is restored the same way.

        Raises :class:`~vrm_alert_relay.state.StateLockedError` when another
        process uses the state directory.
        """
        frozen_providers: dict[str, Provider] = {str(k): v for k, v in providers.items()}
        for provider in (*frozen_providers.values(), dry_run):
            if not isinstance(provider, Provider):
                raise TypeError("providers must implement the Provider protocol")  # noqa: TRY003  # per-check validation message
        for route in routing.routes.values():
            if route.mode is DeliveryMode.LIVE and route.recipient.provider not in frozen_providers:
                raise ValueError(  # noqa: TRY003  # per-check validation message
                    f"no provider registered for live provider {route.recipient.provider!r}"
                )
        self._routing = routing
        self._providers: Mapping[str, Provider] = MappingProxyType(frozen_providers)
        self._dry_run = dry_run
        self._store = store
        self._clock = clock
        self._rng = rng if rng is not None else random.SystemRandom()
        self._retry = retry_policy or RetryPolicy(max_retries=rate_limits.retries)
        self._limits = limits or DeliveryLimits()

        self._records: dict[DeliveryKey, DeliveryRecord] = {}
        self._active: set[DeliveryKey] = set()
        self._due: dict[DeliveryKey, float] = {}
        self._dirty_records: set[DeliveryKey] = set()
        self._rule_states: dict[str, RuleState] = {}
        self._dirty_states: set[str] = set()
        self._new_attempts: deque[AttemptMark] = deque(maxlen=MAX_ATTEMPT_ROWS)
        self._expired: deque[AttemptKey] = deque(maxlen=MAX_EXPIRED)
        self._durable = True
        self._history_known = True
        self._unaccounted: dict[AttemptKey, tuple[float, bool]] = {}
        self._per_hour = rate_limits.global_per_hour
        self._per_day = rate_limits.global_per_day
        self._notice_sent = False
        self._suppressed_total = 0
        self._dry_run_over_cap = 0

        wall, mono = clock.wall(), clock.monotonic()
        self._restore(store.load(wall), wall, mono)

    def _restore(self, snapshot: Snapshot, wall: datetime, mono: float) -> None:
        self._rule_states.update(snapshot.rule_states)
        self._rebuild_limiters(snapshot.attempts, wall, mono)
        self._history_known = snapshot.attempts_complete
        if not self._history_known:
            logger.error(
                "the send-attempt history could not be read; real alerts are held until it can",
                extra={"event": "delivery.attempt_history_unknown"},
            )
        state = snapshot.suppression
        self._suppression = state
        self._last_summary_mono = (
            None
            if state.last_summary_at is None
            else mono - max(_seconds(wall - state.last_summary_at), 0.0)
        )
        recovered = 0
        for record in snapshot.deliveries:
            if record.status is DeliveryStatus.IN_FLIGHT:
                # The process stopped between recording the attempt and its
                # outcome: the message may or may not have been sent.
                self._put(
                    replace(record, status=DeliveryStatus.AMBIGUOUS, next_attempt_at=wall),
                    mono,
                )
                recovered += 1
                continue
            self._records[record.key] = record
            if not record.status.terminal:
                self._active.add(record.key)
                self._due[record.key] = self._restored_due(record, wall, mono)
        if recovered:
            logger.warning(
                "found deliveries interrupted mid-send; reconciling before any retry",
                extra={"event": "delivery.recovered_in_flight", "count": recovered},
            )
        self._prune_memory()
        if self._dirty_records:
            self.flush()

    def _rebuild_limiters(
        self, marks: tuple[AttemptMark, ...], wall: datetime, mono: float
    ) -> None:
        slots: dict[AttemptKey, tuple[float, bool]] = {}
        for mark in marks:
            age = max(_seconds(wall - mark.at), 0.0)
            if age < _seconds(DAY):
                slots[mark.key] = (mono - age, mark.live)
        slots.update(self._unaccounted)
        live = [(at, key) for key, (at, is_live) in slots.items() if is_live]
        shadow = [(at, key) for key, (at, is_live) in slots.items() if not is_live]
        self._live = RateLimiter(self._per_hour, self._per_day, live)
        self._shadow = RateLimiter(self._per_hour, self._per_day, shadow)

    def _reload_history(self) -> None:
        wall, mono = self._clock.wall(), self._clock.monotonic()
        marks = self._store.reload_attempts(wall)
        if marks is None:
            return
        self._rebuild_limiters(marks, wall, mono)
        self._history_known = True
        self._unaccounted.clear()
        logger.warning(
            "the send-attempt history is readable again",
            extra={"event": "delivery.attempt_history_restored"},
        )

    def _consume(self, mark: AttemptMark, mono: float) -> None:
        (self._live if mark.live else self._shadow).consume(mark.key, mono)
        if not self._history_known:
            self._unaccounted[mark.key] = (mono, mark.live)

    def _restored_due(self, record: DeliveryRecord, wall: datetime, mono: float) -> float:
        if record.next_attempt_at is None:
            return mono
        ahead = _seconds(record.next_attempt_at - wall)
        if ahead <= 0 or ahead > _seconds(self._retry.max_delay):
            return mono
        return mono + ahead

    @classmethod
    def from_config(  # noqa: PLR0913  # keyword-only collaborators and settings
        cls,
        config: RelayConfig,
        *,
        providers: Mapping[ProviderName, Provider],
        dry_run: Provider,
        store: StateStore,
        clock: Clock,
        rng: random.Random | None = None,
        limits: DeliveryLimits | None = None,
    ) -> DeliveryEngine:
        """Build an engine whose recipients and limits come only from ``config``."""
        return cls(
            routing=Routing.from_config(config),
            providers=providers,
            dry_run=dry_run,
            store=store,
            rate_limits=config.rate_limits,
            clock=clock,
            rng=rng,
            limits=limits,
        )

    # Rule state ---------------------------------------------------------

    def rule_state(self, rule_id: str) -> RuleState:
        """The last stored state for ``rule_id``, or fresh state."""
        return self._rule_states.get(rule_id, RuleState())

    # Intake ---------------------------------------------------------------

    def accept_cycle(
        self,
        *,
        rule_states: Mapping[str, RuleState],
        notifications: Iterable[Notification],
    ) -> int:
        """Record a poll cycle's new rule states and notifications atomically.

        Returns the number of deliveries queued. Deliveries already known for
        the same (event_id, recipient) are ignored.
        """
        wall, mono = self._clock.wall(), self._clock.monotonic()
        queued = 0
        held = 0
        for notification in notifications:
            routes = self._routes_for(notification)
            if not routes:
                continue
            text = sanitize_text(notification.text)
            target = notification.target
            rule_id = target.rule_id if isinstance(target, RuleTarget) else None
            for route in routes:
                key = (notification.event_id, route.name)
                if key in self._records:
                    continue
                if len(self._active) >= self._limits.max_queue:
                    status = DeliveryStatus.SUPPRESSED
                    self._count_suppressed(wall)
                    held += 1
                else:
                    status = DeliveryStatus.PENDING
                    queued += 1
                record = DeliveryRecord(
                    event_id=notification.event_id,
                    recipient=route.name,
                    rule_id=rule_id,
                    kind=DeliveryKind.EVENT,
                    status=status,
                    text=text,
                    attempts=0,
                    created_at=wall,
                    updated_at=wall,
                    next_attempt_at=None if status.terminal else wall,
                )
                self._put(record, mono)
                if len(self._records) > self._limits.max_records + self._limits.max_queue:
                    self._prune_memory()
        if held:
            logger.warning(
                "delivery queue is full; deliveries held back",
                extra={"event": "delivery.queue_full", "count": held},
            )
        for rule_id, state in rule_states.items():
            self._set_rule_state(rule_id, state)
        self._prune_memory()
        self.flush()
        return queued

    def _routes_for(self, notification: object) -> tuple[Route, ...]:
        if not isinstance(notification, Notification) or not is_identifier(notification.event_id):
            logger.error(
                "dropping a malformed notification",
                extra={"event": "delivery.notification_invalid"},
            )
            return ()
        text: object = notification.text
        if not isinstance(text, str):
            logger.error(
                "dropping a notification without text",
                extra={"event": "delivery.notification_invalid", "event_id": notification.event_id},
            )
            return ()
        try:
            return self._routing.resolve(notification.target)
        except UnknownTargetError:
            logger.error(  # noqa: TRY400  # an expected configuration mismatch, not a crash
                "dropping a notification for an unconfigured rule or recipient",
                extra={"event": "delivery.unknown_target", "event_id": notification.event_id},
            )
            return ()

    def _set_rule_state(self, rule_id: str, state: RuleState) -> None:
        if not is_identifier(rule_id) or not isinstance(state, RuleState):
            logger.error(
                "ignoring malformed rule state", extra={"event": "delivery.rule_state_invalid"}
            )
            return
        if rule_id not in self._rule_states and len(self._rule_states) >= MAX_RULE_STATES:
            logger.error(
                "too many rule states; not storing more",
                extra={"event": "delivery.rule_state_limit", "rule_id": rule_id},
            )
            return
        self._rule_states[rule_id] = state
        self._dirty_states.add(rule_id)

    # Delivery -------------------------------------------------------------

    def run_due(self) -> RunReport:
        """Process due deliveries: real alerts first, then any summary."""
        report = RunReport()
        if not self._history_known:
            self._reload_history()
        if not self._durable and self.flush():
            self._set_durable(durable=True)
        for record in self._due_records(DeliveryKind.EVENT):
            self._process(record, report)
        if not self._due_records(DeliveryKind.EVENT):
            self._maybe_open_summary()
            for record in self._due_records(DeliveryKind.SUMMARY):
                self._process(record, report)
        self._maybe_send_storage_notice(report)
        if report.suppressed:
            logger.warning(
                "global rate limit reached; deliveries held back",
                extra={"event": "delivery.suppressed", "count": report.suppressed},
            )
        if not (self._durable and self._history_known):
            logger.error(
                "state storage is unavailable; real alerts are held until it recovers",
                extra={"event": "delivery.no_durable_accounting", "held": report.held_for_storage},
            )
        self._prune_memory()
        self.flush()
        return report

    def _due_records(self, kind: DeliveryKind) -> list[DeliveryRecord]:
        mono = self._clock.monotonic()
        due = [
            self._records[key]
            for key in self._active
            if self._due.get(key, mono) <= mono and self._records[key].kind is kind
        ]
        return sorted(
            due, key=lambda record: (record.created_at, record.event_id, record.recipient)
        )

    def _process(  # noqa: C901  # one decision ladder per delivery
        self, record: DeliveryRecord, report: RunReport
    ) -> None:
        route = self._routing.route(record.recipient)
        if route is None:
            self._finish(record, DeliveryStatus.FAILED)
            report.failed += 1
            logger.error(
                "dropping a delivery to a recipient that is no longer configured",
                extra={"event": "delivery.recipient_removed", **self._log_ids(record)},
            )
            return
        provider = self._provider_for(route)
        live = route.mode is DeliveryMode.LIVE
        message = Message(delivery_id(record.event_id, record.recipient), record.text)
        if record.status is DeliveryStatus.AMBIGUOUS and self._reconciled(
            provider, record, route.recipient, message
        ):
            report.reconciled += 1
            return
        if record.attempts >= self._retry.max_attempts:
            self._finish(record, DeliveryStatus.FAILED)
            report.failed += 1
            logger.error(
                "giving up on a delivery after the maximum number of attempts",
                extra={
                    "event": "delivery.attempts_exhausted",
                    "outcome_unknown": record.status is DeliveryStatus.AMBIGUOUS,
                    **self._log_ids(record),
                },
            )
            return
        mono, wall = self._clock.monotonic(), self._clock.wall()
        if live and not self._history_known:
            # Without the stored history the cap cannot be enforced (ADR 0002).
            report.held_for_storage += 1
            return
        if live and not self._live.available(mono):
            self._finish(record, DeliveryStatus.SUPPRESSED)
            if record.kind is DeliveryKind.EVENT:
                self._count_suppressed(wall)
            report.suppressed += 1
            return
        in_flight = replace(
            record,
            status=DeliveryStatus.IN_FLIGHT,
            attempts=record.attempts + 1,
            last_attempt_at=wall,
            next_attempt_at=None,
            updated_at=wall,
        )
        mark = AttemptMark(record.event_id, record.recipient, in_flight.attempts, wall, live)
        self._put(in_flight, mono)
        self._new_attempts.append(mark)
        if live:
            if not self._make_durable(in_flight):
                self._new_attempts.pop()
                self._put(record, mono)
                report.held_for_storage += 1
                return
            self._consume(mark, mono)
            report.sent += 1
        else:
            if not self._shadow.available(mono):
                self._dry_run_over_cap = min(self._dry_run_over_cap + 1, MAX_COUNTER)
            self._consume(mark, mono)
            report.dry_run_sent += 1
        result = self._send(provider, message, route.recipient, record)
        outcome = self._apply(in_flight, result, report)
        if live:
            self._persist(outcome)

    def _persist(self, record: DeliveryRecord) -> None:
        """Best effort: SQLite, or else the journal, so a restart does not resend."""
        if not self.flush():
            self._store.journal((JournalEntry(record, attempt=False),))

    def _make_durable(self, in_flight: DeliveryRecord) -> bool:
        """Record the attempt in SQLite, or else in the journal (R15, ADR 0002)."""
        durable = self.flush() or self._store.journal((JournalEntry(in_flight, attempt=True),))
        self._set_durable(durable=durable)
        return durable

    def _set_durable(self, *, durable: bool) -> None:
        if durable and not self._durable:
            logger.warning(
                "send attempts can be recorded again",
                extra={"event": "delivery.durable_accounting_restored"},
            )
        elif not durable and self._durable:
            logger.error(
                "cannot record a send attempt durably; holding real alerts",
                extra={"event": "delivery.durable_accounting_lost"},
            )
        self._durable = durable

    def _maybe_send_storage_notice(self, report: RunReport) -> None:
        """While nothing can be recorded, send one notice per process, unaccounted."""
        if (self._durable and self._history_known) or self._notice_sent:
            return
        routes = self._routing.system_routes
        if not routes:
            return
        route = next((r for r in routes if r.mode is DeliveryMode.LIVE), routes[0])
        live = route.mode is DeliveryMode.LIVE
        mono, wall = self._clock.monotonic(), self._clock.wall()
        if live and not self._live.available(mono):
            return
        self._notice_sent = True
        event_id = f"storage_{int(wall.timestamp())}"
        mark = AttemptMark(event_id, route.name, 1, wall, live)
        self._consume(mark, mono)
        self._new_attempts.append(mark)
        record = DeliveryRecord(
            event_id=event_id,
            recipient=route.name,
            kind=DeliveryKind.SUMMARY,
            status=DeliveryStatus.IN_FLIGHT,
            text=STORAGE_NOTICE_TEXT,
            attempts=1,
            created_at=wall,
            updated_at=wall,
        )
        self._send(
            self._provider_for(route),
            Message(delivery_id(event_id, route.name), STORAGE_NOTICE_TEXT),
            route.recipient,
            record,
        )
        report.storage_notice_sent = True
        logger.error(
            "sent the one storage-unavailable notice for this process",
            extra={"event": "delivery.storage_notice", **self._log_ids(record)},
        )

    def _provider_for(self, route: Route) -> Provider:
        if route.mode is DeliveryMode.LIVE:
            return self._providers[route.recipient.provider]
        return self._dry_run

    def _reconciled(
        self,
        provider: Provider,
        record: DeliveryRecord,
        recipient: Recipient,
        message: Message,
    ) -> bool:
        """Ask the provider about an ambiguous attempt; True if it was delivered."""
        if not isinstance(provider, ReconcilingProvider):
            return False
        query = ReconcileQuery(
            message=message,
            recipient=recipient,
            provider_message_id=record.provider_message_id,
            attempted_at=record.last_attempt_at or record.created_at,
        )
        outcome: object
        try:
            outcome = _untrusted(provider.reconcile(query))
        except Exception:  # noqa: BLE001  # any provider failure means the outcome is unknown
            outcome = ReconcileStatus.UNKNOWN
        if not isinstance(outcome, ReconcileStatus):
            outcome = ReconcileStatus.UNKNOWN
        logger.info(
            "reconciled an ambiguous delivery",
            extra={
                "event": "delivery.reconciled",
                "outcome": outcome.value,
                **self._log_ids(record),
            },
        )
        if outcome is ReconcileStatus.DELIVERED:
            self._finish(record, DeliveryStatus.DELIVERED)
            self._persist(self._records[record.key])
            return True
        return False

    def _send(
        self, provider: Provider, message: Message, recipient: Recipient, record: DeliveryRecord
    ) -> SendResult:
        result: object
        try:
            result = _untrusted(provider.send(message, recipient))
        except Exception:  # noqa: BLE001  # the message may have gone out; treat as ambiguous
            logger.warning(
                "provider raised during send; treating the outcome as ambiguous",
                extra={"event": "delivery.provider_error", **self._log_ids(record)},
            )
            return SendResult(SendStatus.AMBIGUOUS)
        if not isinstance(result, SendResult) or not isinstance(result.status, SendStatus):
            logger.warning(
                "provider returned an invalid result; treating the outcome as ambiguous",
                extra={"event": "delivery.provider_invalid_result", **self._log_ids(record)},
            )
            return SendResult(SendStatus.AMBIGUOUS)
        return result

    def _apply(
        self, record: DeliveryRecord, result: SendResult, report: RunReport
    ) -> DeliveryRecord:
        mono, wall = self._clock.monotonic(), self._clock.wall()
        message_id = (
            result.provider_message_id
            if is_message_id(result.provider_message_id)
            else record.provider_message_id
        )
        ids = self._log_ids(record)
        delay: timedelta | None = None
        if result.status is SendStatus.DELIVERED:
            status = DeliveryStatus.DELIVERED
            report.delivered += 1
            logger.info("delivered", extra={"event": "delivery.delivered", **ids})
        elif result.status is SendStatus.AMBIGUOUS:
            status = DeliveryStatus.AMBIGUOUS
            delay = self._retry.delay(record.attempts, self._rng)
            report.ambiguous += 1
            logger.warning(
                "delivery outcome is unknown; will reconcile or retry",
                extra={"event": "delivery.ambiguous", **ids},
            )
        elif result.retryable is True and record.attempts < self._retry.max_attempts:
            status = DeliveryStatus.PENDING
            delay = self._retry.delay(record.attempts, self._rng)
            report.retrying += 1
            logger.warning(
                "delivery failed; will retry", extra={"event": "delivery.retrying", **ids}
            )
        else:
            status = DeliveryStatus.FAILED
            report.failed += 1
            logger.error("delivery failed", extra={"event": "delivery.failed", **ids})
        updated = replace(
            record,
            status=status,
            next_attempt_at=None if delay is None else wall + delay,
            provider_message_id=message_id,
            updated_at=wall,
        )
        self._put(updated, mono if delay is None else mono + _seconds(delay))
        return updated

    def _log_ids(self, record: DeliveryRecord) -> dict[str, str]:
        return {"event_id": record.event_id, "recipient": self._routing.display(record.recipient)}

    # Suppression and summaries --------------------------------------------

    def _count_suppressed(self, wall: datetime) -> None:
        state = self._suppression
        self._suppression = replace(
            state,
            count=min(state.count + 1, MAX_COUNTER),
            since=state.since or wall,
        )
        self._suppressed_total = min(self._suppressed_total + 1, MAX_COUNTER)

    def _maybe_open_summary(self) -> None:
        state = self._suppression
        if state.count <= 0 or state.summary_event_id is not None:
            return
        routes = self._routing.system_routes
        if not routes:
            return
        mono, wall = self._clock.monotonic(), self._clock.wall()
        last = self._last_summary_mono
        if last is not None and mono - last < _seconds(self._limits.summary_interval):
            return
        if any(route.mode is DeliveryMode.LIVE for route in routes) and not self._live.available(
            mono
        ):
            return
        digest = hashlib.sha256(f"{encode_time(wall)}|{mono!r}".encode()).hexdigest()
        event_id = f"sum_{digest[:32]}"
        text = _summary_text(state.count, state.since or wall)
        self._suppression = replace(
            state, summary_event_id=event_id, summary_count=state.count, last_summary_at=wall
        )
        self._last_summary_mono = mono
        for route in routes:
            self._put(
                DeliveryRecord(
                    event_id=event_id,
                    recipient=route.name,
                    kind=DeliveryKind.SUMMARY,
                    status=DeliveryStatus.PENDING,
                    text=text,
                    attempts=0,
                    created_at=wall,
                    updated_at=wall,
                    next_attempt_at=wall,
                ),
                mono,
            )
        logger.warning(
            "sending a summary of deliveries held back by the global rate limit",
            extra={"event": "delivery.summary", "count": state.count},
        )

    def _summary_progress(self, record: DeliveryRecord) -> None:
        """Settle the summary in progress as its deliveries finish."""
        state = self._suppression
        if record.event_id != state.summary_event_id:
            return
        if record.status is DeliveryStatus.DELIVERED and state.summary_count:
            remaining = max(state.count - state.summary_count, 0)
            state = replace(
                state,
                count=remaining,
                since=None if remaining == 0 else state.since,
                summary_count=0,
            )
        if not any(key[0] == record.event_id for key in self._active):
            # Every delivery of this summary has finished. If none was
            # delivered, the count stands and a later summary reports it.
            state = replace(state, summary_event_id=None, summary_count=0)
        self._suppression = state

    # Bookkeeping ------------------------------------------------------------

    def _put(self, record: DeliveryRecord, due: float) -> None:
        self._records[record.key] = record
        self._dirty_records.add(record.key)
        if record.status.terminal:
            self._active.discard(record.key)
            self._due.pop(record.key, None)
            if record.kind is DeliveryKind.SUMMARY:
                self._summary_progress(record)
        else:
            self._active.add(record.key)
            self._due[record.key] = due

    def _finish(self, record: DeliveryRecord, status: DeliveryStatus) -> None:
        self._put(
            replace(record, status=status, next_attempt_at=None, updated_at=self._clock.wall()),
            self._clock.monotonic(),
        )

    def _prune_memory(self) -> None:
        excess = len(self._records) - self._limits.max_records
        if excess <= 0:
            return
        finished = sorted(
            (record for record in self._records.values() if record.status.terminal),
            key=lambda record: (record.updated_at, record.event_id, record.recipient),
        )
        for record in finished[:excess]:
            del self._records[record.key]
            self._dirty_records.discard(record.key)

    def flush(self) -> bool:
        """Write unsaved changes; on failure they are kept and retried next time."""
        self._expired.extend(self._live.take_expired())
        self._expired.extend(self._shadow.take_expired())
        changes = Changes(
            rule_states=MappingProxyType(
                {rule_id: self._rule_states[rule_id] for rule_id in self._dirty_states}
            ),
            deliveries=tuple(
                self._records[key] for key in self._dirty_records if key in self._records
            ),
            attempts=tuple(self._new_attempts),
            expired_attempts=tuple(self._expired),
            suppression=self._suppression,
        )
        if not self._store.flush(changes, self._clock.wall()):
            return False
        self._dirty_states.clear()
        self._dirty_records.clear()
        self._new_attempts.clear()
        self._expired.clear()
        return True

    # Health -----------------------------------------------------------------

    def health(self) -> DeliveryHealth:
        mono = self._clock.monotonic()
        hour, day = self._live.counts(mono)
        dry_hour, dry_day = self._shadow.counts(mono)
        return DeliveryHealth(
            persistence_healthy=self._store.healthy,
            persistence_error=self._store.error,
            durable_accounting=self._durable and self._history_known,
            queued=len(self._active),
            suppressed_pending=self._suppression.count,
            suppressed_total=self._suppressed_total,
            sent_last_hour=hour,
            sent_last_day=day,
            dry_run_sent_last_hour=dry_hour,
            dry_run_sent_last_day=dry_day,
            dry_run_over_cap_total=self._dry_run_over_cap,
        )

    def record(self, event_id: str, recipient: str) -> DeliveryRecord | None:
        """The current record for one delivery, if it is still held in memory."""
        return self._records.get((event_id, recipient))

"""The delivery engine: identity, at-most-once intent, the global cap, and retries.

Life of a delivery, one per (event_id, recipient):

* :meth:`DeliveryEngine.accept_cycle` resolves each notification's recipients
  from configuration, creates ``PENDING`` records for new pairs (pairs it has
  already seen are ignored), stores the cycle's rule states, and commits both
  in one transaction.
* :meth:`DeliveryEngine.run_due` processes due records. Before each provider
  call it takes a slot from the global cap and commits the record as
  ``IN_FLIGHT``. The provider's result moves it to ``DELIVERED``, ``FAILED``,
  back to ``PENDING`` with a backoff (a retryable failure), or ``AMBIGUOUS``.
* An ``AMBIGUOUS`` record, or an ``IN_FLIGHT`` one found at startup (a crash
  mid-send), is reconciled with the provider before any retry when the
  provider supports a lookup; otherwise, or when the lookup cannot tell, it is
  retried. A rare duplicate after a crash is accepted.
* When the cap has no free slot, the record becomes ``SUPPRESSED`` and is
  counted. Once the window reopens, each affected recipient gets one
  "N alerts held back" summary, at most one summary per ``summary_interval``.

The in-memory working set is authoritative while the process runs and is
written through to the :class:`~vrm_alert_relay.state.StateStore`. If the
store fails, delivery continues with in-memory duplicate suppression and the
same cap, and the unsaved changes are written on the next successful flush.
"""

from __future__ import annotations

import hashlib
import logging
import random
from collections import deque
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from vrm_alert_relay.config import DeliveryMode
from vrm_alert_relay.engine import RuleState
from vrm_alert_relay.state import (
    MAX_PROVIDER_MESSAGE_ID_LENGTH,
    Changes,
    DeliveryKind,
    DeliveryRecord,
    DeliveryStatus,
    Suppression,
    is_identifier,
)
from vrm_alert_relay.state.models import MAX_COUNTER, encode_time
from vrm_alert_relay.state.store import MAX_ATTEMPT_ROWS, MAX_RULE_STATES

from .limits import HOUR, RateLimiter, RetryPolicy
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
from .routing import Notification, Route, Routing, UnknownTargetError

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from vrm_alert_relay.config import ProviderName, RateLimitsConfig, Recipient, RelayConfig
    from vrm_alert_relay.state import StateStore

__all__ = ["DeliveryEngine", "DeliveryHealth", "DeliveryLimits", "RunReport"]

logger = logging.getLogger(__name__)

type DeliveryKey = tuple[str, str]

DEFAULT_MAX_QUEUE: Final = 1000


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
    delivered: int = 0
    reconciled: int = 0
    retrying: int = 0
    ambiguous: int = 0
    failed: int = 0
    suppressed: int = 0


@dataclass(frozen=True, slots=True)
class DeliveryHealth:
    """Informational health data; contains no recipient data or secrets."""

    persistence_healthy: bool
    persistence_error: str | None
    queued: int
    suppressed_pending: int
    suppressed_total: int
    sent_last_hour: int
    sent_last_day: int


def _untrusted(value: object) -> object:
    """Widen a provider's return value so that it is validated, not trusted."""
    return value


def _bounded_message_id(value: object) -> str | None:
    if (
        isinstance(value, str)
        and 0 < len(value) <= MAX_PROVIDER_MESSAGE_ID_LENGTH
        and value.isprintable()
    ):
        return value
    return None


def _summary_text(count: int, since: datetime) -> str:
    noun = "alert" if count == 1 else "alerts"
    stamp = since.astimezone(UTC).strftime("%Y-%m-%d %H:%M")
    return f"VRM Alert Relay: {count} {noun} held back by the global rate limit since {stamp} UTC."


@dataclass(slots=True)
class _Suppressed:
    counts: dict[str, int] = field(default_factory=dict)
    since: datetime | None = None
    last_summary_at: datetime | None = None
    total_since_start: int = 0


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
        now: datetime,
        rng: random.Random | None = None,
        retry_policy: RetryPolicy | None = None,
        limits: DeliveryLimits | None = None,
    ) -> None:
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
        self._rng = rng if rng is not None else random.SystemRandom()
        self._retry = retry_policy or RetryPolicy(max_retries=rate_limits.retries)
        self._limits = limits or DeliveryLimits()

        self._records: dict[DeliveryKey, DeliveryRecord] = {}
        self._active: set[DeliveryKey] = set()
        self._dirty_records: set[DeliveryKey] = set()
        self._rule_states: dict[str, RuleState] = {}
        self._dirty_states: set[str] = set()
        self._new_attempts: deque[datetime] = deque(maxlen=MAX_ATTEMPT_ROWS)

        snapshot = store.load()
        self._rule_states.update(snapshot.rule_states)
        self._limiter = RateLimiter(
            rate_limits.global_per_hour, rate_limits.global_per_day, snapshot.attempts
        )
        self._suppressed = _Suppressed(
            counts=dict(snapshot.suppression.counts),
            since=snapshot.suppression.since,
            last_summary_at=snapshot.suppression.last_summary_at,
        )
        recovered = 0
        for record in snapshot.deliveries:
            if record.status is DeliveryStatus.IN_FLIGHT:
                # The process stopped between recording the attempt and its
                # outcome: the message may or may not have been sent.
                record = replace(  # noqa: PLW2901  # recovered copy replaces the loaded record
                    record, status=DeliveryStatus.AMBIGUOUS, next_attempt_at=now, updated_at=now
                )
                recovered += 1
                self._put(record)
            else:
                self._records[record.key] = record
                if not record.status.terminal:
                    self._active.add(record.key)
        if recovered:
            logger.warning(
                "found deliveries interrupted mid-send; reconciling before any retry",
                extra={"event": "delivery.recovered_in_flight", "count": recovered},
            )
        self._prune_memory()
        if self._dirty_records:
            self.flush(now)

    @classmethod
    def from_config(  # noqa: PLR0913  # keyword-only collaborators and settings
        cls,
        config: RelayConfig,
        *,
        providers: Mapping[ProviderName, Provider],
        dry_run: Provider,
        store: StateStore,
        now: datetime,
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
            now=now,
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
        now: datetime,
    ) -> int:
        """Record a poll cycle's new rule states and notifications atomically.

        Returns the number of deliveries queued. Deliveries already known for
        the same (event_id, recipient) are ignored.
        """
        queued = 0
        held = 0
        for notification in notifications:
            routes = self._routes_for(notification)
            text = sanitize_text(notification.text) if routes else ""
            for route in routes:
                key = (notification.event_id, route.name)
                if key in self._records:
                    continue
                if len(self._active) >= self._limits.max_queue:
                    status = DeliveryStatus.SUPPRESSED
                    self._count_suppressed(route.name, now)
                    held += 1
                else:
                    status = DeliveryStatus.PENDING
                    queued += 1
                self._put(
                    DeliveryRecord(
                        event_id=notification.event_id,
                        recipient=route.name,
                        kind=DeliveryKind.EVENT,
                        status=status,
                        text=text,
                        attempts=0,
                        created_at=now,
                        updated_at=now,
                        next_attempt_at=None if status.terminal else now,
                    )
                )
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
        self.flush(now)
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

    def run_due(self, now: datetime) -> RunReport:
        """Process every record that is due at ``now``; summaries go first."""
        report = RunReport()
        self._maybe_open_summary(now)
        due = sorted(
            (
                record
                for record in (self._records[key] for key in self._active)
                if record.next_attempt_at is None or record.next_attempt_at <= now
            ),
            key=lambda record: (
                record.kind is not DeliveryKind.SUMMARY,
                record.created_at,
                record.event_id,
                record.recipient,
            ),
        )
        for record in due:
            self._process(record, now, report)
        if report.suppressed:
            logger.warning(
                "global rate limit reached; deliveries held back",
                extra={"event": "delivery.suppressed", "count": report.suppressed},
            )
        self._prune_memory()
        self.flush(now)
        return report

    def _process(self, record: DeliveryRecord, now: datetime, report: RunReport) -> None:
        route = self._routing.route(record.recipient)
        if route is None:
            self._finish(record, DeliveryStatus.FAILED, now)
            report.failed += 1
            logger.error(
                "dropping a delivery to a recipient that is no longer configured",
                extra={"event": "delivery.recipient_removed", "recipient": record.recipient},
            )
            return
        provider = self._provider_for(route)
        message = Message(delivery_id(record.event_id, record.recipient), record.text)
        if record.status is DeliveryStatus.AMBIGUOUS and self._reconciled(
            provider, record, route.recipient, message, now
        ):
            report.reconciled += 1
            return
        if record.attempts >= self._retry.max_attempts:
            self._finish(record, DeliveryStatus.FAILED, now)
            report.failed += 1
            logger.error(
                "giving up on a delivery after the maximum number of attempts",
                extra={
                    "event": "delivery.attempts_exhausted",
                    "event_id": record.event_id,
                    "recipient": record.recipient,
                    "outcome_unknown": record.status is DeliveryStatus.AMBIGUOUS,
                },
            )
            return
        if not self._limiter.available(now):
            if record.kind is DeliveryKind.SUMMARY:
                return  # A summary waits for the window to reopen.
            self._finish(record, DeliveryStatus.SUPPRESSED, now)
            self._count_suppressed(record.recipient, now)
            report.suppressed += 1
            return
        self._limiter.consume(now)
        self._new_attempts.append(now)
        in_flight = replace(
            record,
            status=DeliveryStatus.IN_FLIGHT,
            attempts=record.attempts + 1,
            last_attempt_at=now,
            next_attempt_at=None,
            updated_at=now,
        )
        self._put(in_flight)
        # The attempt is durable before the provider is called (R15). If the
        # write fails, sending goes ahead anyway: fail toward alerting.
        self.flush(now)
        report.sent += 1
        result = self._send(provider, message, route.recipient, record)
        self._apply(in_flight, result, now, report)
        self.flush(now)

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
        now: datetime,
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
                "event_id": record.event_id,
                "recipient": record.recipient,
                "outcome": outcome.value,
            },
        )
        if outcome is ReconcileStatus.DELIVERED:
            self._finish(record, DeliveryStatus.DELIVERED, now)
            return True
        return False

    @staticmethod
    def _send(
        provider: Provider, message: Message, recipient: Recipient, record: DeliveryRecord
    ) -> SendResult:
        result: object
        try:
            result = _untrusted(provider.send(message, recipient))
        except Exception:  # noqa: BLE001  # the message may have gone out; treat as ambiguous
            logger.warning(
                "provider raised during send; treating the outcome as ambiguous",
                extra={
                    "event": "delivery.provider_error",
                    "event_id": record.event_id,
                    "recipient": record.recipient,
                },
            )
            return SendResult(SendStatus.AMBIGUOUS)
        if not isinstance(result, SendResult) or not isinstance(result.status, SendStatus):
            logger.warning(
                "provider returned an invalid result; treating the outcome as ambiguous",
                extra={
                    "event": "delivery.provider_invalid_result",
                    "event_id": record.event_id,
                    "recipient": record.recipient,
                },
            )
            return SendResult(SendStatus.AMBIGUOUS)
        return result

    def _apply(
        self, record: DeliveryRecord, result: SendResult, now: datetime, report: RunReport
    ) -> None:
        message_id = _bounded_message_id(result.provider_message_id) or record.provider_message_id
        extra = {"event_id": record.event_id, "recipient": record.recipient}
        if result.status is SendStatus.DELIVERED:
            status, next_at = DeliveryStatus.DELIVERED, None
            report.delivered += 1
            logger.info("delivered", extra={"event": "delivery.delivered", **extra})
        elif result.status is SendStatus.AMBIGUOUS:
            status = DeliveryStatus.AMBIGUOUS
            next_at = now + self._retry.delay(record.attempts, self._rng)
            report.ambiguous += 1
            logger.warning(
                "delivery outcome is unknown; will reconcile or retry",
                extra={"event": "delivery.ambiguous", **extra},
            )
        elif result.retryable is True and record.attempts < self._retry.max_attempts:
            status = DeliveryStatus.PENDING
            next_at = now + self._retry.delay(record.attempts, self._rng)
            report.retrying += 1
            logger.warning(
                "delivery failed; will retry", extra={"event": "delivery.retrying", **extra}
            )
        else:
            status, next_at = DeliveryStatus.FAILED, None
            report.failed += 1
            logger.error("delivery failed", extra={"event": "delivery.failed", **extra})
        self._put(
            replace(
                record,
                status=status,
                next_attempt_at=next_at,
                provider_message_id=message_id,
                updated_at=now,
            )
        )

    # Suppression ----------------------------------------------------------

    def _count_suppressed(self, recipient: str, now: datetime) -> None:
        state = self._suppressed
        state.counts[recipient] = min(state.counts.get(recipient, 0) + 1, MAX_COUNTER)
        if state.since is None:
            state.since = now
        state.total_since_start = min(state.total_since_start + 1, MAX_COUNTER)

    def _maybe_open_summary(self, now: datetime) -> None:
        state = self._suppressed
        if not state.counts:
            return
        if any(self._records[key].kind is DeliveryKind.SUMMARY for key in self._active):
            return
        last = state.last_summary_at
        if last is not None and last <= now < last + self._limits.summary_interval:
            return
        if not self._limiter.available(now):
            return
        digest = hashlib.sha256(encode_time(now).encode()).hexdigest()
        event_id = f"sum_{digest[:32]}"
        since = state.since or now
        total = 0
        for recipient, count in sorted(state.counts.items()):
            if self._routing.route(recipient) is None:
                continue
            total += count
            self._put(
                DeliveryRecord(
                    event_id=event_id,
                    recipient=recipient,
                    kind=DeliveryKind.SUMMARY,
                    status=DeliveryStatus.PENDING,
                    text=_summary_text(count, since),
                    attempts=0,
                    created_at=now,
                    updated_at=now,
                    next_attempt_at=now,
                )
            )
        logger.warning(
            "sending a summary of deliveries held back by the global rate limit",
            extra={"event": "delivery.summary", "count": total},
        )
        state.counts.clear()
        state.since = None
        state.last_summary_at = now

    # Bookkeeping ------------------------------------------------------------

    def _put(self, record: DeliveryRecord) -> None:
        self._records[record.key] = record
        if record.status.terminal:
            self._active.discard(record.key)
        else:
            self._active.add(record.key)
        self._dirty_records.add(record.key)

    def _finish(self, record: DeliveryRecord, status: DeliveryStatus, now: datetime) -> None:
        self._put(replace(record, status=status, next_attempt_at=None, updated_at=now))

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

    def flush(self, now: datetime) -> bool:
        """Write unsaved changes; on failure they are kept and retried next time."""
        changes = Changes(
            rule_states=MappingProxyType(
                {rule_id: self._rule_states[rule_id] for rule_id in self._dirty_states}
            ),
            deliveries=tuple(
                self._records[key] for key in self._dirty_records if key in self._records
            ),
            attempts=tuple(self._new_attempts),
            suppression=Suppression(
                counts=MappingProxyType(dict(self._suppressed.counts)),
                since=self._suppressed.since,
                last_summary_at=self._suppressed.last_summary_at,
            ),
        )
        if not self._store.flush(changes, now):
            return False
        self._dirty_states.clear()
        self._dirty_records.clear()
        self._new_attempts.clear()
        return True

    # Health -----------------------------------------------------------------

    def health(self, now: datetime) -> DeliveryHealth:
        hour, day = self._limiter.counts(now)
        return DeliveryHealth(
            persistence_healthy=self._store.healthy,
            persistence_error=self._store.error,
            queued=len(self._active),
            suppressed_pending=sum(self._suppressed.counts.values()),
            suppressed_total=self._suppressed.total_since_start,
            sent_last_hour=hour,
            sent_last_day=day,
        )

    def record(self, event_id: str, recipient: str) -> DeliveryRecord | None:
        """The current record for one delivery, if it is still held in memory."""
        return self._records.get((event_id, recipient))

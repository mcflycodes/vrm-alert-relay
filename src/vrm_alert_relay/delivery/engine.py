"""The delivery engine: identity, durable attempts, the global cap, retries, summaries.

Life of a delivery, one per (event_id, recipient):

* :meth:`DeliveryEngine.accept_cycle` resolves each notification's recipients
  from configuration, creates ``PENDING`` records for new pairs (pairs it has
  already seen are ignored), stores the cycle's rule states, and commits both
  in one transaction.
* :meth:`DeliveryEngine.run_due` processes due records. A real provider call
  needs a free slot in the global cap. Its ``IN_FLIGHT`` record is made
  durable first, in SQLite or else in the fallback journal; if neither can
  record it, the message is sent anyway (see "failures favour alerting"
  below). The provider's result moves the record to ``DELIVERED``,
  ``FAILED``, back to ``PENDING`` with a backoff (a retryable failure), or
  ``AMBIGUOUS``.
* An ``AMBIGUOUS`` record, or an ``IN_FLIGHT`` one found at startup (a crash
  mid-send), is reconciled with the provider before any retry when the
  provider supports a lookup; otherwise, or when the lookup cannot tell, it is
  retried. A rare duplicate after a crash is accepted.
* When the cap has no free slot, a real delivery becomes ``SUPPRESSED`` and is
  counted. One aggregate "N alerts held back" summary goes to the system
  recipients, at most one per ``summary_interval``: when no real alert is
  due, or once the summary has waited ``summary_max_wait``, whichever comes
  first. The count is reduced only once a summary is delivered.

Only real provider calls use the cap. Dry-run sends go to the dry-run sink and
are counted against a separate "would send" cap that is only reported.

**Failures favour alerting.** The cap is hard in normal operation and
across ordinary crashes and restarts. When state storage cannot be read or
written, or the stored history is lost, the engine keeps alerting under the
cap it enforces in memory, reports itself unhealthy, logs an error every run,
and sends a storage notice to the system recipients (at most one per
:data:`NOTICE_INTERVAL`, and when nothing can be recorded, one per process
start). Provider-side limits are the final backstop.

Windows and backoff use monotonic time. Wall-clock time is only stored; see
:meth:`DeliveryEngine.__init__` for how it is interpreted after a restart.
"""

from __future__ import annotations

import hashlib
import logging
import random
from collections import deque
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from vrm_alert_relay.config import DeliveryMode
from vrm_alert_relay.engine import RuleState
from vrm_alert_relay.state import (
    AttemptMark,
    Changes,
    DeliveryKind,
    DeliveryOrigin,
    DeliveryRecord,
    DeliveryStatus,
    JournalEntry,
    SuppressionState,
    is_identifier,
)
from vrm_alert_relay.state.models import MAX_COUNTER, encode_time, is_message_id
from vrm_alert_relay.state.store import MAX_ATTEMPT_ROWS, MAX_RULE_STATES
from vrm_alert_relay.templates import NotificationKind, TemplateFields, render_notification

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
from .routing import Notification, Route, Routing, RuleTarget, SystemTarget, UnknownTargetError

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from vrm_alert_relay.config import ProviderName, RateLimitsConfig, Recipient, RelayConfig
    from vrm_alert_relay.state import AttemptKey, Snapshot, StateStore

    from .clock import Clock

__all__ = [
    "NOTICE_INTERVAL",
    "STORAGE_NOTICE_TEXT",
    "DeliveryEngine",
    "DeliveryHealth",
    "DeliveryLimits",
    "RunReport",
]

logger = logging.getLogger(__name__)

type DeliveryKey = tuple[str, str]

DEFAULT_MAX_QUEUE: Final = 1000
MAX_UNREAD_LEDGER: Final = 100_000
NOTICE_INTERVAL: Final = timedelta(days=1)
STORAGE_NOTICE_TEXT: Final = render_notification(
    TemplateFields(kind=NotificationKind.STORAGE_NOTICE)
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
    summary_max_wait: timedelta = HOUR
    """How long a summary gives way to real alerts before it takes the next free slot."""

    def __post_init__(self) -> None:
        if self.max_queue < 1 or self.max_records < self.max_queue:
            raise ValueError("limits need max_queue >= 1 and max_records >= max_queue")  # noqa: TRY003  # per-check validation message
        if self.summary_interval <= timedelta(0) or self.summary_max_wait < timedelta(0):
            raise ValueError("summary_interval must be positive and summary_max_wait >= 0")  # noqa: TRY003  # per-check validation message


@dataclass(slots=True)
class RunReport:
    """What one :meth:`DeliveryEngine.run_due` call did."""

    sent: int = 0
    """Real provider calls, whether or not they could be recorded."""
    dry_run_sent: int = 0
    delivered: int = 0
    reconciled: int = 0
    retrying: int = 0
    ambiguous: int = 0
    failed: int = 0
    suppressed: int = 0
    sent_unrecorded: int = 0
    """The subset of ``sent`` made although no attempt record could be made durable."""
    storage_notice: SendStatus | None = None
    """The outcome of a storage notice sent in this run, if one was."""


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


@dataclass(slots=True)
class _NoticeEpisode:
    """A storage notice working through the system recipients in order."""

    event_id: str
    routes: tuple[Route, ...]
    position: int = 0
    started: bool = False
    """Whether a provider call was made: the notice interval starts there."""


def _untrusted(value: object) -> object:
    """Widen a provider's return value so that it is validated, not trusted."""
    return value


def _summary_text(count: int, since: datetime) -> str:
    return render_notification(
        TemplateFields(kind=NotificationKind.SUPPRESSION_SUMMARY, count=count, time=since)
    )


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
        self._journaled: dict[DeliveryKey, DeliveryRecord] = {}
        self._rule_states: dict[str, RuleState] = {}
        self._dirty_states: set[str] = set()
        self._new_attempts: deque[AttemptMark] = deque(maxlen=MAX_ATTEMPT_ROWS)
        self._expired: deque[AttemptKey] = deque(maxlen=MAX_EXPIRED)
        self._durable = True
        self._complete = True
        self._reset = False
        self._suppression_read = True
        self._per_hour = rate_limits.global_per_hour
        self._per_day = rate_limits.global_per_day
        self._live = RateLimiter(self._per_hour, self._per_day)
        self._shadow = RateLimiter(self._per_hour, self._per_day)
        self._notice_mono: float | None = None
        self._notice: _NoticeEpisode | None = None
        self._summary_wanted_mono: float | None = None
        self._suppressed_total = 0
        self._dry_run_over_cap = 0
        # While the stored suppression counts are unread: what this process
        # counted, by identity, so that merging them counts nothing twice.
        self._held_unread: set[DeliveryKey] = set()
        self._untracked_unread = 0
        self._acknowledged_unread: dict[str, int] = {}

        wall, mono = clock.wall(), clock.monotonic()
        self._restore(store.load(wall), wall, mono)

    def _restore(self, snapshot: Snapshot, wall: datetime, mono: float) -> None:
        self._rule_states.update(snapshot.rule_states)
        self._restore_slots(snapshot.attempts, wall, mono)
        self._complete = snapshot.complete
        self._suppression_read = snapshot.suppression_read
        if not self._complete:
            logger.error(
                "stored state could not be read; alerting continues with the cap kept in memory",
                extra={"event": "delivery.history_unknown"},
            )
        state = snapshot.suppression
        self._suppression = state
        for record in snapshot.deliveries:
            self._note_stored(record, snapshot)
        self._last_summary_mono = self._mono_of(state.last_summary_at, wall, mono)
        if state.count:
            self._summary_wanted_mono = self._mono_of(state.since, wall, mono) or mono
        recovered = sum(self._adopt(record, wall, mono) for record in snapshot.deliveries)
        if recovered:
            logger.warning(
                "found deliveries interrupted mid-send; reconciling before any retry",
                extra={"event": "delivery.recovered_in_flight", "count": recovered},
            )
        self._adopt_open_summary()
        if snapshot.complete:
            self._forget_lost_summary(mono)
        if snapshot.reset:
            self._start_afresh(snapshot)
        self._prune_memory()
        if self._dirty_records:
            self._save()

    @staticmethod
    def _mono_of(when: datetime | None, wall: datetime, mono: float) -> float | None:
        """Monotonic time for a stored wall-clock time; a future one counts as now."""
        return None if when is None else mono - max(_seconds(wall - when), 0.0)

    def _restore_slots(self, marks: Iterable[AttemptMark], wall: datetime, mono: float) -> None:
        """Give stored attempts slots by their age; slots already held do not move."""
        slots: list[tuple[float, AttemptKey]] = []
        for mark in marks:
            age = max(_seconds(wall - mark.at), 0.0)
            if mark.live and age < _seconds(DAY):
                slots.append((mono - age, mark.key))
        self._live.restore(slots)

    def _adopt(self, record: DeliveryRecord, wall: datetime, mono: float) -> bool:
        """Take a stored record into memory; True if it was interrupted mid-send."""
        current = self._records.get(record.key)
        if current is not None and current.progress() >= record.progress():
            return False
        if record.kind is DeliveryKind.NOTICE:
            # History only: a storage notice is never sent again after a restart.
            self._records[record.key] = record
            noticed = self._mono_of(record.created_at, wall, mono)
            if noticed is not None and mono - noticed < _seconds(NOTICE_INTERVAL):
                self._notice_mono = max(noticed, self._notice_mono or noticed)
            return False
        if record.status is DeliveryStatus.IN_FLIGHT:
            # The process stopped between recording the attempt and its
            # outcome: the message may or may not have been sent.
            self._put(replace(record, status=DeliveryStatus.AMBIGUOUS, next_attempt_at=wall), mono)
            return True
        self._records[record.key] = record
        if not record.status.terminal:
            self._active.add(record.key)
            self._due[record.key] = self._restored_due(record, wall, mono)
        return False

    def _adopt_open_summary(self) -> None:
        """Resume a summary whose start only the journal recorded."""
        if self._suppression.summary_event_id is not None:
            return
        open_summaries = sorted(
            (
                self._records[key]
                for key in self._active
                if self._records[key].kind is DeliveryKind.SUMMARY and self._records[key].covers
            ),
            key=lambda record: record.created_at,
        )
        if open_summaries:
            newest = open_summaries[-1]
            self._suppression = replace(
                self._suppression,
                summary_event_id=newest.event_id,
                summary_count=newest.covers,
                last_summary_at=newest.created_at,
            )

    def _start_afresh(self, snapshot: Snapshot) -> None:
        """The database was corrupt and replaced: write everything held into the new one."""
        self._reset = True
        self._dirty_records.update(self._records)
        self._dirty_states.update(self._rule_states)
        self._new_attempts.extend(mark for mark in snapshot.attempts if mark.live)

    def _reload(self) -> None:
        """Merge stored state that could not be read before, once it can."""
        wall, mono = self._clock.wall(), self._clock.monotonic()
        snapshot = self._store.reload(wall)
        if snapshot is None:
            return
        self._restore_slots(snapshot.attempts, wall, mono)
        for record in snapshot.deliveries:
            self._adopt(record, wall, mono)
        for rule_id, state in snapshot.rule_states.items():
            self._rule_states.setdefault(rule_id, state)
        if not self._suppression_read and (snapshot.suppression_read or snapshot.reset):
            if snapshot.suppression_read:
                self._merge_suppression(snapshot, wall, mono)
            self._suppression_read = True
            self._held_unread.clear()
            self._untracked_unread = 0
            self._acknowledged_unread.clear()
        self._adopt_open_summary()
        if snapshot.reset:
            self._start_afresh(snapshot)
        # Partly read (say, a corrupt file that could not be moved aside):
        # what was read is merged, and the next cycle reads it all again.
        self._complete = snapshot.complete
        if self._complete:
            self._forget_lost_summary(mono)
            logger.warning(
                "stored state is readable again and was merged",
                extra={"event": "delivery.history_restored"},
            )

    def _merge_suppression(self, snapshot: Snapshot, wall: datetime, mono: float) -> None:
        """Merge the stored suppression counts, keyed by delivery identity.

        The stored count, read from SQLite and the journal as one snapshot,
        already includes the held-back deliveries it names and excludes what
        the delivered summaries it names reported. Only what this process
        counted beyond those, over the whole time the counts were unread, is
        added or subtracted, so a delivery that both recorded is counted once.
        """
        stored, current = snapshot.suppression, self._suppression
        added = len(self._held_unread - snapshot.counted_held) + self._untracked_unread
        reported = sum(
            covers
            for event_id, covers in self._acknowledged_unread.items()
            if event_id not in snapshot.counted_acknowledged
        )
        count = min(max(stored.count + added - reported, 0), MAX_COUNTER)
        sinces = [when for when in (current.since, stored.since) if when is not None]
        summaries = [when for when in (current.last_summary_at, stored.last_summary_at) if when]
        if current.summary_event_id is not None:
            summary_event_id, summary_count = current.summary_event_id, current.summary_count
        elif stored.summary_event_id in self._acknowledged_unread:
            summary_event_id, summary_count = None, 0  # delivered here: already subtracted
        else:
            summary_event_id, summary_count = stored.summary_event_id, stored.summary_count
        self._suppression = SuppressionState(
            count=count,
            since=min(sinces) if sinces and count else None,
            last_summary_at=max(summaries) if summaries else None,
            summary_event_id=summary_event_id,
            summary_count=summary_count,
        )
        if count and self._summary_wanted_mono is None:
            self._summary_wanted_mono = self._mono_of(self._suppression.since, wall, mono) or mono

    def _note_stored(self, record: DeliveryRecord, snapshot: Snapshot) -> None:
        """Note what a record loaded while the counts are unread already accounts for."""
        if record.status is DeliveryStatus.SUPPRESSED:
            self._note_held(record)
        elif record.event_id in snapshot.counted_acknowledged:
            self._note_acknowledged(record)

    def _note_held(self, record: DeliveryRecord) -> None:
        if self._suppression_read or record.kind is not DeliveryKind.EVENT:
            return
        if len(self._held_unread) < MAX_UNREAD_LEDGER:
            self._held_unread.add(record.key)
        else:
            # Too many to track: counted, perhaps twice; reporting more is safe.
            self._untracked_unread = min(self._untracked_unread + 1, MAX_COUNTER)

    def _note_acknowledged(self, record: DeliveryRecord) -> None:
        if not self._suppression_read and record.kind is DeliveryKind.SUMMARY and record.covers:
            self._acknowledged_unread.setdefault(record.event_id, record.covers)

    def _forget_lost_summary(self, mono: float) -> None:
        """Forget a summary in progress whose deliveries were lost; its count stands.

        A corrupt database can keep the summary's id while losing its
        deliveries, which would otherwise block every later summary.
        """
        event_id = self._suppression.summary_event_id
        if event_id is None or any(key[0] == event_id for key in self._active):
            return
        self._suppression = replace(self._suppression, summary_event_id=None, summary_count=0)
        if self._suppression.count:
            self._summary_wanted_mono = mono
        logger.warning(
            "a summary in progress was lost with stored state; the count will be summarised again",
            extra={"event": "delivery.summary_lost", "count": self._suppression.count},
        )

    def _consume(self, mark: AttemptMark, mono: float) -> None:
        (self._live if mark.live else self._shadow).consume(mark.key, mono)

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
            origin = (
                DeliveryOrigin.SYSTEM if isinstance(target, SystemTarget) else notification.origin
            )
            for route in routes:
                key = (notification.event_id, route.name)
                if key in self._records:
                    continue
                if len(self._active) >= self._limits.max_queue:
                    status = DeliveryStatus.SUPPRESSED
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
                    origin=origin,
                )
                self._put(record, mono)
                if status is DeliveryStatus.SUPPRESSED:
                    self._count_suppressed(record)
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
        self._save()
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
        """Process due deliveries: real alerts first, then any summary, then any notice."""
        report = RunReport()
        self._prepare_run()
        overdue = self._summary_overdue()
        if overdue:
            self._process_summary(report)
        for record in self._due_records(DeliveryKind.EVENT):
            self._process(record, report)
        if not overdue and not self._due_records(DeliveryKind.EVENT):
            self._process_summary(report)
        self._storage_notice(report)
        if report.suppressed:
            logger.warning(
                "global rate limit reached; deliveries held back",
                extra={"event": "delivery.suppressed", "count": report.suppressed},
            )
        if self._degraded():
            logger.error(
                "state storage is failing; alerting continues under the cap kept in memory",
                extra={
                    "event": "delivery.storage_degraded",
                    "sent_unrecorded": report.sent_unrecorded,
                },
            )
        self._prune_memory()
        self._save()
        return report

    def run_only(self, event_id: str) -> RunReport:
        """Process the due deliveries of one event, and nothing else.

        For an explicitly requested one-off message such as a test
        notification (R26). The global cap and dry-run routing apply as in
        :meth:`run_due`; other due deliveries, summaries and storage notices
        wait for the next :meth:`run_due`.
        """
        report = RunReport()
        self._prepare_run()
        for record in self._due_records(DeliveryKind.EVENT):
            if record.event_id == event_id:
                self._process(record, report)
        self._prune_memory()
        self._save()
        return report

    def _prepare_run(self) -> None:
        if not self._complete:
            self._reload()
        if not self._durable and self.flush():
            self._set_durable(durable=True)

    def _degraded(self) -> bool:
        """Whether accounting is not fully durable: the case for a storage notice."""
        return not (self._durable and self._complete) or self._reset

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

    def _process(  # one decision ladder per delivery
        self, record: DeliveryRecord, report: RunReport
    ) -> None:
        if self._routing.opted_out(record.origin, record.rule_id):
            # Queued before a restart under a configuration that sent it.
            self._finish(record, DeliveryStatus.FAILED)
            logger.info(
                "not sending a delivery that the configuration now only logs",
                extra={
                    "event": "delivery.suppressed_by_config",
                    "origin": None if record.origin is None else record.origin.value,
                    "rule_id": record.rule_id,
                    **self._log_ids(record),
                },
            )
            return
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
        if record.attempts >= self._retry.max_attempts and not record.recovered:
            # A delivery recovered from a corrupt row is owed one retry first.
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
        mono = self._clock.monotonic()
        if live and not self._live.available(mono):
            self._finish(record, DeliveryStatus.SUPPRESSED)
            if record.kind is DeliveryKind.EVENT:
                self._count_suppressed(record)
            report.suppressed += 1
            return
        in_flight = self._begin_attempt(record, report, live=live)
        result = self._send(provider, message, route.recipient, record)
        self._apply(in_flight, result, report)
        if live:
            self._save()

    def _begin_attempt(
        self, record: DeliveryRecord, report: RunReport, *, live: bool
    ) -> DeliveryRecord:
        """Record an attempt (durably for a real send, best effort) and take its slot."""
        mono, wall = self._clock.monotonic(), self._clock.wall()
        in_flight = replace(
            record,
            status=DeliveryStatus.IN_FLIGHT,
            attempts=record.attempts + 1,
            recovered=False,
            last_attempt_at=wall,
            next_attempt_at=None,
            updated_at=wall,
        )
        mark = AttemptMark(record.event_id, record.recipient, in_flight.attempts, wall, live)
        self._put(in_flight, mono)
        if live:
            self._new_attempts.append(mark)
            report.sent += 1
            if not self._make_durable(in_flight):
                report.sent_unrecorded += 1
            self._consume(mark, mono)
        else:
            if not self._shadow.available(mono):
                self._dry_run_over_cap = min(self._dry_run_over_cap + 1, MAX_COUNTER)
            self._consume(mark, mono)
            report.dry_run_sent += 1
        return in_flight

    def _make_durable(self, in_flight: DeliveryRecord) -> bool:
        """Record the attempt in SQLite, or else in the journal (R15, ADR 0002).

        When neither can record it the message is still sent: the cap kept
        in memory still applies, and alerting comes first.
        """
        durable = self._save(attempt=in_flight)
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
                "cannot record send attempts; sending anyway under the cap kept in memory",
                extra={"event": "delivery.durable_accounting_lost"},
            )
        self._durable = durable

    def _storage_notice(self, report: RunReport) -> None:
        """Tell the system recipients, in order, that storage is failing.

        At most one notice per :data:`NOTICE_INTERVAL`, counted from its
        first provider call and remembered in storage
        when anything can record it. Recipients are tried in order (live ones
        first) until one reports the notice delivered or its outcome is
        unknown; only a definite failure moves on to the next. The notice
        waits for a free slot in the cap.
        """
        mono, wall = self._clock.monotonic(), self._clock.wall()
        if self._notice is None:
            recent = self._notice_mono is not None and mono - self._notice_mono < _seconds(
                NOTICE_INTERVAL
            )
            routes = sorted(
                self._routing.system_routes, key=lambda route: route.mode is not DeliveryMode.LIVE
            )
            if not self._degraded() or recent or not routes:
                return
            digest = hashlib.sha256(f"notice|{encode_time(wall)}|{mono!r}".encode()).hexdigest()
            self._notice = _NoticeEpisode(f"notice_{digest[:32]}", tuple(routes))
        episode = self._notice
        while episode.position < len(episode.routes):
            route = episode.routes[episode.position]
            live = route.mode is DeliveryMode.LIVE
            if live and not self._live.available(mono):
                return  # Wait for the next free slot.
            record = DeliveryRecord(
                event_id=episode.event_id,
                recipient=route.name,
                kind=DeliveryKind.NOTICE,
                status=DeliveryStatus.PENDING,
                text=STORAGE_NOTICE_TEXT,
                attempts=0,
                created_at=wall,
                updated_at=wall,
                origin=DeliveryOrigin.SYSTEM,
            )
            if not episode.started:
                episode.started = True
                self._notice_mono = mono
            in_flight = self._begin_attempt(record, report, live=live)
            result = self._send(
                self._provider_for(route),
                Message(delivery_id(record.event_id, route.name), STORAGE_NOTICE_TEXT),
                route.recipient,
                record,
            )
            status = {
                SendStatus.DELIVERED: DeliveryStatus.DELIVERED,
                SendStatus.AMBIGUOUS: DeliveryStatus.AMBIGUOUS,
            }.get(result.status, DeliveryStatus.FAILED)
            self._put(
                replace(in_flight, status=status, updated_at=self._clock.wall()),
                self._clock.monotonic(),
            )
            report.storage_notice = result.status
            logger.error(
                "sent a storage notice",
                extra={
                    "event": "delivery.storage_notice",
                    "outcome": result.status.value,
                    **self._log_ids(record),
                },
            )
            if live:
                self._save()
            if status is not DeliveryStatus.FAILED:
                break
            episode.position += 1
        self._notice = None

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
            self._save()
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

    def _count_suppressed(self, record: DeliveryRecord) -> None:
        self._note_held(record)
        state = self._suppression
        self._suppression = replace(
            state,
            count=min(state.count + 1, MAX_COUNTER),
            since=state.since or self._clock.wall(),
        )
        if self._summary_wanted_mono is None:
            self._summary_wanted_mono = self._clock.monotonic()
        self._suppressed_total = min(self._suppressed_total + 1, MAX_COUNTER)

    def _summary_overdue(self) -> bool:
        """Whether a summary has given way to real alerts for long enough."""
        wanted = self._summary_wanted_mono
        return (
            self._suppression.count > 0
            and wanted is not None
            and self._clock.monotonic() - wanted >= _seconds(self._limits.summary_max_wait)
        )

    def _process_summary(self, report: RunReport) -> None:
        self._maybe_open_summary()
        for record in self._due_records(DeliveryKind.SUMMARY):
            self._process(record, report)

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
                    covers=state.count,
                    origin=DeliveryOrigin.SYSTEM,
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
            self._note_acknowledged(record)
            remaining = max(state.count - record.covers, 0)
            state = replace(
                state,
                count=remaining,
                since=None if remaining == 0 else state.since,
                summary_count=0,
            )
            # Anything still unreported starts its own wait for a summary.
            self._summary_wanted_mono = None if remaining == 0 else self._clock.monotonic()
        if not any(key[0] == record.event_id for key in self._active):
            # Every delivery of this summary has finished. If none was
            # delivered, the count stands and a later summary reports it.
            state = replace(state, summary_event_id=None, summary_count=0)
        self._suppression = state

    # Bookkeeping ------------------------------------------------------------

    def _put(self, record: DeliveryRecord, due: float) -> None:
        self._records[record.key] = record
        self._dirty_records.add(record.key)
        if record.kind is DeliveryKind.NOTICE:
            return  # Sent inline by _storage_notice, never queued.
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
            (
                record
                for record in self._records.values()
                if record.status.terminal or record.kind is DeliveryKind.NOTICE
            ),
            key=lambda record: (record.updated_at, record.event_id, record.recipient),
        )
        for record in finished[:excess]:
            del self._records[record.key]
            self._dirty_records.discard(record.key)
            self._journaled.pop(record.key, None)

    def flush(self) -> bool:
        """Write unsaved changes to SQLite; on failure they are kept and retried next time."""
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
        self._journaled.clear()
        self._new_attempts.clear()
        self._expired.clear()
        return True

    def _save(self, attempt: DeliveryRecord | None = None) -> bool:
        """Write to SQLite, or else journal what changed; True if it is durable.

        The journal gets every changed delivery not yet journaled in its
        current version, so suppression and summary acknowledgements survive
        a restart, keyed by delivery identity. ``attempt`` is journaled as a
        send attempt, which also holds its slot in the cap after a restart.
        """
        if self.flush():
            return True
        entries = [
            JournalEntry(record, attempt=False)
            for key in sorted(self._dirty_records)
            if (record := self._records.get(key)) is not None
            and self._journaled.get(key) != record
            and (attempt is None or key != attempt.key)
        ]
        if attempt is not None:
            entries.append(JournalEntry(attempt, attempt=True))
        if not entries:
            return True
        if not self._store.journal(tuple(entries), self._clock.wall()):
            return False
        for entry in entries:
            self._journaled[entry.record.key] = entry.record
        return True

    # Health -----------------------------------------------------------------

    def health(self) -> DeliveryHealth:
        mono = self._clock.monotonic()
        hour, day = self._live.counts(mono)
        dry_hour, dry_day = self._shadow.counts(mono)
        return DeliveryHealth(
            persistence_healthy=self._store.healthy,
            persistence_error=self._store.error,
            durable_accounting=not self._degraded(),
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

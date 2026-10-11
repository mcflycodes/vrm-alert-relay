"""Immutable records persisted by the state store."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Mapping

    from vrm_alert_relay.engine import RuleState

MAX_IDENTIFIER_LENGTH: Final = 128
MAX_MESSAGE_LENGTH: Final = 1000
MAX_PROVIDER_MESSAGE_ID_LENGTH: Final = 128
MAX_ATTEMPTS: Final = 100
MAX_COUNTER: Final = 2**63 - 1
MAX_TIME_LENGTH: Final = 64

_IDENTIFIER_RE: Final = re.compile(r"[A-Za-z0-9_.:-]+")

type AttemptKey = tuple[str, str, int]


class InvalidRecordError(ValueError):
    """Raised when a persisted record is malformed or outside safe bounds."""


class DeliveryStatus(StrEnum):
    """Lifecycle of one delivery of one event to one recipient."""

    PENDING = "pending"
    IN_FLIGHT = "in_flight"
    AMBIGUOUS = "ambiguous"
    DELIVERED = "delivered"
    FAILED = "failed"
    SUPPRESSED = "suppressed"

    @property
    def terminal(self) -> bool:
        """Whether no further work will be done for a record in this status."""
        return self in _TERMINAL


_TERMINAL: Final = frozenset(
    {DeliveryStatus.DELIVERED, DeliveryStatus.FAILED, DeliveryStatus.SUPPRESSED}
)


class DeliveryKind(StrEnum):
    """Whether a delivery carries a rule or direct event, or a rate-limit summary."""

    EVENT = "event"
    SUMMARY = "summary"


def is_identifier(value: object) -> bool:
    """Whether ``value`` is a bounded identifier safe to store and log."""
    return (
        isinstance(value, str)
        and len(value) <= MAX_IDENTIFIER_LENGTH
        and _IDENTIFIER_RE.fullmatch(value) is not None
    )


def is_aware(value: object) -> bool:
    """Whether ``value`` is a timezone-aware datetime."""
    return isinstance(value, datetime) and value.utcoffset() is not None


def is_counter(value: object, *, upper: int = MAX_COUNTER) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= upper


def is_message_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= MAX_PROVIDER_MESSAGE_ID_LENGTH
        and value.isprintable()
    )


def encode_time(value: datetime) -> str:
    """Encode an aware datetime so that string order matches time order."""
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def decode_time(raw: object) -> datetime:
    """Decode a stored timestamp, rejecting anything unbounded or naive."""
    if not isinstance(raw, str) or len(raw) > MAX_TIME_LENGTH:
        raise InvalidRecordError("timestamp must be a bounded string")  # noqa: TRY003  # per-check validation message
    value = datetime.fromisoformat(raw)
    if not is_aware(value):
        raise InvalidRecordError("timestamp must be timezone-aware")  # noqa: TRY003  # per-check validation message
    return value


def decode_optional_time(raw: object) -> datetime | None:
    return None if raw is None else decode_time(raw)


RECORD_FIELDS: Final = (
    "event_id",
    "recipient",
    "rule_id",
    "kind",
    "status",
    "text",
    "attempts",
    "created_at",
    "updated_at",
    "next_attempt_at",
    "last_attempt_at",
    "provider_message_id",
)


@dataclass(frozen=True, slots=True)
class DeliveryRecord:
    """The persisted state of one delivery, identified by (event_id, recipient)."""

    event_id: str
    recipient: str
    kind: DeliveryKind
    status: DeliveryStatus
    text: str
    attempts: int
    created_at: datetime
    updated_at: datetime
    next_attempt_at: datetime | None = None
    last_attempt_at: datetime | None = None
    provider_message_id: str | None = None
    rule_id: str | None = None
    """The rule whose event this is, so that a lost record can reset that rule."""

    def __post_init__(self) -> None:  # noqa: C901  # flat validation checklist, deliberately not split
        if not is_identifier(self.event_id):
            raise InvalidRecordError("event_id must be a bounded identifier")  # noqa: TRY003  # per-check validation message
        if not is_identifier(self.recipient):
            raise InvalidRecordError("recipient must be a bounded identifier")  # noqa: TRY003  # per-check validation message
        if self.rule_id is not None and not is_identifier(self.rule_id):
            raise InvalidRecordError("rule_id must be a bounded identifier or null")  # noqa: TRY003  # per-check validation message
        if not isinstance(self.kind, DeliveryKind):
            raise InvalidRecordError("kind must be a DeliveryKind")  # noqa: TRY003  # per-check validation message
        if not isinstance(self.status, DeliveryStatus):
            raise InvalidRecordError("status must be a DeliveryStatus")  # noqa: TRY003  # per-check validation message
        if not isinstance(self.text, str) or len(self.text) > MAX_MESSAGE_LENGTH:
            raise InvalidRecordError("text must be a bounded string")  # noqa: TRY003  # per-check validation message
        if not is_counter(self.attempts, upper=MAX_ATTEMPTS):
            raise InvalidRecordError("attempts is outside safe bounds")  # noqa: TRY003  # per-check validation message
        for name in ("created_at", "updated_at"):
            if not is_aware(getattr(self, name)):
                raise InvalidRecordError(f"{name} must be an aware datetime")  # noqa: TRY003  # per-check validation message
        for name in ("next_attempt_at", "last_attempt_at"):
            value = getattr(self, name)
            if value is not None and not is_aware(value):
                raise InvalidRecordError(f"{name} must be an aware datetime or null")  # noqa: TRY003  # per-check validation message
        if self.provider_message_id is not None and not is_message_id(self.provider_message_id):
            raise InvalidRecordError("provider_message_id must be a bounded printable string")  # noqa: TRY003  # per-check validation message

    @property
    def key(self) -> tuple[str, str]:
        """The delivery identity: one delivery per (event_id, recipient)."""
        return (self.event_id, self.recipient)

    def progress(self) -> tuple[int, int, datetime]:
        """Orders two versions of one record; the larger one is newer.

        Every attempt starts ``IN_FLIGHT`` and then moves on, so the attempt
        count and the stage order versions even when wall-clock time does not.
        """
        if self.status is DeliveryStatus.IN_FLIGHT:
            stage = 0
        elif self.status.terminal:
            stage = 2
        else:
            stage = 1
        return (self.attempts, stage, self.updated_at)

    def to_json(self) -> dict[str, object]:
        def stamp(value: datetime | None) -> str | None:
            return None if value is None else encode_time(value)

        return {
            "event_id": self.event_id,
            "recipient": self.recipient,
            "rule_id": self.rule_id,
            "kind": self.kind.value,
            "status": self.status.value,
            "text": self.text,
            "attempts": self.attempts,
            "created_at": encode_time(self.created_at),
            "updated_at": encode_time(self.updated_at),
            "next_attempt_at": stamp(self.next_attempt_at),
            "last_attempt_at": stamp(self.last_attempt_at),
            "provider_message_id": self.provider_message_id,
        }

    @classmethod
    def from_json(cls, data: object) -> DeliveryRecord:
        if not isinstance(data, dict) or set(data) != set(RECORD_FIELDS):
            raise InvalidRecordError("record must contain exactly the record fields")  # noqa: TRY003  # per-check validation message
        return cls(
            event_id=data["event_id"],
            recipient=data["recipient"],
            rule_id=data["rule_id"],
            kind=DeliveryKind(str(data["kind"])),
            status=DeliveryStatus(str(data["status"])),
            text=data["text"],
            attempts=data["attempts"],
            created_at=decode_time(data["created_at"]),
            updated_at=decode_time(data["updated_at"]),
            next_attempt_at=decode_optional_time(data["next_attempt_at"]),
            last_attempt_at=decode_optional_time(data["last_attempt_at"]),
            provider_message_id=data["provider_message_id"],
        )


@dataclass(frozen=True, slots=True)
class AttemptMark:
    """Evidence of one send, which occupies a slot of a rate window."""

    event_id: str
    recipient: str
    attempt: int
    at: datetime
    live: bool = True
    """A real provider call; ``False`` for a dry-run send."""

    def __post_init__(self) -> None:
        if not is_identifier(self.event_id) or not is_identifier(self.recipient):
            raise InvalidRecordError("attempt identity must be bounded identifiers")  # noqa: TRY003  # per-check validation message
        if not is_counter(self.attempt, upper=MAX_ATTEMPTS):
            raise InvalidRecordError("attempt number is outside safe bounds")  # noqa: TRY003  # per-check validation message
        if not is_aware(self.at):
            raise InvalidRecordError("attempt time must be aware")  # noqa: TRY003  # per-check validation message
        if not isinstance(self.live, bool):
            raise InvalidRecordError("live must be a bool")  # noqa: TRY003  # per-check validation message

    @property
    def key(self) -> AttemptKey:
        return (self.event_id, self.recipient, self.attempt)


@dataclass(frozen=True, slots=True)
class SuppressionState:
    """Deliveries held back and not yet reported, and the summary reporting them."""

    count: int = 0
    since: datetime | None = None
    last_summary_at: datetime | None = None
    summary_event_id: str | None = None
    summary_count: int = 0
    """How many held-back deliveries the summary in progress reports."""


@dataclass(frozen=True, slots=True)
class JournalEntry:
    """One line of the fallback attempt journal."""

    record: DeliveryRecord
    attempt: bool
    """Whether this line records a provider call at ``record.last_attempt_at``."""

    def mark(self) -> AttemptMark | None:
        if not self.attempt or self.record.last_attempt_at is None:
            return None
        return AttemptMark(
            self.record.event_id,
            self.record.recipient,
            self.record.attempts,
            self.record.last_attempt_at,
        )


def _empty_states() -> Mapping[str, RuleState]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class Snapshot:
    """Everything loaded from the store and the journal at startup.

    Attempt times are never later than the load time: an attempt stamped in
    the future (the clock moved backwards since) counts as happening now.
    """

    rule_states: Mapping[str, RuleState] = field(default_factory=_empty_states)
    deliveries: tuple[DeliveryRecord, ...] = ()
    attempts: tuple[AttemptMark, ...] = ()
    attempts_complete: bool = True
    """False when the stored send-attempt history could not be read."""
    suppression: SuppressionState = field(default_factory=SuppressionState)
    last_seen: datetime | None = None
    clock_moved_backwards: bool = False
    problems: int = 0
    """Corrupt rows or journal lines found; any makes the store unhealthy."""


@dataclass(frozen=True, slots=True)
class Changes:
    """One atomic write: upserted rows, new and expired attempts, and suppression."""

    rule_states: Mapping[str, RuleState] = field(default_factory=_empty_states)
    deliveries: tuple[DeliveryRecord, ...] = ()
    attempts: tuple[AttemptMark, ...] = ()
    expired_attempts: tuple[AttemptKey, ...] = ()
    suppression: SuppressionState = field(default_factory=SuppressionState)

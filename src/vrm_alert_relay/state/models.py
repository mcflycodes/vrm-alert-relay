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

_IDENTIFIER_RE: Final = re.compile(r"[A-Za-z0-9_.:-]+")


class InvalidRecordError(ValueError):
    """Raised when a delivery record is malformed or outside safe bounds."""


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
    """Whether a delivery carries a rule event or a rate-limit summary."""

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


def encode_time(value: datetime) -> str:
    """Encode an aware datetime so that string order matches time order."""
    return value.astimezone(UTC).isoformat(timespec="microseconds")


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

    def __post_init__(self) -> None:  # noqa: C901  # flat validation checklist, deliberately not split
        if not is_identifier(self.event_id):
            raise InvalidRecordError("event_id must be a bounded identifier")  # noqa: TRY003  # per-check validation message
        if not is_identifier(self.recipient):
            raise InvalidRecordError("recipient must be a bounded identifier")  # noqa: TRY003  # per-check validation message
        if not isinstance(self.kind, DeliveryKind):
            raise InvalidRecordError("kind must be a DeliveryKind")  # noqa: TRY003  # per-check validation message
        if not isinstance(self.status, DeliveryStatus):
            raise InvalidRecordError("status must be a DeliveryStatus")  # noqa: TRY003  # per-check validation message
        if not isinstance(self.text, str) or len(self.text) > MAX_MESSAGE_LENGTH:
            raise InvalidRecordError("text must be a bounded string")  # noqa: TRY003  # per-check validation message
        if (
            not isinstance(self.attempts, int)
            or isinstance(self.attempts, bool)
            or not 0 <= self.attempts <= MAX_ATTEMPTS
        ):
            raise InvalidRecordError("attempts is outside safe bounds")  # noqa: TRY003  # per-check validation message
        for name in ("created_at", "updated_at"):
            if not is_aware(getattr(self, name)):
                raise InvalidRecordError(f"{name} must be an aware datetime")  # noqa: TRY003  # per-check validation message
        for name in ("next_attempt_at", "last_attempt_at"):
            value = getattr(self, name)
            if value is not None and not is_aware(value):
                raise InvalidRecordError(f"{name} must be an aware datetime or null")  # noqa: TRY003  # per-check validation message
        if self.provider_message_id is not None and not (
            isinstance(self.provider_message_id, str)
            and 0 < len(self.provider_message_id) <= MAX_PROVIDER_MESSAGE_ID_LENGTH
            and self.provider_message_id.isprintable()
        ):
            raise InvalidRecordError("provider_message_id must be a bounded printable string")  # noqa: TRY003  # per-check validation message

    @property
    def key(self) -> tuple[str, str]:
        """The delivery identity: one delivery per (event_id, recipient)."""
        return (self.event_id, self.recipient)


def _empty_counts() -> Mapping[str, int]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class Suppression:
    """Deliveries held back by the global cap and not yet reported in a summary."""

    counts: Mapping[str, int] = field(default_factory=_empty_counts)
    since: datetime | None = None
    last_summary_at: datetime | None = None


def _empty_states() -> Mapping[str, RuleState]:
    return MappingProxyType({})


@dataclass(frozen=True, slots=True)
class Snapshot:
    """Everything loaded from the store at startup."""

    rule_states: Mapping[str, RuleState] = field(default_factory=_empty_states)
    deliveries: tuple[DeliveryRecord, ...] = ()
    attempts: tuple[datetime, ...] = ()
    suppression: Suppression = field(default_factory=Suppression)


@dataclass(frozen=True, slots=True)
class Changes:
    """One atomic write: upserted rows, new send attempts, and the suppression state."""

    rule_states: Mapping[str, RuleState] = field(default_factory=_empty_states)
    deliveries: tuple[DeliveryRecord, ...] = ()
    attempts: tuple[datetime, ...] = ()
    suppression: Suppression = field(default_factory=Suppression)

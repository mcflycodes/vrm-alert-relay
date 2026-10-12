"""The interface between the delivery engine and notification providers.

A provider receives a :class:`Message` and the operator-configured
:class:`~vrm_alert_relay.config.Recipient` it should deliver to, and returns a
:class:`SendResult`. A result carries only an outcome and an optional
provider-side message ID; it has no field through which a provider could
name or change a destination.
"""

from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol, runtime_checkable

from vrm_alert_relay.state import MAX_MESSAGE_LENGTH

if TYPE_CHECKING:
    from datetime import datetime

    from vrm_alert_relay.config import Recipient

__all__ = [
    "MAX_MESSAGE_LENGTH",
    "Message",
    "Provider",
    "ReconcileQuery",
    "ReconcileStatus",
    "ReconcilingProvider",
    "SendResult",
    "SendStatus",
    "delivery_id",
    "sanitize_text",
]

_ELLIPSIS: Final = "…"


class SendStatus(StrEnum):
    """The outcome of one provider call."""

    DELIVERED = "delivered"
    """The provider accepted the message."""
    FAILED = "failed"
    """The provider definitively did not accept the message."""
    AMBIGUOUS = "ambiguous"
    """The outcome is unknown, for example after a timeout."""


@dataclass(frozen=True, slots=True)
class SendResult:
    """What a provider reports back. It cannot name a destination."""

    status: SendStatus
    provider_message_id: str | None = None
    retryable: bool = False
    """For ``FAILED`` only: whether a later attempt could succeed."""


class ReconcileStatus(StrEnum):
    """What a provider lookup says about an earlier, ambiguous attempt."""

    DELIVERED = "delivered"
    NOT_DELIVERED = "not_delivered"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Message:
    """One rendered notification for one recipient."""

    delivery_id: str
    """Stable for an (event, recipient) pair; usable as an idempotency key."""
    text: str


@dataclass(frozen=True, slots=True)
class ReconcileQuery:
    """Everything a provider may use to look up an earlier attempt."""

    message: Message
    recipient: Recipient
    provider_message_id: str | None
    attempted_at: datetime


@runtime_checkable
class Provider(Protocol):
    """A notification transport.

    ``send`` should return ``AMBIGUOUS`` when it cannot tell whether the
    message went out. An exception from ``send`` is treated as ``AMBIGUOUS``.
    """

    def send(self, message: Message, recipient: Recipient) -> SendResult: ...


@runtime_checkable
class ReconcilingProvider(Provider, Protocol):
    """A provider that can look up whether an ambiguous attempt was delivered.

    An exception from ``reconcile`` is treated as ``UNKNOWN``.
    """

    def reconcile(self, query: ReconcileQuery) -> ReconcileStatus: ...


def delivery_id(event_id: str, recipient: str) -> str:
    """Return the stable identity of the delivery of ``event_id`` to ``recipient``."""
    digest = hashlib.sha256(f"{event_id}\x00{recipient}".encode()).hexdigest()
    return f"dlv_{digest[:32]}"


def sanitize_text(text: str, max_length: int = MAX_MESSAGE_LENGTH) -> str:
    """Replace control and format characters, keep newlines, and bound the length."""
    cleaned = "".join(
        char if char == "\n" or not unicodedata.category(char).startswith("C") else " "
        for char in text[: max_length * 2]
    )
    if len(cleaned) > max_length:
        return cleaned[: max_length - 1] + _ELLIPSIS
    return cleaned

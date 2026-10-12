"""Messages that carry structured event fields alongside their text."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from vrm_alert_relay.delivery.protocol import Message

if TYPE_CHECKING:
    from vrm_alert_relay.templates import TemplateFields

__all__ = ["DetailedMessage"]


@dataclass(frozen=True, slots=True)
class DetailedMessage(Message):
    """A :class:`Message` with the template fields it was rendered from.

    Providers that send structured data, such as the webhook, use ``fields``
    when present and fall back to the text alone otherwise. Like the text,
    the fields can never name a recipient or a destination.
    """

    fields: TemplateFields | None = None

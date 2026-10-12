"""Log-safe descriptions of recipients, shared by every provider."""

from __future__ import annotations

from typing import TYPE_CHECKING

from vrm_alert_relay.config import (
    HomeAssistantRecipient,
    VoipmsRecipient,
    WebhookRecipient,
    display_name,
)
from vrm_alert_relay.logs.redaction import mask_recipient

if TYPE_CHECKING:
    from vrm_alert_relay.config import Recipient

__all__ = ["describe_recipient"]


def describe_recipient(recipient: Recipient) -> str:
    """How logs may name ``recipient``.

    Phone numbers show only their last four digits. A Home Assistant service
    name follows the rule ``check-config`` and the delivery engine apply to
    recipient names (:func:`~vrm_alert_relay.config.display_name`): one that
    carries too many digits to be shown, such as ``mobile_app_2025550199``,
    is replaced by a placeholder holding only its last four characters.
    """
    if isinstance(recipient, VoipmsRecipient):
        return f"sms:{recipient.phone.masked}"
    if isinstance(recipient, HomeAssistantRecipient):
        return f"notify.{display_name(recipient.service, mask_recipient(recipient.service))}"
    if isinstance(recipient, WebhookRecipient):
        return "webhook"
    return "log"

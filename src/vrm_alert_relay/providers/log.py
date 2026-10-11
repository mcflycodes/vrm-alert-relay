"""The ``log`` provider: dry-run delivery that records what would be sent."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from vrm_alert_relay.config import (
    HomeAssistantRecipient,
    VoipmsRecipient,
    WebhookRecipient,
)
from vrm_alert_relay.providers._http import DELIVERED
from vrm_alert_relay.providers.voipms import sms_text

if TYPE_CHECKING:
    from vrm_alert_relay.config import Recipient
    from vrm_alert_relay.delivery.protocol import Message, SendResult

__all__ = ["DryRunLogProvider", "describe_recipient"]

_log = logging.getLogger(__name__)


def describe_recipient(recipient: Recipient) -> str:
    """A log-safe description: phone numbers show only their last four digits."""
    if isinstance(recipient, VoipmsRecipient):
        return f"sms:{recipient.phone.masked}"
    if isinstance(recipient, HomeAssistantRecipient):
        return f"notify.{recipient.service}"
    if isinstance(recipient, WebhookRecipient):
        return "webhook"
    return "log"


class DryRunLogProvider:
    """Writes one structured log record per message instead of sending it.

    The record shows the text as the recipient's provider would send it (an
    SMS is trimmed to 160 characters). It never contacts any service and
    always reports the message as delivered.
    """

    def send(self, message: Message, recipient: Recipient) -> SendResult:
        text = sms_text(message.text) if isinstance(recipient, VoipmsRecipient) else message.text
        _log.info(
            "dry run: message not sent",
            extra={
                "event": "provider.dry_run",
                "provider": recipient.provider,
                "recipient": describe_recipient(recipient),
                "delivery_id": message.delivery_id,
                "text": text,
            },
        )
        return DELIVERED

    def __repr__(self) -> str:
        return "DryRunLogProvider()"

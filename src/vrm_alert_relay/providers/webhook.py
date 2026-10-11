"""The ``webhook`` provider: a fixed JSON document POSTed to one configured URL.

The payload (version 1) always has exactly these keys::

    {
      "version": 1,
      "source": "vrm-alert-relay",
      "delivery_id": "dlv_...",
      "kind": "escalated",
      "rule": "cabin-freezer-warm",
      "level": "critical",
      "value": -3.5,
      "unit": "°C",
      "installation": "cabin",
      "measurement": "tsT",
      "time": "2026-01-15T12:00:00Z",
      "text": "critical: cabin-freezer-warm at cabin: ..."
    }

``delivery_id`` is stable across retries of the same message and can be used
to drop duplicates. ``text`` is the rendered message. The structured fields
are ``null`` when the message does not carry them, and string fields are
sanitized and bounded like template output. Nothing in the payload or the
receiver's response can change the URL, which comes only from configuration.

An optional authentication header (name from configuration, value from a
secret file) is sent with every request; the value is registered with the log
redaction registry. The URL path is treated as secret in logs and errors,
since webhook URLs often embed a token. A 2xx response is delivered; other
outcomes follow the same rules as the Home Assistant provider.
"""

from __future__ import annotations

import logging
import math
from datetime import UTC
from typing import TYPE_CHECKING, Final

from pydantic import TypeAdapter

from vrm_alert_relay.config import WebhookRecipient
from vrm_alert_relay.config.fields import HeaderName
from vrm_alert_relay.delivery.protocol import SendResult, SendStatus, sanitize_text
from vrm_alert_relay.logs.redaction import SecretRegistry, register_secret
from vrm_alert_relay.net import Endpoint, HttpError
from vrm_alert_relay.providers._http import DELIVERED, FAILED, result_for_error
from vrm_alert_relay.providers.messages import DetailedMessage
from vrm_alert_relay.templates import FIELD_LIMITS, sanitize_field

if TYPE_CHECKING:
    from vrm_alert_relay.config import Recipient, Secret
    from vrm_alert_relay.delivery.protocol import Message
    from vrm_alert_relay.net import SafeHttpClient
    from vrm_alert_relay.templates import TemplateFields

__all__ = ["PAYLOAD_SOURCE", "PAYLOAD_VERSION", "WebhookPostProvider", "webhook_payload"]

PAYLOAD_VERSION: Final = 1
PAYLOAD_SOURCE: Final = "vrm-alert-relay"
MAX_RESPONSE_BYTES: Final = 64 * 1024

_HEADER_NAME: Final = TypeAdapter(HeaderName)
_TEXT_FIELDS: Final = ("rule", "level", "unit", "installation", "measurement")
_log = logging.getLogger(__name__)

type JsonScalar = str | int | float | None


def _bounded(fields: TemplateFields, name: str) -> str | None:
    value: str | None = getattr(fields, name)
    return None if value is None else sanitize_field(value, FIELD_LIMITS[name])


def webhook_payload(message: Message) -> dict[str, JsonScalar]:
    """The version 1 payload for ``message``. See the module docstring."""
    fields = message.fields if isinstance(message, DetailedMessage) else None
    payload: dict[str, JsonScalar] = {
        "version": PAYLOAD_VERSION,
        "source": PAYLOAD_SOURCE,
        "delivery_id": message.delivery_id,
        "kind": None,
        "rule": None,
        "level": None,
        "value": None,
        "unit": None,
        "installation": None,
        "measurement": None,
        "time": None,
        "text": sanitize_text(message.text),
    }
    if fields is not None:
        payload["kind"] = fields.kind.value
        for name in _TEXT_FIELDS:
            payload[name] = _bounded(fields, name)
        value = fields.value
        if value is not None and not isinstance(value, bool) and math.isfinite(value):
            payload["value"] = value
        when = fields.time
        if when is not None and when.utcoffset() is not None:
            payload["time"] = when.astimezone(UTC).isoformat().replace("+00:00", "Z")
    return payload


class WebhookPostProvider:
    """POSTs :func:`webhook_payload` to the configured webhook URL."""

    def __init__(
        self,
        http: SafeHttpClient,
        *,
        url: str,
        auth_header: tuple[str, Secret] | None = None,
        registry: SecretRegistry | None = None,
    ) -> None:
        self._http = http
        self._endpoint = Endpoint(url, secret_path=True, allow_http=http.allow_insecure_http)
        self._auth: tuple[str, Secret] | None = None
        if auth_header is not None:
            name, value = auth_header
            # Raises a ValidationError, whose input is hidden, for a bad name.
            self._auth = (_HEADER_NAME.validate_python(name), value)
            if registry is None:
                register_secret(value.reveal())
            else:
                registry.register(value.reveal())

    def __repr__(self) -> str:
        return f"WebhookPostProvider({self._endpoint.display!r})"

    def send(self, message: Message, recipient: Recipient) -> SendResult:
        if not isinstance(recipient, WebhookRecipient):
            return self._outcome(message, FAILED, "wrong_recipient_type")
        headers = None if self._auth is None else {self._auth[0]: self._auth[1].reveal()}
        try:
            self._http.post(
                self._endpoint,
                json=webhook_payload(message),
                headers=headers,
                max_response_bytes=MAX_RESPONSE_BYTES,
            )
        except HttpError as error:
            return self._outcome(message, result_for_error(error), type(error).__name__)
        return self._outcome(message, DELIVERED, "accepted")

    def _outcome(self, message: Message, result: SendResult, reason: str) -> SendResult:
        _log.log(
            logging.INFO if result.status is SendStatus.DELIVERED else logging.WARNING,
            "webhook post %s",
            result.status.value,
            extra={
                "event": f"provider.{result.status.value}",
                "provider": "webhook",
                "delivery_id": message.delivery_id,
                "target": self._endpoint.display,
                "retryable": result.retryable,
                "reason": reason,
            },
        )
        return result

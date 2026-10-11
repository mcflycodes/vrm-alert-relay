"""The ``homeassistant`` provider: a Home Assistant ``notify`` service call.

Each message is one ``POST {base_url}/api/services/notify/<service>`` with a
long-lived access token as ``Authorization: Bearer <token>`` and the fixed
JSON body ``{"message": ..., "title": ...}``. The service name comes only
from the recipient's configuration and is checked again here; it is joined
as one percent-encoded path segment, so it can never change the host or the
rest of the path. The token and the full header value are registered with the
log redaction registry when the provider is built.

A 2xx response is delivered. 401 and 403 (bad or under-privileged token),
like other 4xx answers except 408, 425 and 429, fail without retry; a 5xx,
a timeout after the request was sent or an unreadable response is
ambiguous. Home Assistant offers no lookup, so there is no reconcile.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Final

from pydantic import TypeAdapter, ValidationError

from vrm_alert_relay.config import HomeAssistantRecipient
from vrm_alert_relay.config.fields import HaServiceName
from vrm_alert_relay.delivery.protocol import SendResult, SendStatus, sanitize_text
from vrm_alert_relay.logs.redaction import SecretRegistry, register_derived_secret, register_secret
from vrm_alert_relay.net import Endpoint, HttpError
from vrm_alert_relay.providers._http import DELIVERED, FAILED, result_for_error

if TYPE_CHECKING:
    from vrm_alert_relay.config import Recipient, Secret
    from vrm_alert_relay.delivery.protocol import Message
    from vrm_alert_relay.net import SafeHttpClient

__all__ = ["DEFAULT_TITLE", "HomeAssistantNotifyProvider"]

DEFAULT_TITLE: Final = "VRM Alert Relay"
MAX_RESPONSE_BYTES: Final = 256 * 1024

_SERVICE_NAME: Final = TypeAdapter(HaServiceName)
_log = logging.getLogger(__name__)


class HomeAssistantNotifyProvider:
    """Calls ``notify.<service>`` on the configured Home Assistant instance."""

    def __init__(
        self,
        http: SafeHttpClient,
        *,
        base_url: str,
        token: Secret,
        title: str = DEFAULT_TITLE,
        registry: SecretRegistry | None = None,
    ) -> None:
        self._http = http
        self._base = Endpoint(base_url, allow_http=http.allow_insecure_http)
        self._token = token
        self._title = sanitize_text(title, 64)
        header = f"Bearer {token.reveal()}"
        if registry is None:
            register_secret(token.reveal())
            register_derived_secret(header)
        else:
            registry.register(token.reveal())
            registry.register(header)

    def __repr__(self) -> str:
        return f"HomeAssistantNotifyProvider({self._base.display!r})"

    def send(self, message: Message, recipient: Recipient) -> SendResult:
        if not isinstance(recipient, HomeAssistantRecipient):
            return self._outcome(message, FAILED, "wrong_recipient_type")
        try:
            service = _SERVICE_NAME.validate_python(recipient.service)
        except ValidationError:
            return self._outcome(message, FAILED, "invalid_service")
        endpoint = self._base.join("api", "services", "notify", service)
        payload = {"message": sanitize_text(message.text), "title": self._title}
        try:
            self._http.post(
                endpoint,
                json=payload,
                headers={"Authorization": f"Bearer {self._token.reveal()}"},
                max_response_bytes=MAX_RESPONSE_BYTES,
            )
        except HttpError as error:
            return self._outcome(message, result_for_error(error), type(error).__name__, service)
        return self._outcome(message, DELIVERED, "accepted", service)

    def _outcome(
        self, message: Message, result: SendResult, reason: str, service: str | None = None
    ) -> SendResult:
        _log.log(
            logging.INFO if result.status is SendStatus.DELIVERED else logging.WARNING,
            "home assistant notify %s",
            result.status.value,
            extra={
                "event": f"provider.{result.status.value}",
                "provider": "homeassistant",
                "delivery_id": message.delivery_id,
                "recipient": None if service is None else f"notify.{service}",
                "retryable": result.retryable,
                "reason": reason,
            },
        )
        return result

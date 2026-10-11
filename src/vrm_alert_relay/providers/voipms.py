"""The ``voipms`` provider: SMS through the VoIP.ms REST API.

Every call is one ``POST`` to the configured endpoint (default
``https://voip.ms/api/v1/rest.php``) with a ``multipart/form-data`` body that
carries the API username, API password, method and arguments. Credentials
never appear in a URL, so no URL can leak them; both are also registered with
the log redaction registry when the provider is built. A URL-encoded body is
not used because VoIP.ms answers it as SOAP.

VoIP.ms reports errors as HTTP 200 with a JSON ``status`` other than
``success``, so a message counts as delivered only when ``status`` is exactly
``success``. Statuses known to mean the message was refused are ``FAILED``
(retryable when the cause may be transient); an unrecognised status, an
unreadable body or a failure after the request was sent is ``AMBIGUOUS``.

:meth:`VoipmsSmsProvider.reconcile` looks an ambiguous attempt up with
``getSMS``: by the message ID when one is known, otherwise among messages
sent from the DID to the recipient in a window around the attempt with
exactly the text that was sent.
"""

from __future__ import annotations

import logging
import re
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final

from vrm_alert_relay.config import VoipmsRecipient
from vrm_alert_relay.config.models import DEFAULT_VOIPMS_BASE_URL
from vrm_alert_relay.delivery.protocol import ReconcileStatus, SendResult, SendStatus
from vrm_alert_relay.logs.redaction import SecretRegistry, register_secret
from vrm_alert_relay.net import Endpoint, HttpDecodeError, HttpError
from vrm_alert_relay.providers._http import (
    AMBIGUOUS,
    FAILED,
    FAILED_RETRYABLE,
    result_for_error,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from vrm_alert_relay.config import PhoneNumber, Recipient, Secret
    from vrm_alert_relay.delivery.protocol import Message, ReconcileQuery
    from vrm_alert_relay.net import SafeHttpClient

__all__ = [
    "MAX_SMS_CHARS",
    "NON_RETRYABLE_STATUSES",
    "RETRYABLE_STATUSES",
    "VoipmsSmsProvider",
    "sms_text",
]

MAX_SMS_CHARS: Final = 160
MAX_RESPONSE_BYTES: Final = 256 * 1024
RECONCILE_LIMIT: Final = 100
"""The most ``getSMS`` records requested, and examined, per lookup."""
RECONCILE_BEFORE: Final = timedelta(minutes=10)
RECONCILE_AFTER: Final = timedelta(hours=6)
"""A sent message matches an attempt when stamped within this window of it."""

NON_RETRYABLE_STATUSES: Final = frozenset(
    {
        "api_not_enabled",
        "invalid_credentials",
        "invalid_did",
        "invalid_dst",
        "invalid_method",
        "ip_not_enabled",
        "missing_credentials",
        "missing_did",
        "missing_dst",
        "missing_message",
        "missing_method",
        "sms_toolong",
    }
)
"""VoIP.ms statuses that mean the message was refused and will be again."""
RETRYABLE_STATUSES: Final = frozenset(
    {"api_limit_exceeded", "limit_reached", "method_maintenance", "sms_failed"}
)
"""VoIP.ms statuses that mean the message was refused for now."""

_TRIM_MARK: Final = "..."
_SUCCESS: Final = "success"
_NO_SMS: Final = "no_sms"
_MESSAGE_ID: Final = re.compile(r"[0-9]{1,20}")
_DATE_FORMAT: Final = "%Y-%m-%d %H:%M:%S"
_SENT_TYPE: Final = "0"

_log = logging.getLogger(__name__)


def sms_text(text: str) -> str:
    """Trim ``text`` to :data:`MAX_SMS_CHARS`, ending in ``...`` when trimmed.

    The marker is ASCII so that trimming alone never forces a non-GSM encoding.
    """
    if len(text) <= MAX_SMS_CHARS:
        return text
    return text[: MAX_SMS_CHARS - len(_TRIM_MARK)].rstrip() + _TRIM_MARK


def _message_id(value: object) -> str | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        value = str(value)
    if isinstance(value, str) and _MESSAGE_ID.fullmatch(value):
        return value
    return None


def _status_of(payload: object) -> str | None:
    if isinstance(payload, dict):
        status = payload.get("status")
        if isinstance(status, str):
            return status
    return None


def _known(status: str | None) -> str:
    """The status as logs may show it: response text is never logged as is."""
    if status is None:
        return "missing"
    if status == _SUCCESS or status in NON_RETRYABLE_STATUSES or status in RETRYABLE_STATUSES:
        return status
    return "unrecognized"


class VoipmsSmsProvider:
    """Sends SMS from the configured DID to :class:`VoipmsRecipient` numbers."""

    def __init__(  # noqa: PLR0913  # keyword-only collaborators and settings
        self,
        http: SafeHttpClient,
        *,
        username: Secret,
        password: Secret,
        did: PhoneNumber,
        base_url: str = DEFAULT_VOIPMS_BASE_URL,
        registry: SecretRegistry | None = None,
    ) -> None:
        if http.allow_insecure_http:
            raise ValueError("the VoIP.ms provider requires a client limited to https")  # noqa: TRY003  # message is specific to this check
        self._http = http
        self._endpoint = Endpoint(base_url)
        self._username = username
        self._password = password
        self._did = did
        for value in (username.reveal(), password.reveal()):
            if registry is None:
                register_secret(value)
            else:
                registry.register(value)

    def __repr__(self) -> str:
        return f"VoipmsSmsProvider({self._endpoint.display!r})"

    def _call(self, method: str, arguments: Mapping[str, str]) -> object:
        """POST one API call and return the parsed JSON body."""
        fields = {
            "api_username": self._username.reveal(),
            "api_password": self._password.reveal(),
            "method": method,
            **arguments,
        }
        response = self._http.post(
            self._endpoint, multipart=fields, max_response_bytes=MAX_RESPONSE_BYTES
        )
        return response.json()

    def send(self, message: Message, recipient: Recipient) -> SendResult:
        if not isinstance(recipient, VoipmsRecipient):
            self._log_outcome(message, FAILED, reason="wrong_recipient_type")
            return FAILED
        arguments = {
            "did": self._did.national,
            "dst": recipient.phone.national,
            "message": sms_text(message.text),
        }
        try:
            payload = self._call("sendSMS", arguments)
        except HttpDecodeError:
            result = AMBIGUOUS
            self._log_outcome(message, result, recipient, reason="malformed_response")
            return result
        except HttpError as error:
            result = result_for_error(error)
            self._log_outcome(message, result, recipient, reason=type(error).__name__)
            return result
        status = _status_of(payload)
        if status == _SUCCESS:
            message_id = _message_id(payload.get("sms")) if isinstance(payload, dict) else None
            result = SendResult(SendStatus.DELIVERED, provider_message_id=message_id)
        elif status in NON_RETRYABLE_STATUSES:
            result = FAILED
        elif status in RETRYABLE_STATUSES:
            result = FAILED_RETRYABLE
        else:
            result = AMBIGUOUS
        self._log_outcome(message, result, recipient, reason=_known(status))
        return result

    def reconcile(self, query: ReconcileQuery) -> ReconcileStatus:
        recipient = query.recipient
        if not isinstance(recipient, VoipmsRecipient):
            return ReconcileStatus.UNKNOWN
        known_id = _message_id(query.provider_message_id)
        arguments = {
            "did": self._did.national,
            "contact": recipient.phone.national,
            "type": _SENT_TYPE,
            "timezone": "0",
            "limit": str(RECONCILE_LIMIT),
        }
        if known_id is not None:
            arguments["sms"] = known_id
        else:
            attempted = query.attempted_at.astimezone(UTC)
            arguments["from"] = (attempted - RECONCILE_BEFORE).date().isoformat()
            arguments["to"] = (attempted + RECONCILE_AFTER).date().isoformat()
        try:
            payload = self._call("getSMS", arguments)
        except HttpError:
            return self._log_reconcile(query, ReconcileStatus.UNKNOWN, "lookup_failed")
        status = _status_of(payload)
        if status == _NO_SMS:
            # A message ID came from an accepted send, so its absence is not proof.
            outcome = ReconcileStatus.UNKNOWN if known_id else ReconcileStatus.NOT_DELIVERED
            return self._log_reconcile(query, outcome, "no_sms")
        records = payload.get("sms") if isinstance(payload, dict) else None
        if status != _SUCCESS or not isinstance(records, list):
            return self._log_reconcile(query, ReconcileStatus.UNKNOWN, _known(status))
        outcome = self._match(records[:RECONCILE_LIMIT], query, recipient, known_id)
        return self._log_reconcile(query, outcome, "lookup")

    def _match(
        self,
        records: list[object],
        query: ReconcileQuery,
        recipient: VoipmsRecipient,
        known_id: str | None,
    ) -> ReconcileStatus:
        expected = sms_text(query.message.text)
        attempted = query.attempted_at.astimezone(UTC)
        uncertain = False
        for record in records:
            if not isinstance(record, dict) or not self._same_route(record, recipient):
                continue
            if known_id is not None:
                if _message_id(record.get("id")) == known_id:
                    return ReconcileStatus.DELIVERED
                continue
            if record.get("message") != expected:
                continue
            sent_at = _parse_date(record.get("date"))
            if sent_at is None:
                uncertain = True
            elif attempted - RECONCILE_BEFORE <= sent_at <= attempted + RECONCILE_AFTER:
                return ReconcileStatus.DELIVERED
        if uncertain or known_id is not None:
            return ReconcileStatus.UNKNOWN
        return ReconcileStatus.NOT_DELIVERED

    def _same_route(self, record: Mapping[object, object], recipient: VoipmsRecipient) -> bool:
        return (
            str(record.get("did")) == self._did.national
            and str(record.get("contact")) == recipient.phone.national
            and str(record.get("type", _SENT_TYPE)) == _SENT_TYPE
        )

    def _log_outcome(
        self,
        message: Message,
        result: SendResult,
        recipient: VoipmsRecipient | None = None,
        *,
        reason: str,
    ) -> None:
        _log.log(
            logging.INFO if result.status is SendStatus.DELIVERED else logging.WARNING,
            "voip.ms sendSMS %s",
            result.status.value,
            extra={
                "event": f"provider.{result.status.value}",
                "provider": "voipms",
                "delivery_id": message.delivery_id,
                "recipient": None if recipient is None else f"sms:{recipient.phone.masked}",
                "retryable": result.retryable,
                "reason": reason,
            },
        )

    def _log_reconcile(
        self, query: ReconcileQuery, outcome: ReconcileStatus, reason: str
    ) -> ReconcileStatus:
        _log.info(
            "voip.ms getSMS lookup: %s",
            outcome.value,
            extra={
                "event": "provider.reconcile",
                "provider": "voipms",
                "delivery_id": query.message.delivery_id,
                "outcome": outcome.value,
                "reason": reason,
            },
        )
        return outcome


def _parse_date(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value, _DATE_FORMAT).replace(tzinfo=UTC)
    except ValueError:
        return None

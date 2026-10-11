"""Shared fictitious values and helpers for provider tests."""

from __future__ import annotations

import email.parser
import email.policy
import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

import httpx

from vrm_alert_relay.config import (
    HomeAssistantRecipient,
    LogRecipient,
    PhoneNumber,
    Secret,
    VoipmsRecipient,
    WebhookRecipient,
)
from vrm_alert_relay.delivery.protocol import Message

if TYPE_CHECKING:
    import logging

VOIPMS_USER = "fake-voipms-user@example.test"
VOIPMS_PASSWORD = "fake-voipms-api-pass-0000"  # noqa: S105  # fictitious test credential
HA_TOKEN = "fake-ha-long-lived-token-0000-not-real"  # noqa: S105  # fictitious test credential
WEBHOOK_SECRET = "fake-webhook-secret-0000"  # noqa: S105  # fictitious test credential
SECRETS = (VOIPMS_USER, VOIPMS_PASSWORD, HA_TOKEN, WEBHOOK_SECRET)

VOIPMS_URL = "https://voipms.example.test/api/v1/rest.php"
HA_URL = "https://ha.example.test:8123"
WEBHOOK_URL = "https://hooks.example.test/relay/fake-path-token-0000"

DID = PhoneNumber.parse("202-555-0100")
SMS = VoipmsRecipient(provider="voipms", phone=PhoneNumber.parse("+1 202 555 0142"))
HA = HomeAssistantRecipient(provider="homeassistant", service="mobile_app_example_phone")
HOOK = WebhookRecipient(provider="webhook")
LOG = LogRecipient(provider="log")

NOW = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
MESSAGE = Message(delivery_id="dlv_" + "0" * 32, text="critical: freezer at cabin: -3.5°C")

Handler = Callable[[httpx.Request], httpx.Response]


def secret(value: str) -> Secret:
    return Secret(value)


class StubTransport:
    """Replaces the client's real transport so no test can reach the network."""

    def __init__(self) -> None:
        self.handler: Handler | None = None
        self.requests: list[httpx.Request] = []

    def respond(self, handler: Handler) -> None:
        self.handler = handler

    def json(self, payload: Any, status: int = 200) -> None:
        self.respond(lambda _r: httpx.Response(status, json=payload))

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.handler is None:
            raise AssertionError("unexpected network request")
        response = self.handler(request)
        body = b"".join(response.stream)  # type: ignore[arg-type]
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            stream=UnreadStream(body),
            request=request,
        )


class UnreadStream(httpx.SyncByteStream):
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __iter__(self) -> Iterator[bytes]:
        yield self._body


def multipart_fields(request: httpx.Request) -> dict[str, str]:
    """Decode a multipart/form-data request body into its text fields."""
    head = f"Content-Type: {request.headers['content-type']}\r\n\r\n".encode()
    parsed = email.parser.BytesParser(policy=email.policy.default).parsebytes(
        head + request.content
    )
    fields: dict[str, str] = {}
    for part in parsed.iter_parts():
        name = part.get_param("name", header="content-disposition")
        payload = part.get_payload(decode=True)
        fields[str(name)] = payload.decode("utf-8") if isinstance(payload, bytes) else ""
    return fields


def json_body(request: httpx.Request) -> Any:
    return json.loads(request.content)


def assert_no_secrets(records: list[logging.LogRecord], *extra: object) -> None:
    """No secret appears in any log record (raw fields) or in ``extra`` objects."""
    texts = [repr(record.__dict__) + record.getMessage() for record in records]
    texts.extend(repr(item) + str(item) for item in extra)
    for text in texts:
        for value in SECRETS:
            assert value not in text
        assert "2025550142" not in text

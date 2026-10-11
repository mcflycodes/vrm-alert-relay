"""The webhook provider against a mocked receiver."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import TYPE_CHECKING

import httpx
import pytest
from provider_helpers import (
    HOOK,
    MESSAGE,
    NOW,
    SMS,
    WEBHOOK_SECRET,
    WEBHOOK_URL,
    StubTransport,
    assert_no_secrets,
    json_body,
    secret,
)
from pydantic import ValidationError

from vrm_alert_relay.delivery.protocol import Message, SendStatus
from vrm_alert_relay.net import InvalidUrlError
from vrm_alert_relay.providers import (
    PAYLOAD_VERSION,
    DetailedMessage,
    WebhookPostProvider,
    webhook_payload,
)
from vrm_alert_relay.templates import NotificationKind, TemplateFields

if TYPE_CHECKING:
    from vrm_alert_relay.logs.redaction import SecretRegistry
    from vrm_alert_relay.net import SafeHttpClient

FIELDS = TemplateFields(
    kind=NotificationKind.ESCALATED,
    rule="freezer",
    level="critical",
    value=-3.5,
    unit="°C",
    installation="cabin",
    measurement="tsT",
    label="Freezer",
    time=NOW,
)
KEYS = [
    "version",
    "source",
    "delivery_id",
    "kind",
    "rule",
    "level",
    "value",
    "unit",
    "installation",
    "measurement",
    "time",
    "text",
]


@pytest.fixture
def provider(http: SafeHttpClient, registry: SecretRegistry) -> WebhookPostProvider:
    return WebhookPostProvider(
        http,
        url=WEBHOOK_URL,
        auth_header=("X-Relay-Token", secret(WEBHOOK_SECRET)),
        registry=registry,
    )


def test_payload_with_fields() -> None:
    payload = webhook_payload(DetailedMessage(MESSAGE.delivery_id, MESSAGE.text, FIELDS))
    assert list(payload) == KEYS
    assert payload == {
        "version": PAYLOAD_VERSION,
        "source": "vrm-alert-relay",
        "delivery_id": MESSAGE.delivery_id,
        "kind": "escalated",
        "rule": "freezer",
        "level": "critical",
        "value": -3.5,
        "unit": "°C",
        "installation": "cabin",
        "measurement": "tsT",
        "time": "2026-01-15T12:00:00Z",
        "text": MESSAGE.text,
    }


def test_payload_without_fields_has_nulls() -> None:
    for message in (MESSAGE, DetailedMessage(MESSAGE.delivery_id, MESSAGE.text)):
        payload = webhook_payload(message)
        assert list(payload) == KEYS
        assert all(payload[key] is None for key in KEYS[3:-1])
        assert payload["text"] == MESSAGE.text


def test_payload_sanitizes_untrusted_values() -> None:
    fields = TemplateFields(
        kind=NotificationKind.REMINDER,
        unit="°C\n\x1b[2J",
        value=float("nan"),
        time=datetime(2026, 1, 15, 12, 0),  # naive on purpose
        rule="r" * 500,
    )
    payload = webhook_payload(DetailedMessage(MESSAGE.delivery_id, "line1\nline2\x07", fields))
    assert payload["unit"] == "°C [2J"
    assert payload["value"] is None
    assert payload["time"] is None
    assert isinstance(payload["rule"], str)
    assert len(payload["rule"]) == 64
    assert payload["text"] == "line1\nline2 "
    bool_value = TemplateFields(kind=NotificationKind.ESCALATED, value=True)
    assert webhook_payload(DetailedMessage("dlv_x", "t", bool_value))["value"] is None


def test_send_posts_payload_with_auth_header(
    provider: WebhookPostProvider, transport: StubTransport, caplog: pytest.LogCaptureFixture
) -> None:
    transport.respond(lambda _r: httpx.Response(204))
    with caplog.at_level(logging.DEBUG):
        result = provider.send(DetailedMessage(MESSAGE.delivery_id, MESSAGE.text, FIELDS), HOOK)
    assert result.status is SendStatus.DELIVERED
    (request,) = transport.requests
    assert str(request.url) == WEBHOOK_URL
    assert request.headers["x-relay-token"] == WEBHOOK_SECRET
    assert request.headers["content-type"] == "application/json"
    assert json_body(request)["rule"] == "freezer"
    record = next(r for r in caplog.records if r.name.endswith("webhook"))
    assert record.target == "https://hooks.example.test/[REDACTED]"  # type: ignore[attr-defined]
    assert_no_secrets(caplog.records, provider, result)
    assert all("fake-path-token" not in repr(r.__dict__) for r in caplog.records)


def test_send_without_auth_header(http: SafeHttpClient, transport: StubTransport) -> None:
    transport.json({"ok": True})
    provider = WebhookPostProvider(http, url=WEBHOOK_URL)
    assert provider.send(MESSAGE, HOOK).status is SendStatus.DELIVERED
    assert "x-relay-token" not in transport.requests[0].headers


def test_registers_the_header_value(
    provider: WebhookPostProvider, registry: SecretRegistry
) -> None:
    assert WEBHOOK_SECRET in registry.secrets


def test_registers_with_the_default_registry(
    http: SafeHttpClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []
    monkeypatch.setattr("vrm_alert_relay.providers.webhook.register_secret", seen.append)
    WebhookPostProvider(http, url=WEBHOOK_URL, auth_header=("X-Key", secret(WEBHOOK_SECRET)))
    assert seen == [WEBHOOK_SECRET]


@pytest.mark.parametrize("name", ["Bad Header", "Content-Length", "Host", "X-A\r\nX-B", ""])
def test_header_name_is_validated(http: SafeHttpClient, name: str) -> None:
    with pytest.raises(ValidationError) as caught:
        WebhookPostProvider(http, url=WEBHOOK_URL, auth_header=(name, secret(WEBHOOK_SECRET)))
    assert WEBHOOK_SECRET not in str(caught.value)


@pytest.mark.parametrize(
    ("http_status", "status", "retryable"),
    [
        (200, SendStatus.DELIVERED, False),
        (202, SendStatus.DELIVERED, False),
        (401, SendStatus.FAILED, False),
        (403, SendStatus.FAILED, False),
        (422, SendStatus.FAILED, False),
        (429, SendStatus.FAILED, True),
        (500, SendStatus.AMBIGUOUS, True),
        (308, SendStatus.FAILED, False),
    ],
)
def test_statuses(
    provider: WebhookPostProvider,
    transport: StubTransport,
    http_status: int,
    status: SendStatus,
    retryable: bool,
) -> None:
    transport.respond(
        lambda _r: httpx.Response(http_status, headers={"Location": "https://evil.example.test/"})
    )
    result = provider.send(MESSAGE, HOOK)
    assert (result.status, result.retryable) == (status, retryable)
    assert len(transport.requests) == 1


def test_timeout_is_ambiguous(provider: WebhookPostProvider, transport: StubTransport) -> None:
    def fail(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("fictitious")

    transport.respond(fail)
    assert provider.send(MESSAGE, HOOK).status is SendStatus.AMBIGUOUS


def test_other_recipient_types_are_refused(
    provider: WebhookPostProvider, transport: StubTransport
) -> None:
    assert provider.send(MESSAGE, SMS).status is SendStatus.FAILED
    assert transport.requests == []


def test_plain_http_needs_an_opted_in_client(
    http: SafeHttpClient, insecure_http: SafeHttpClient, transport: StubTransport
) -> None:
    with pytest.raises(InvalidUrlError):
        WebhookPostProvider(http, url="http://hooks.example.test/relay")
    transport.json({})
    provider = WebhookPostProvider(insecure_http, url="http://hooks.example.test/relay")
    assert provider.send(MESSAGE, HOOK).status is SendStatus.DELIVERED


def test_repr_hides_the_url_path(provider: WebhookPostProvider) -> None:
    assert repr(provider) == "WebhookPostProvider('https://hooks.example.test/[REDACTED]')"


def test_plain_message_is_accepted(provider: WebhookPostProvider, transport: StubTransport) -> None:
    transport.json({})
    provider.send(Message("dlv_plain", "hello"), HOOK)
    assert json_body(transport.requests[0])["kind"] is None

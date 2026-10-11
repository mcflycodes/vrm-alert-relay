"""The Home Assistant notify provider against a mocked Home Assistant API."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import httpx
import pytest
from provider_helpers import (
    HA,
    HA_TOKEN,
    HA_URL,
    MESSAGE,
    SMS,
    StubTransport,
    assert_no_secrets,
    json_body,
    secret,
)

from vrm_alert_relay.config import HomeAssistantRecipient
from vrm_alert_relay.delivery.protocol import (
    Message,
    Provider,
    ReconcilingProvider,
    SendStatus,
)
from vrm_alert_relay.net import InvalidUrlError
from vrm_alert_relay.providers import HomeAssistantNotifyProvider
from vrm_alert_relay.providers.homeassistant import DEFAULT_TITLE

if TYPE_CHECKING:
    from vrm_alert_relay.logs.redaction import SecretRegistry
    from vrm_alert_relay.net import SafeHttpClient


@pytest.fixture
def provider(http: SafeHttpClient, registry: SecretRegistry) -> HomeAssistantNotifyProvider:
    return HomeAssistantNotifyProvider(
        http, base_url=HA_URL, token=secret(HA_TOKEN), registry=registry
    )


def test_protocols(provider: HomeAssistantNotifyProvider) -> None:
    assert isinstance(provider, Provider)
    assert not isinstance(provider, ReconcilingProvider)


def test_send_calls_the_notify_service(
    provider: HomeAssistantNotifyProvider,
    transport: StubTransport,
    caplog: pytest.LogCaptureFixture,
) -> None:
    transport.json([], status=200)
    with caplog.at_level(logging.DEBUG):
        result = provider.send(MESSAGE, HA)
    assert result.status is SendStatus.DELIVERED
    assert result.provider_message_id is None
    (request,) = transport.requests
    assert request.method == "POST"
    assert str(request.url) == f"{HA_URL}/api/services/notify/mobile_app_example_phone"
    assert request.headers["authorization"] == f"Bearer {HA_TOKEN}"
    assert json_body(request) == {"message": MESSAGE.text, "title": DEFAULT_TITLE}
    record = next(r for r in caplog.records if r.name.endswith("homeassistant"))
    assert record.recipient == "notify.mobile_app_example_phone"  # type: ignore[attr-defined]
    assert_no_secrets(caplog.records, provider, result)


def test_base_url_path_prefix_is_kept(http: SafeHttpClient, transport: StubTransport) -> None:
    transport.json([])
    provider = HomeAssistantNotifyProvider(
        http, base_url="https://ha.example.test/prefix/", token=secret(HA_TOKEN), title="Cabin"
    )
    provider.send(MESSAGE, HA)
    assert transport.requests[0].url.path == "/prefix/api/services/notify/mobile_app_example_phone"
    assert json_body(transport.requests[0])["title"] == "Cabin"


def test_registers_token_and_header(
    provider: HomeAssistantNotifyProvider, registry: SecretRegistry
) -> None:
    assert registry.redact(f"Authorization: Bearer {HA_TOKEN}").count(HA_TOKEN) == 0
    assert {HA_TOKEN, f"Bearer {HA_TOKEN}"} <= set(registry.secrets)


def test_registers_with_the_default_registry(
    http: SafeHttpClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []
    module = "vrm_alert_relay.providers.homeassistant"
    monkeypatch.setattr(f"{module}.register_secret", seen.append)
    monkeypatch.setattr(f"{module}.register_derived_secret", seen.append)
    HomeAssistantNotifyProvider(http, base_url=HA_URL, token=secret(HA_TOKEN))
    assert seen == [HA_TOKEN, f"Bearer {HA_TOKEN}"]


@pytest.mark.parametrize(
    ("http_status", "status", "retryable"),
    [
        (201, SendStatus.DELIVERED, False),
        (401, SendStatus.FAILED, False),
        (403, SendStatus.FAILED, False),
        (400, SendStatus.FAILED, False),
        (404, SendStatus.FAILED, False),
        (408, SendStatus.FAILED, True),
        (429, SendStatus.FAILED, True),
        (500, SendStatus.AMBIGUOUS, True),
        (502, SendStatus.AMBIGUOUS, True),
        (301, SendStatus.FAILED, False),
        (307, SendStatus.FAILED, False),
    ],
)
def test_statuses(
    provider: HomeAssistantNotifyProvider,
    transport: StubTransport,
    http_status: int,
    status: SendStatus,
    retryable: bool,
) -> None:
    transport.respond(
        lambda _r: httpx.Response(http_status, headers={"Location": "https://evil.example.test/"})
    )
    result = provider.send(MESSAGE, HA)
    assert (result.status, result.retryable) == (status, retryable)
    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    ("error", "status"),
    [
        (httpx.ReadTimeout("fictitious"), SendStatus.AMBIGUOUS),
        (httpx.ConnectTimeout("fictitious"), SendStatus.FAILED),
        (httpx.ConnectError("fictitious"), SendStatus.FAILED),
    ],
)
def test_timeouts(
    provider: HomeAssistantNotifyProvider,
    transport: StubTransport,
    error: Exception,
    status: SendStatus,
) -> None:
    def fail(_request: httpx.Request) -> httpx.Response:
        raise error

    transport.respond(fail)
    result = provider.send(MESSAGE, HA)
    assert result.status is status
    assert result.retryable is True


def test_message_text_is_bounded(
    provider: HomeAssistantNotifyProvider, transport: StubTransport
) -> None:
    transport.json([])
    provider.send(Message(MESSAGE.delivery_id, "a\x00b" + "c" * 5000), HA)
    sent = json_body(transport.requests[0])["message"]
    assert sent.startswith("a b")
    assert len(sent) == 1000


def test_unvalidated_service_names_are_refused(
    provider: HomeAssistantNotifyProvider, transport: StubTransport
) -> None:
    forged = HomeAssistantRecipient.model_construct(provider="homeassistant", service="../../x")
    result = provider.send(MESSAGE, forged)
    assert (result.status, result.retryable) == (SendStatus.FAILED, False)
    assert transport.requests == []


def test_other_recipient_types_are_refused(
    provider: HomeAssistantNotifyProvider, transport: StubTransport
) -> None:
    assert provider.send(MESSAGE, SMS).status is SendStatus.FAILED
    assert transport.requests == []


def test_plain_http_needs_an_opted_in_client(
    http: SafeHttpClient, insecure_http: SafeHttpClient, transport: StubTransport
) -> None:
    with pytest.raises(InvalidUrlError):
        HomeAssistantNotifyProvider(http, base_url="http://ha.example.test", token=secret(HA_TOKEN))
    provider = HomeAssistantNotifyProvider(
        insecure_http, base_url="http://ha.example.test:8123", token=secret(HA_TOKEN)
    )
    transport.json([])
    assert provider.send(MESSAGE, HA).status is SendStatus.DELIVERED
    assert transport.requests[0].url.scheme == "http"


def test_repr_has_no_token(provider: HomeAssistantNotifyProvider) -> None:
    assert repr(provider) == f"HomeAssistantNotifyProvider('{HA_URL}/')"

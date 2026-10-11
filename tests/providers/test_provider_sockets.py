"""Providers built from configuration, end to end against servers on 127.0.0.1.

Exercises owner decision Q12: ``ca_file`` with a private (trustme) CA, and
``allow_insecure_http`` for plain-http receivers. Every value is fictitious.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING, Any

import pytest
import trustme
import yaml
from provider_helpers import HA, HA_TOKEN, HOOK, MESSAGE, secret

from local_server import LocalServer, http_response
from vrm_alert_relay.config import RelaySecrets, parse_config
from vrm_alert_relay.delivery.protocol import SendStatus
from vrm_alert_relay.providers import build_providers

if TYPE_CHECKING:
    from pathlib import Path

REAL_SOCKETS = True

Start = Callable[..., LocalServer]


@pytest.fixture(scope="module")
def ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture
def serve() -> Iterator[Start]:
    servers: list[LocalServer] = []

    def start(*args: Any, **kwargs: Any) -> LocalServer:
        server = LocalServer(*args, **kwargs)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def config(providers: dict[str, Any], recipients: dict[str, Any]) -> Any:
    data = {
        "version": 1,
        "sending": {"enabled": True},
        "vrm": {
            "token_file": "/run/secrets/vrm_token",
            "installations": [{"id": "cabin", "site_id": 123456}],
        },
        "recipients": recipients,
        "providers": providers,
    }
    return parse_config(yaml.safe_dump(data))


def body(request: bytes) -> Any:
    return json.loads(request.partition(b"\r\n\r\n")[2])


def test_home_assistant_with_private_ca(serve: Start, ca: trustme.CA, tmp_path: Path) -> None:
    pem = tmp_path / "ha-ca.pem"
    ca.cert_pem.write_to_path(str(pem))
    server = serve(lambda _r: http_response(200, b"[]"), ca=ca)
    relay = config(
        {
            "homeassistant": {
                "enabled": True,
                "base_url": server.url(""),
                "token_file": "/run/secrets/ha_token",
                "ca_file": str(pem),
            }
        },
        {"app": {"provider": "homeassistant", "service": "mobile_app_example_phone"}},
    )
    with build_providers(relay, RelaySecrets(homeassistant_token=secret(HA_TOKEN))) as built:
        result = built.providers["homeassistant"].send(MESSAGE, HA)
    assert result.status is SendStatus.DELIVERED
    (request,) = server.requests
    assert request.startswith(b"POST /api/services/notify/mobile_app_example_phone HTTP/1.1\r\n")
    assert f"\r\nAuthorization: Bearer {HA_TOKEN}\r\n".encode() in request
    assert body(request)["message"] == MESSAGE.text


def test_home_assistant_private_ca_without_ca_file_fails_closed(
    serve: Start, ca: trustme.CA
) -> None:
    server = serve(lambda _r: http_response(200, b"[]"), ca=ca)
    relay = config(
        {
            "homeassistant": {
                "enabled": True,
                "base_url": server.url(""),
                "token_file": "/run/secrets/ha_token",
            }
        },
        {"app": {"provider": "homeassistant", "service": "mobile_app_example_phone"}},
    )
    with build_providers(relay, RelaySecrets(homeassistant_token=secret(HA_TOKEN))) as built:
        result = built.providers["homeassistant"].send(MESSAGE, HA)
    assert (result.status, result.retryable) == (SendStatus.FAILED, True)
    assert server.requests == []


def test_webhook_over_plain_http_with_opt_in(serve: Start) -> None:
    server = serve(lambda _r: http_response(204, b""))
    relay = config(
        {"webhook": {"enabled": True, "url": server.url("/hook"), "allow_insecure_http": True}},
        {"hook": {"provider": "webhook"}},
    )
    with build_providers(relay, RelaySecrets()) as built:
        result = built.providers["webhook"].send(MESSAGE, HOOK)
    assert result.status is SendStatus.DELIVERED
    assert server.requests[0].startswith(b"POST /hook HTTP/1.1\r\n")
    assert body(server.requests[0])["delivery_id"] == MESSAGE.delivery_id


def test_webhook_redirect_is_refused_end_to_end(serve: Start) -> None:
    server = serve(lambda _r: http_response(302, b"", "Location: http://evil.example.test/"))
    relay = config(
        {"webhook": {"enabled": True, "url": server.url("/hook"), "allow_insecure_http": True}},
        {"hook": {"provider": "webhook"}},
    )
    with build_providers(relay, RelaySecrets()) as built:
        result = built.providers["webhook"].send(MESSAGE, HOOK)
    assert (result.status, result.retryable) == (SendStatus.FAILED, False)
    assert len(server.requests) == 1

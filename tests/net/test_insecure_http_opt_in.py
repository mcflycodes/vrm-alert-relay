"""Plain http is refused unless a client and its endpoint both opt in."""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import pytest

from vrm_alert_relay.net import Endpoint, InvalidUrlError, SafeHttpClient

if TYPE_CHECKING:
    from conftest import StubTransport


def test_endpoint_refuses_http_by_default() -> None:
    with pytest.raises(InvalidUrlError, match="must be https, not 'http'"):
        Endpoint("http://hooks.example.test/relay")


def test_endpoint_accepts_http_only_with_opt_in() -> None:
    endpoint = Endpoint("http://hooks.example.test/relay?token=fake-0000", allow_http=True)
    assert endpoint.scheme == "http"
    assert endpoint.display == "http://hooks.example.test/relay"
    assert endpoint.join("a b").display == "http://hooks.example.test/relay/a%20b"
    assert Endpoint("https://hooks.example.test/", allow_http=True).scheme == "https"


@pytest.mark.parametrize(
    ("url", "port"),
    [
        ("http://hooks.example.test:80/relay", None),
        ("http://hooks.example.test:8123/relay", 8123),
        ("http://hooks.example.test/relay", None),
    ],
)
def test_http_endpoint_ports(url: str, port: int | None) -> None:
    assert Endpoint(url, allow_http=True).port == port


def test_opt_in_never_widens_to_other_schemes() -> None:
    with pytest.raises(InvalidUrlError, match="must be https or http, not 'ftp'"):
        Endpoint("ftp://hooks.example.test/", allow_http=True)


def test_strict_client_refuses_an_http_endpoint_before_io(transport: StubTransport) -> None:
    endpoint = Endpoint("http://hooks.example.test/relay", allow_http=True)
    with SafeHttpClient() as client:
        assert client.allow_insecure_http is False
        with pytest.raises(InvalidUrlError, match="plain http is not allowed"):
            client.post(endpoint, json={})
        with pytest.raises(InvalidUrlError):
            client.get("http://hooks.example.test/relay")
    assert transport.requests == []


def test_opted_in_client_sends_http(transport: StubTransport) -> None:
    transport.respond(lambda request: httpx.Response(200, json={"ok": True}))
    with SafeHttpClient(allow_insecure_http=True) as client:
        assert client.get("http://hooks.example.test/relay").json() == {"ok": True}
        assert client.get("https://hooks.example.test/relay").status_code == 200
    assert [str(r.url) for r in transport.requests] == [
        "http://hooks.example.test/relay",
        "https://hooks.example.test/relay",
    ]


def test_opt_in_flag_must_be_a_real_bool() -> None:
    with pytest.raises(TypeError):
        SafeHttpClient(allow_insecure_http="yes")  # type: ignore[arg-type]

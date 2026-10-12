"""ca_file and plain-http clients against real servers on 127.0.0.1.

Every certificate is issued by a throwaway trustme CA.
"""

from __future__ import annotations

import ssl
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

import pytest
import trustme

from local_server import LocalServer, http_response
from vrm_alert_relay.net import (
    HttpRedirectRefused,
    HttpTimeout,
    HttpTooLarge,
    HttpTransportError,
    InvalidCaFileError,
    SafeHttpClient,
    Timeouts,
    load_ca_file,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

REAL_SOCKETS = True

Start = Callable[..., LocalServer]


@pytest.fixture(scope="module")
def ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture
def ca_pem(ca: trustme.CA, tmp_path: Path) -> str:
    path = tmp_path / "test-ca.pem"
    ca.cert_pem.write_to_path(str(path))
    return str(path)


@pytest.fixture
def serve() -> Iterator[Start]:
    servers: list[LocalServer] = []

    def start(*args: object, **kwargs: object) -> LocalServer:
        server = LocalServer(*args, **kwargs)  # type: ignore[arg-type]
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def ok(_request: bytes) -> bytes:
    return http_response(200, b'{"ok": true}', "Content-Type: application/json")


def test_load_ca_file_keeps_verification_on(ca_pem: str) -> None:
    context = load_ca_file(ca_pem)
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.cert_store_stats()["x509_ca"] == 1


@pytest.mark.parametrize("content", [None, b"", b"not a certificate\n", b"-----BEGIN CERT"])
def test_unusable_ca_file_is_rejected_without_detail(tmp_path: Path, content: bytes | None) -> None:
    path = tmp_path / "secret-looking-name.pem"
    if content is not None:
        path.write_bytes(content)
    with pytest.raises(InvalidCaFileError) as caught:
        load_ca_file(path)
    assert "secret-looking-name" not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    with pytest.raises(InvalidCaFileError):
        SafeHttpClient(ca_file=path)


def test_directory_is_not_a_ca_file(tmp_path: Path) -> None:
    with pytest.raises(InvalidCaFileError):
        load_ca_file(tmp_path)


def test_ca_file_trusts_a_private_ca(serve: Start, ca: trustme.CA, ca_pem: str) -> None:
    server = serve(ok, ca=ca)
    with SafeHttpClient(ca_file=ca_pem) as client:
        assert client.post(server.url("/api"), json={"a": 1}).json() == {"ok": True}
    assert server.requests[0].startswith(b"POST /api HTTP/1.1\r\n")


def test_without_ca_file_the_private_ca_is_untrusted(serve: Start, ca: trustme.CA) -> None:
    server = serve(ok, ca=ca)
    with SafeHttpClient() as client, pytest.raises(HttpTransportError) as caught:
        client.get(server.url())
    assert caught.value.cause == "ConnectError"


def test_ca_file_of_another_ca_is_rejected(serve: Start, ca: trustme.CA, tmp_path: Path) -> None:
    other = tmp_path / "other-ca.pem"
    trustme.CA().cert_pem.write_to_path(str(other))
    server = serve(ok, ca=ca)
    with SafeHttpClient(ca_file=other) as client, pytest.raises(HttpTransportError):
        client.get(server.url())


def test_ca_file_still_checks_the_hostname(serve: Start, ca: trustme.CA, ca_pem: str) -> None:
    server = serve(ok, ca=ca, hostname="other.example.test")
    with SafeHttpClient(ca_file=ca_pem) as client, pytest.raises(HttpTransportError):
        client.get(server.url())


def test_ca_file_refuses_redirects(serve: Start, ca: trustme.CA, ca_pem: str) -> None:
    server = serve(
        lambda _r: http_response(302, b"", "Location: https://evil.example.test/"), ca=ca
    )
    with SafeHttpClient(ca_file=ca_pem) as client, pytest.raises(HttpRedirectRefused):
        client.get(server.url())
    assert len(server.requests) == 1


def test_plain_http_with_opt_in(serve: Start) -> None:
    server = serve(ok)
    with SafeHttpClient(allow_insecure_http=True) as client:
        assert client.post(server.url("/hook"), json={}).json() == {"ok": True}
    assert server.requests[0].startswith(b"POST /hook HTTP/1.1\r\n")


def test_plain_http_keeps_redirect_refusal(serve: Start) -> None:
    server = serve(lambda _r: http_response(307, b"", "Location: http://evil.example.test/"))
    with SafeHttpClient(allow_insecure_http=True) as client, pytest.raises(HttpRedirectRefused):
        client.post(server.url(), json={})
    assert len(server.requests) == 1


def test_plain_http_keeps_the_size_cap(serve: Start) -> None:
    server = serve(lambda _r: http_response(200, b"x" * 5000))
    with (
        SafeHttpClient(allow_insecure_http=True, max_response_bytes=1000) as client,
        pytest.raises(HttpTooLarge),
    ):
        client.get(server.url())


def test_plain_http_keeps_the_deadline(serve: Start) -> None:
    server = serve(lambda _r: None)
    timeouts = Timeouts(connect=5.0, read=5.0, write=5.0, deadline=0.5)
    with SafeHttpClient(allow_insecure_http=True, timeouts=timeouts) as client:
        start = time.monotonic()
        with pytest.raises(HttpTimeout) as caught:
            client.get(server.url())
        elapsed = time.monotonic() - start
    assert caught.value.phase == "deadline"
    assert elapsed < 1.5

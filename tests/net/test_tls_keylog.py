"""TLS contexts never write session secrets to SSLKEYLOGFILE.

``ssl.create_default_context`` (and httpx's helper built on it) opens the
file that ``SSLKEYLOGFILE`` names; the client's contexts must not.
"""

from __future__ import annotations

import ssl
from collections.abc import Callable, Iterator
from typing import TYPE_CHECKING

import pytest
import trustme

from local_server import LocalServer, http_response
from vrm_alert_relay.net import HttpTransportError, SafeHttpClient, load_ca_file
from vrm_alert_relay.net import client as client_module

if TYPE_CHECKING:
    from pathlib import Path

REAL_SOCKETS = True


@pytest.fixture
def keylog(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "tls-keys.log"
    monkeypatch.setenv("SSLKEYLOGFILE", str(path))
    return path


@pytest.fixture(scope="module")
def ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture
def server(ca: trustme.CA) -> Iterator[LocalServer]:
    local = LocalServer(lambda _r: http_response(200, b"{}"), ca=ca)
    yield local
    local.close()


@pytest.fixture
def ca_pem(ca: trustme.CA, tmp_path: Path) -> str:
    path = tmp_path / "ca.pem"
    ca.cert_pem.write_to_path(str(path))
    return str(path)


Build = Callable[[], ssl.SSLContext]


def test_bundled_context_matches_the_verifying_defaults(keylog: Path) -> None:
    context = client_module._tls_context()
    assert context.verify_mode is ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert context.cert_store_stats()["x509_ca"] > 0
    assert context.keylog_filename is None
    assert not keylog.exists()


def test_custom_ca_context_has_no_key_log(keylog: Path, ca_pem: str) -> None:
    context = load_ca_file(ca_pem)
    assert context.keylog_filename is None
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert not keylog.exists()


def test_bundled_client_handshake_writes_no_key_log(keylog: Path, server: LocalServer) -> None:
    with SafeHttpClient() as client, pytest.raises(HttpTransportError):
        client.get(server.url())
    assert server.requests == []
    assert not keylog.exists()


def test_custom_ca_client_request_writes_no_key_log(
    keylog: Path, server: LocalServer, ca_pem: str
) -> None:
    with SafeHttpClient(ca_file=ca_pem) as client:
        assert client.get(server.url()).status_code == 200
    assert len(server.requests) == 1
    assert not keylog.exists()


def test_an_existing_key_log_is_left_untouched(
    keylog: Path, server: LocalServer, ca_pem: str
) -> None:
    keylog.write_text("")
    with SafeHttpClient(ca_file=ca_pem) as client:
        client.get(server.url())
    with SafeHttpClient() as client, pytest.raises(HttpTransportError):
        client.get(server.url())
    assert keylog.read_text() == ""


# Parity with the standard library's verifying defaults --------------------------


def test_contexts_match_create_default_context(
    monkeypatch: pytest.MonkeyPatch, ca_pem: str
) -> None:
    monkeypatch.delenv("SSLKEYLOGFILE", raising=False)
    pairs = (
        (client_module._tls_context(), ssl.create_default_context()),
        (load_ca_file(ca_pem), ssl.create_default_context(cafile=ca_pem)),
    )
    for ours, stdlib in pairs:
        assert ours.verify_flags == stdlib.verify_flags
        assert ours.verify_flags & ssl.VERIFY_X509_STRICT
        assert ours.verify_flags & ssl.VERIFY_X509_PARTIAL_CHAIN
        assert ours.options == stdlib.options
        assert ours.verify_mode == stdlib.verify_mode == ssl.CERT_REQUIRED
        assert ours.check_hostname is stdlib.check_hostname is True
        assert ours.minimum_version >= stdlib.minimum_version
        assert ours.keylog_filename is None


def test_intermediate_only_ca_file_is_a_trust_anchor(
    keylog: Path, ca: trustme.CA, tmp_path: Path
) -> None:
    intermediate = ca.create_child_ca()
    anchor = tmp_path / "intermediate-only.pem"
    intermediate.cert_pem.write_to_path(str(anchor))
    local = LocalServer(lambda _r: http_response(200, b"{}"), ca=intermediate)
    try:
        with SafeHttpClient(ca_file=anchor) as client:
            assert client.get(local.url()).status_code == 200
    finally:
        local.close()
    assert not keylog.exists()

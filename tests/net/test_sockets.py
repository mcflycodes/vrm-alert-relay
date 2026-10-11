"""End-to-end tests against TLS servers on 127.0.0.1 that genuinely block."""

from __future__ import annotations

import gzip
import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator

import pytest
import trustme

from vrm_alert_relay.net import (
    HttpContentEncodingRefused,
    HttpError,
    HttpTimeout,
    HttpTransportError,
    SafeHttpClient,
    Timeouts,
)
from vrm_alert_relay.net import client as client_module

REAL_SOCKETS = True
DEADLINE = 0.6
EPSILON = 0.4
DRIP_INTERVAL = 0.05
QUERY_CANARY = "fictitious-query-secret-0001"
REAL_TLS_CONTEXT = client_module._tls_context

Responder = Callable[[ssl.SSLSocket, threading.Event], bool]


def read_request(conn: ssl.SSLSocket) -> bytes | None:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk:
            return None
        data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    length = 0
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            length = int(value)
    while len(body) < length:
        chunk = conn.recv(65536)
        if not chunk:
            return None
        body += chunk
    return head + b"\r\n\r\n" + body


class Server:
    """A threaded server. With ``tls=False`` it accepts TCP and never speaks."""

    def __init__(
        self, ca: trustme.CA, responder: Responder, *, tls: bool = True
    ) -> None:
        self._context: ssl.SSLContext | None = None
        if tls:
            self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ca.issue_cert("localhost").configure_cert(self._context)
        self._responder = responder
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.1)
        self.port: int = self._listener.getsockname()[1]
        self.stop = threading.Event()
        self.requests: list[bytes] = []
        self.connections = 0
        self._threads = [threading.Thread(target=self._serve, daemon=True)]
        self._threads[0].start()

    @property
    def url(self) -> str:
        return f"https://localhost:{self.port}/api"

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue
            self.connections += 1
            thread = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            self._threads.append(thread)
            thread.start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5)
            if self._context is None:
                self.stop.wait(5)
                return
            with self._context.wrap_socket(conn, server_side=True) as tls:
                while not self.stop.is_set():
                    request = read_request(tls)
                    if request is None:
                        return
                    self.requests.append(request)
                    if not self._responder(tls, self.stop):
                        return
        except OSError:
            pass
        finally:
            conn.close()

    def close(self) -> None:
        self.stop.set()
        for thread in self._threads:
            thread.join(timeout=5)
        self._listener.close()


def respond(body: bytes, *extra_headers: str, keep_alive: bool = True) -> Responder:
    def responder(conn: ssl.SSLSocket, stop: threading.Event) -> bool:
        headers = [f"Content-Length: {len(body)}", *extra_headers]
        head = "HTTP/1.1 200 OK\r\n" + "".join(f"{h}\r\n" for h in headers) + "\r\n"
        conn.sendall(head.encode() + body)
        return keep_alive

    return responder


def drip(prefix: bytes) -> Responder:
    def responder(conn: ssl.SSLSocket, stop: threading.Event) -> bool:
        conn.sendall(prefix)
        while not stop.is_set():
            conn.sendall(b"a")
            stop.wait(DRIP_INTERVAL)
        return False

    return responder


@pytest.fixture(scope="module")
def ca() -> trustme.CA:
    return trustme.CA()


@pytest.fixture(autouse=True)
def trust_test_ca(ca: trustme.CA, monkeypatch: pytest.MonkeyPatch) -> None:
    def context() -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ca.configure_trust(ctx)
        return ctx

    monkeypatch.setattr(client_module, "_tls_context", context)


@pytest.fixture
def serve(ca: trustme.CA) -> Iterator[Callable[..., Server]]:
    servers: list[Server] = []

    def start(responder: Responder, *, tls: bool = True) -> Server:
        server = Server(ca, responder, tls=tls)
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.close()


def slow_client() -> SafeHttpClient:
    return SafeHttpClient(
        timeouts=Timeouts(connect=5.0, read=5.0, write=5.0, deadline=DEADLINE)
    )


def timed_failure(server: Server, error: type[HttpError]) -> tuple[HttpError, float]:
    with slow_client() as client:
        start = time.monotonic()
        with pytest.raises(error) as excinfo:
            client.get(f"{server.url}?token={QUERY_CANARY}")
        elapsed = time.monotonic() - start
    assert excinfo.value.__context__ is None
    assert excinfo.value.__cause__ is None
    assert QUERY_CANARY not in str(excinfo.value)
    return excinfo.value, elapsed


def test_request_over_tls(serve: Callable[..., Server]) -> None:
    server = serve(respond(b'{"ok": true}', "Content-Type: application/json"))
    with SafeHttpClient() as client:
        first = client.post(server.url, json={"message": "x" * 40_000})
        second = client.get(server.url, params={"page": 2})
    assert first.json() == {"ok": True}
    assert second.status_code == 200
    assert server.connections == 1
    assert server.requests[0].startswith(b"POST /api HTTP/1.1\r\n")
    assert b"accept-encoding: identity\r\n" in server.requests[0].lower()
    assert len(server.requests[0]) > 40_000
    assert server.requests[1].startswith(b"GET /api?page=2 HTTP/1.1\r\n")


def test_untrusted_certificate_rejected(
    serve: Callable[..., Server], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client_module, "_tls_context", REAL_TLS_CONTEXT)
    server = serve(respond(b"{}"))
    error, _ = timed_failure(server, HttpTransportError)
    assert isinstance(error, HttpTransportError)
    assert error.cause == "ConnectError"


def test_slow_drip_headers_stop_at_deadline(serve: Callable[..., Server]) -> None:
    server = serve(drip(b"HTTP/1.1 200 OK\r\nX-Drip: "))
    error, elapsed = timed_failure(server, HttpTimeout)
    assert isinstance(error, HttpTimeout)
    assert error.phase == "deadline"
    assert DEADLINE - 0.05 <= elapsed < DEADLINE + EPSILON


def test_slow_drip_body_stops_at_deadline(serve: Callable[..., Server]) -> None:
    server = serve(drip(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n"))
    error, elapsed = timed_failure(server, HttpTimeout)
    assert isinstance(error, HttpTimeout)
    assert error.phase == "deadline"
    assert DEADLINE - 0.05 <= elapsed < DEADLINE + EPSILON


def test_stalled_tls_handshake_stops_at_deadline(serve: Callable[..., Server]) -> None:
    server = serve(respond(b""), tls=False)
    error, elapsed = timed_failure(server, HttpTimeout)
    assert isinstance(error, HttpTimeout)
    assert error.phase == "deadline"
    assert DEADLINE - 0.05 <= elapsed < DEADLINE + EPSILON


def test_gzip_despite_identity_request_is_refused(serve: Callable[..., Server]) -> None:
    bomb = gzip.compress(b"\x00" * (32 * 1024 * 1024))
    server = serve(respond(bomb, "Content-Encoding: gzip"))
    timed_failure(server, HttpContentEncodingRefused)
    assert b"accept-encoding: identity\r\n" in server.requests[0].lower()


def test_truncated_body_is_a_transport_error(serve: Callable[..., Server]) -> None:
    def responder(conn: ssl.SSLSocket, stop: threading.Event) -> bool:
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort")
        return False

    error, _ = timed_failure(serve(responder), HttpTransportError)
    assert isinstance(error, HttpTransportError)
    assert error.cause == "RemoteProtocolError"


def test_connection_refused_is_a_transport_error() -> None:
    with socket.create_server(("127.0.0.1", 0)) as probe:
        port = probe.getsockname()[1]
    with SafeHttpClient() as client, pytest.raises(HttpTransportError) as excinfo:
        client.get(f"https://127.0.0.1:{port}/api?token={QUERY_CANARY}")
    assert excinfo.value.cause == "ConnectError"
    assert excinfo.value.__context__ is None
    assert QUERY_CANARY not in str(excinfo.value)

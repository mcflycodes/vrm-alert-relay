"""A tiny threaded HTTP(S) server on 127.0.0.1 for end-to-end client tests.

Each connection serves one request and is closed. ``responder`` receives the
raw request and returns the raw response bytes, or ``None`` to stall until the
server stops. Every certificate comes from a test-only ``trustme`` CA.
"""

from __future__ import annotations

import socket
import ssl
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import trustme

Responder = Callable[[bytes], bytes | None]


def read_request(conn: socket.socket) -> bytes | None:
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


def http_response(
    status: int = 200, body: bytes = b"{}", *headers: str, reason: str = "OK"
) -> bytes:
    lines = [f"HTTP/1.1 {status} {reason}", f"Content-Length: {len(body)}", "Connection: close"]
    lines.extend(headers)
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


class LocalServer:
    """Serves ``responder`` over TLS (certificate for ``hostname``) or plain HTTP."""

    def __init__(
        self,
        responder: Responder,
        *,
        ca: trustme.CA | None = None,
        hostname: str = "localhost",
    ) -> None:
        self._context: ssl.SSLContext | None = None
        if ca is not None:
            self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ca.issue_cert(hostname).configure_cert(self._context)
        self._responder = responder
        self._listener = socket.create_server(("127.0.0.1", 0))
        self._listener.settimeout(0.1)
        self.port: int = self._listener.getsockname()[1]
        self.stop = threading.Event()
        self.requests: list[bytes] = []
        self._threads = [threading.Thread(target=self._serve, daemon=True)]
        self._threads[0].start()

    def url(self, path: str = "/") -> str:
        scheme = "http" if self._context is None else "https"
        return f"{scheme}://localhost:{self.port}{path}"

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue
            thread = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            self._threads.append(thread)
            thread.start()

    def _handle(self, conn: socket.socket) -> None:
        stream: socket.socket = conn
        try:
            conn.settimeout(5)
            if self._context is not None:
                stream = self._context.wrap_socket(conn, server_side=True)
            request = read_request(stream)
            if request is not None:
                self.requests.append(request)
                response = self._responder(request)
                if response is None:
                    self.stop.wait(5)
                else:
                    stream.sendall(response)
        except OSError:
            pass
        finally:
            stream.close()
            conn.close()

    def close(self) -> None:
        self.stop.set()
        for thread in self._threads:
            thread.join(timeout=5)
        self._listener.close()

"""HTTPS transport that enforces an absolute per-request deadline.

httpx's timeouts apply to each socket operation, so a peer that drips bytes
just inside the read timeout can hold a request open indefinitely. This
transport plugs a network backend into httpcore whose connect, TLS handshake,
read and write calls are each limited to the time remaining before the
deadline set by :func:`deadline_scope`. A blocked read is interrupted by the
socket timeout itself, not by sampling the clock between chunks.

Only public httpx and httpcore APIs are used.
"""

from __future__ import annotations

import contextvars
import ssl
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from time import monotonic
from typing import Any, Final, cast

import httpcore
import httpx

_WRITE_CHUNK: Final = 16 * 1024
_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "vrm_alert_relay_http_deadline", default=None
)
_EXCEPTIONS: Final[tuple[tuple[type[Exception], type[httpx.TransportError]], ...]] = (
    (httpcore.ConnectTimeout, httpx.ConnectTimeout),
    (httpcore.ReadTimeout, httpx.ReadTimeout),
    (httpcore.WriteTimeout, httpx.WriteTimeout),
    (httpcore.PoolTimeout, httpx.PoolTimeout),
    (httpcore.TimeoutException, httpx.TimeoutException),
    (httpcore.ConnectError, httpx.ConnectError),
    (httpcore.ReadError, httpx.ReadError),
    (httpcore.WriteError, httpx.WriteError),
    (httpcore.NetworkError, httpx.NetworkError),
    (httpcore.RemoteProtocolError, httpx.RemoteProtocolError),
    (httpcore.LocalProtocolError, httpx.LocalProtocolError),
    (httpcore.ProtocolError, httpx.ProtocolError),
    (httpcore.ProxyError, httpx.ProxyError),
    (httpcore.UnsupportedProtocol, httpx.UnsupportedProtocol),
)
_CAUGHT: Final = tuple(core for core, _ in _EXCEPTIONS)


@contextmanager
def deadline_scope(deadline: float) -> Iterator[None]:
    """Limit every socket operation in this context to end by ``deadline``.

    ``deadline`` is a :func:`time.monotonic` timestamp.
    """
    token = _DEADLINE.set(deadline)
    try:
        yield
    finally:
        _DEADLINE.reset(token)


def remaining_time() -> float | None:
    """Seconds left before the current deadline, or None outside a scope."""
    deadline = _DEADLINE.get()
    return None if deadline is None else deadline - monotonic()


def _bounded(
    timeout: float | None, exc_type: type[httpcore.TimeoutException]
) -> float | None:
    remaining = remaining_time()
    if remaining is None:
        return timeout
    if remaining <= 0:
        raise exc_type("request deadline exceeded")
    return remaining if timeout is None else min(timeout, remaining)


class _DeadlineStream(httpcore.NetworkStream):
    def __init__(self, inner: httpcore.NetworkStream) -> None:
        self._inner = inner

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._inner.read(max_bytes, _bounded(timeout, httpcore.ReadTimeout))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        for start in range(0, len(buffer), _WRITE_CHUNK):
            chunk = buffer[start : start + _WRITE_CHUNK]
            self._inner.write(chunk, _bounded(timeout, httpcore.WriteTimeout))

    def close(self) -> None:
        self._inner.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        bounded = _bounded(timeout, httpcore.ConnectTimeout)
        return _DeadlineStream(
            self._inner.start_tls(ssl_context, server_hostname, bounded)
        )

    def get_extra_info(self, info: str) -> Any:
        return self._inner.get_extra_info(info)


class _DeadlineBackend(httpcore.NetworkBackend):
    def __init__(self) -> None:
        self._inner = httpcore.SyncBackend()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        bounded = _bounded(timeout, httpcore.ConnectTimeout)
        stream = self._inner.connect_tcp(
            host, port, bounded, local_address, socket_options
        )
        return _DeadlineStream(stream)


@contextmanager
def _map_exceptions(request: httpx.Request) -> Iterator[None]:
    try:
        yield
    except _CAUGHT as exc:
        httpx_type = next(
            mapped for core, mapped in _EXCEPTIONS if isinstance(exc, core)
        )
        raise httpx_type(type(exc).__name__, request=request) from None


class _ResponseStream(httpx.SyncByteStream):
    def __init__(self, stream: Iterable[bytes], request: httpx.Request) -> None:
        self._stream = stream
        self._request = request

    def __iter__(self) -> Iterator[bytes]:
        with _map_exceptions(self._request):
            yield from self._stream

    def close(self) -> None:
        close = getattr(self._stream, "close", None)
        if callable(close):
            close()


class HardenedTransport(httpx.BaseTransport):
    """HTTP/1.1 connection pool over :class:`_DeadlineBackend`, with no proxy support."""

    def __init__(
        self, *, ssl_context: ssl.SSLContext, limits: httpx.Limits | None = None
    ) -> None:
        limits = limits if limits is not None else httpx.Limits()
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            http1=True,
            http2=False,
            network_backend=_DeadlineBackend(),
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        with _map_exceptions(request):
            timeouts = dict(request.extensions.get("timeout", {}))
            timeouts["pool"] = _bounded(timeouts.get("pool"), httpcore.PoolTimeout)
            core_request = httpcore.Request(
                method=request.method,
                url=httpcore.URL(
                    scheme=request.url.raw_scheme,
                    host=request.url.raw_host,
                    port=request.url.port,
                    target=request.url.raw_path,
                ),
                headers=request.headers.raw,
                content=cast(Iterable[bytes], request.stream),
                extensions={**request.extensions, "timeout": timeouts},
            )
            core_response = self._pool.handle_request(core_request)
        return httpx.Response(
            status_code=core_response.status,
            headers=core_response.headers,
            stream=_ResponseStream(
                cast(Iterable[bytes], core_response.stream), request
            ),
            extensions=core_response.extensions,
        )

    def close(self) -> None:
        self._pool.close()

"""HTTPS transport that enforces an absolute per-request deadline.

httpx's timeouts apply to each socket operation, so a peer that drips bytes
just inside the read timeout can hold a request open indefinitely. This
transport owns the socket layer under httpcore's connection pool and limits
every step to the time remaining before the deadline set by
:func:`deadline_scope`:

- name resolution runs on a small per-transport thread pool and is abandoned
  when the deadline passes; when every worker is busy the request fails at
  once instead of queueing (:class:`DnsTimeout`);
- resolved addresses are tried in order, each connect attempt getting only
  the time still remaining;
- the TLS handshake, every ``recv`` and every partial ``send`` recompute the
  remaining time, so a blocked call is interrupted by the socket timeout
  itself rather than by sampling the clock between chunks.

The hostname, not the resolved address, is still used for the ``Host``
header, SNI and certificate verification. Only public httpx and httpcore
APIs are used.
"""

from __future__ import annotations

import contextvars
import ipaddress
import selectors
import socket
import ssl
import threading
from collections.abc import Callable, Iterable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from time import monotonic
from typing import Any, Final, cast

import httpcore
import httpx

DNS_WORKERS: Final = 2

AddressInfo = tuple[int, int, int, str, tuple[Any, ...]]
"""One :func:`socket.getaddrinfo` result: family, type, proto, canonname, sockaddr."""
Resolver = Callable[[str, int], Sequence[AddressInfo]]
SocketFactory = Callable[[int, int, int], socket.socket]

_DEADLINE: contextvars.ContextVar[float | None] = contextvars.ContextVar(
    "vrm_alert_relay_http_deadline", default=None
)


class DnsTimeout(httpx.ConnectTimeout):
    """Name resolution outlived the deadline, or every resolver worker was busy."""


class _CoreDnsTimeout(httpcore.ConnectTimeout):
    pass


_EXCEPTIONS: Final[tuple[tuple[type[Exception], type[httpx.TransportError]], ...]] = (
    (_CoreDnsTimeout, DnsTimeout),
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
    """Limit every network operation in this context to end by ``deadline``.

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


@contextmanager
def _socket_errors(
    timeout_type: type[httpcore.TimeoutException],
    error_type: type[httpcore.NetworkError],
) -> Iterator[None]:
    try:
        yield
    except TimeoutError:
        raise timeout_type("socket operation timed out") from None
    except OSError as exc:
        raise error_type(type(exc).__name__) from None


def _is_readable(sock: socket.socket) -> bool:
    if sock.fileno() == -1:
        return True
    with selectors.DefaultSelector() as selector:
        selector.register(sock, selectors.EVENT_READ)
        return bool(selector.select(0))


class _SocketStream(httpcore.NetworkStream):
    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        with _socket_errors(httpcore.ReadTimeout, httpcore.ReadError):
            self._sock.settimeout(_bounded(timeout, httpcore.ReadTimeout))
            return self._sock.recv(max_bytes)

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        view = memoryview(buffer)
        with _socket_errors(httpcore.WriteTimeout, httpcore.WriteError):
            while view:
                self._sock.settimeout(_bounded(timeout, httpcore.WriteTimeout))
                view = view[self._sock.send(view) :]

    def close(self) -> None:
        self._sock.close()

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        try:
            with _socket_errors(httpcore.ConnectTimeout, httpcore.ConnectError):
                self._sock.settimeout(_bounded(timeout, httpcore.ConnectTimeout))
                sock = ssl_context.wrap_socket(
                    self._sock, server_hostname=server_hostname
                )
        except BaseException:
            self._sock.close()
            raise
        return _SocketStream(sock)

    def get_extra_info(self, info: str) -> Any:
        if info == "ssl_object":
            return self._sock if isinstance(self._sock, ssl.SSLSocket) else None
        if info == "client_addr":
            return self._sock.getsockname()
        if info == "server_addr":
            return self._sock.getpeername()
        if info == "socket":
            return self._sock
        if info == "is_readable":
            return _is_readable(self._sock)
        return None


def _system_resolver(host: str, port: int) -> Sequence[AddressInfo]:
    return socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)


def _system_socket(family: int, kind: int, proto: int) -> socket.socket:
    return socket.socket(family, kind, proto)


def _ip_literal(host: str, port: int) -> Sequence[AddressInfo] | None:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None
    return socket.getaddrinfo(
        host.strip("[]"), port, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST
    )


class _BoundedResolver:
    """Runs lookups on at most ``DNS_WORKERS`` threads and never queues them.

    A lookup that outlives its deadline keeps its worker until the resolver
    returns, so stalled lookups can occupy at most ``DNS_WORKERS`` threads;
    while they do, new lookups fail immediately.
    """

    def __init__(self, resolve: Resolver) -> None:
        self._resolve = resolve
        self._slots = threading.BoundedSemaphore(DNS_WORKERS)
        self._executor = ThreadPoolExecutor(
            max_workers=DNS_WORKERS, thread_name_prefix="vrm-alert-relay-dns"
        )

    def lookup(
        self, host: str, port: int, timeout: float | None
    ) -> Sequence[AddressInfo]:
        wait = _bounded(timeout, httpcore.ConnectTimeout)
        literal = _ip_literal(host, port)
        if literal is not None:
            return literal
        if not self._slots.acquire(blocking=False):
            raise _CoreDnsTimeout("all resolver workers are busy")
        try:
            future = self._executor.submit(self._run, host, port)
        except RuntimeError:
            self._slots.release()
            raise httpcore.ConnectError("resolver is closed") from None
        try:
            return future.result(timeout=wait)
        except TimeoutError:
            raise _CoreDnsTimeout("name resolution timed out") from None
        except (OSError, UnicodeError) as exc:
            raise httpcore.ConnectError(type(exc).__name__) from None

    def _run(self, host: str, port: int) -> Sequence[AddressInfo]:
        try:
            return list(self._resolve(host, port))
        finally:
            self._slots.release()

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


class _DeadlineBackend(httpcore.NetworkBackend):
    def __init__(
        self, resolver: _BoundedResolver, socket_factory: SocketFactory
    ) -> None:
        self._resolver = resolver
        self._socket_factory = socket_factory

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> httpcore.NetworkStream:
        options = list(socket_options or ())
        error: httpcore.ConnectError | httpcore.ConnectTimeout = httpcore.ConnectError(
            "name resolved to no addresses"
        )
        for family, kind, proto, _, sockaddr in self._resolver.lookup(
            host, port, timeout
        ):
            attempt = _bounded(timeout, httpcore.ConnectTimeout)
            try:
                with _socket_errors(httpcore.ConnectTimeout, httpcore.ConnectError):
                    sock = self._socket_factory(family, kind, proto)
            except httpcore.ConnectError as exc:
                error = exc
                continue
            try:
                with _socket_errors(httpcore.ConnectTimeout, httpcore.ConnectError):
                    sock.settimeout(attempt)
                    for option in options:
                        sock.setsockopt(*option)
                    if local_address is not None:
                        sock.bind((local_address, 0))
                    sock.connect(sockaddr)
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                sock.close()
                error = exc
                continue
            return _SocketStream(sock)
        raise error


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
    """HTTP/1.1 connection pool over :class:`_DeadlineBackend`, with no proxy support.

    ``resolver`` and ``socket_factory`` default to :func:`socket.getaddrinfo`
    and :class:`socket.socket`.
    """

    def __init__(
        self,
        *,
        ssl_context: ssl.SSLContext,
        limits: httpx.Limits | None = None,
        resolver: Resolver | None = None,
        socket_factory: SocketFactory | None = None,
    ) -> None:
        limits = limits if limits is not None else httpx.Limits()
        self._resolver = _BoundedResolver(resolver or _system_resolver)
        self._pool = httpcore.ConnectionPool(
            ssl_context=ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            http1=True,
            http2=False,
            network_backend=_DeadlineBackend(
                self._resolver, socket_factory or _system_socket
            ),
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
        self._resolver.close()

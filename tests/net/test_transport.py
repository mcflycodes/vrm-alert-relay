from __future__ import annotations

import ssl
from collections.abc import Iterator
from time import monotonic
from typing import Any

import httpcore
import httpx
import pytest

from vrm_alert_relay.net import transport as transport_module
from vrm_alert_relay.net.transport import (
    HardenedTransport,
    deadline_scope,
    remaining_time,
)

# Uses the real transport class; nothing here opens a connection.
REAL_SOCKETS = True


class RecordingStream(httpcore.NetworkStream):
    def __init__(self) -> None:
        self.calls: list[tuple[str, Any, float | None]] = []
        self.closed = False

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        self.calls.append(("read", max_bytes, timeout))
        return b"data"

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self.calls.append(("write", len(buffer), timeout))

    def close(self) -> None:
        self.closed = True

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        self.calls.append(("start_tls", server_hostname, timeout))
        return RecordingStream()

    def get_extra_info(self, info: str) -> Any:
        return f"info:{info}"


def test_bounded_outside_scope_keeps_timeout() -> None:
    assert remaining_time() is None
    assert transport_module._bounded(5.0, httpcore.ReadTimeout) == 5.0
    assert transport_module._bounded(None, httpcore.ReadTimeout) is None


def test_bounded_inside_scope_uses_remaining_time() -> None:
    with deadline_scope(monotonic() + 1.0):
        remaining = remaining_time()
        assert remaining is not None
        assert 0.9 < remaining <= 1.0
        assert transport_module._bounded(5.0, httpcore.ReadTimeout) <= 1.0  # type: ignore[operator]
        assert transport_module._bounded(0.2, httpcore.ReadTimeout) == 0.2
        bounded_none = transport_module._bounded(None, httpcore.ReadTimeout)
        assert bounded_none is not None
        assert bounded_none <= 1.0
    assert remaining_time() is None


@pytest.mark.parametrize(
    "exc_type", [httpcore.ReadTimeout, httpcore.WriteTimeout, httpcore.ConnectTimeout]
)
def test_bounded_raises_after_deadline(
    exc_type: type[httpcore.TimeoutException],
) -> None:
    with deadline_scope(monotonic() - 0.01), pytest.raises(exc_type):
        transport_module._bounded(5.0, exc_type)


def test_deadline_stream_bounds_every_operation() -> None:
    inner = RecordingStream()
    stream = transport_module._DeadlineStream(inner)
    with deadline_scope(monotonic() + 1.0):
        assert stream.read(10, 5.0) == b"data"
        stream.write(b"x" * (40 * 1024), 5.0)
        stream.write(b"", 5.0)
        tls = stream.start_tls(ssl.create_default_context(), "example.com", 5.0)
    assert isinstance(tls, transport_module._DeadlineStream)
    assert [call[:2] for call in inner.calls] == [
        ("read", 10),
        ("write", 16384),
        ("write", 16384),
        ("write", 8192),
        ("start_tls", "example.com"),
    ]
    assert all(call[2] is not None and call[2] <= 1.0 for call in inner.calls)
    assert stream.get_extra_info("socket") == "info:socket"
    stream.close()
    assert inner.closed


def test_deadline_stream_refuses_io_after_deadline() -> None:
    stream = transport_module._DeadlineStream(RecordingStream())
    with deadline_scope(monotonic() - 1.0):
        with pytest.raises(httpcore.ReadTimeout):
            stream.read(10, 5.0)
        with pytest.raises(httpcore.WriteTimeout):
            stream.write(b"x", 5.0)
        with pytest.raises(httpcore.ConnectTimeout):
            stream.start_tls(ssl.create_default_context(), "example.com", 5.0)


def test_backend_bounds_connect(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[float | None] = []

    def connect_tcp(
        self: httpcore.SyncBackend,
        host: str,
        port: int,
        timeout: float | None = None,
        *args: Any,
    ) -> httpcore.NetworkStream:
        seen.append(timeout)
        return RecordingStream()

    monkeypatch.setattr(httpcore.SyncBackend, "connect_tcp", connect_tcp)
    backend = transport_module._DeadlineBackend()
    with deadline_scope(monotonic() + 1.0):
        stream = backend.connect_tcp("example.com", 443, timeout=5.0)
    assert isinstance(stream, transport_module._DeadlineStream)
    assert seen[0] is not None and seen[0] <= 1.0
    with deadline_scope(monotonic() - 1.0), pytest.raises(httpcore.ConnectTimeout):
        backend.connect_tcp("example.com", 443, timeout=5.0)


@pytest.mark.parametrize(("core_type", "httpx_type"), transport_module._EXCEPTIONS)
def test_httpcore_exceptions_are_mapped(
    core_type: type[Exception], httpx_type: type[httpx.TransportError]
) -> None:
    request = httpx.Request("GET", "https://example.com/?token=x")
    with (
        pytest.raises(httpx_type) as excinfo,
        transport_module._map_exceptions(request),
    ):
        raise core_type("https://example.com/?token=x")
    assert type(excinfo.value) is httpx_type
    assert "token" not in str(excinfo.value)
    assert excinfo.value.request is request


def test_unrelated_exceptions_pass_through() -> None:
    request = httpx.Request("GET", "https://example.com/")
    with pytest.raises(KeyError), transport_module._map_exceptions(request):
        raise KeyError("x")


def test_response_stream_maps_errors_and_closes() -> None:
    request = httpx.Request("GET", "https://example.com/")

    class Failing:
        closed = False

        def __iter__(self) -> Iterator[bytes]:
            yield b"part"
            raise httpcore.ReadError("reset")

        def close(self) -> None:
            self.closed = True

    failing = Failing()
    stream = transport_module._ResponseStream(failing, request)
    with pytest.raises(httpx.ReadError):
        list(stream)
    stream.close()
    assert failing.closed
    transport_module._ResponseStream([b"a"], request).close()


def test_pool_wait_bounded_by_deadline() -> None:
    transport = HardenedTransport(ssl_context=ssl.create_default_context())
    request = httpx.Request(
        "GET", "https://example.invalid/", extensions={"timeout": {}}
    )
    with deadline_scope(monotonic() - 1.0), pytest.raises(httpx.PoolTimeout):
        transport.handle_request(request)
    transport.close()

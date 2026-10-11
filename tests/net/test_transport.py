from __future__ import annotations

import os
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from time import monotonic
from typing import Any, cast

import httpcore
import httpx
import pytest

from vrm_alert_relay.net import HttpTimeout, SafeHttpClient, Timeouts
from vrm_alert_relay.net import client as client_module
from vrm_alert_relay.net import transport as transport_module
from vrm_alert_relay.net.transport import (
    DNS_WORKERS,
    AddressInfo,
    DnsTimeout,
    HardenedTransport,
    deadline_scope,
    remaining_time,
)

# Uses the real transport class over fakes; nothing here leaves the process.
REAL_SOCKETS = True
EPSILON = 0.1
TEST_NET = ("192.0.2.10", 443)
QUERY_CANARY = "fictitious-query-secret-0003"
DNS_TIMEOUT = transport_module._CoreDnsTimeout


def address(sockaddr: tuple[str, int] = TEST_NET) -> AddressInfo:
    return (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)


class FakeSocket:
    """Socket-compatible fake whose blocking calls sleep, up to the socket timeout."""

    def __init__(
        self,
        *,
        connect_delay: float = 0.0,
        connect_error: OSError | None = None,
        send_delay: float = 0.0,
        send_size: int | None = None,
        send_error: OSError | None = None,
        recv_error: OSError | None = None,
    ) -> None:
        self.connect_delay = connect_delay
        self.connect_error = connect_error
        self.send_delay = send_delay
        self.send_size = send_size
        self.send_error = send_error
        self.recv_error = recv_error
        self.timeout: float | None = None
        self.timeouts: list[float | None] = []
        self.options: list[tuple[Any, ...]] = []
        self.bound: tuple[str, int] | None = None
        self.connected: tuple[Any, ...] | None = None
        self.sent = bytearray()
        self.sends = 0
        self.closed = False

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout
        self.timeouts.append(timeout)

    def _block(self, delay: float) -> None:
        if self.timeout is not None and self.timeout < delay:
            time.sleep(self.timeout)
            raise TimeoutError
        time.sleep(delay)

    def setsockopt(self, *option: Any) -> None:
        self.options.append(option)

    def bind(self, sockaddr: tuple[str, int]) -> None:
        self.bound = sockaddr

    def connect(self, sockaddr: tuple[Any, ...]) -> None:
        self._block(self.connect_delay)
        if self.connect_error is not None:
            raise self.connect_error
        self.connected = sockaddr

    def send(self, data: memoryview) -> int:
        self._block(self.send_delay)
        if self.send_error is not None:
            raise self.send_error
        size = len(data) if self.send_size is None else min(self.send_size, len(data))
        self.sent += data[:size]
        self.sends += 1
        return size

    def recv(self, max_bytes: int) -> bytes:
        if self.recv_error is not None:
            raise self.recv_error
        return b"data"[:max_bytes]

    def close(self) -> None:
        self.closed = True


class FakeTlsContext:
    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error
        self.calls: list[tuple[str | None, float | None]] = []

    def set_alpn_protocols(self, protocols: list[str]) -> None:
        pass

    def wrap_socket(
        self, sock: FakeSocket, server_hostname: str | None = None
    ) -> FakeSocket:
        self.calls.append((server_hostname, sock.timeout))
        if self.error is not None:
            raise self.error
        return sock


class Factory:
    def __init__(self, *sockets: FakeSocket | OSError) -> None:
        self._queue = list(sockets)
        self.created: list[FakeSocket] = []

    def __call__(self, family: int, kind: int, proto: int) -> socket.socket:
        item = self._queue.pop(0) if self._queue else FakeSocket()
        if isinstance(item, OSError):
            raise item
        self.created.append(item)
        return cast(socket.socket, item)


def stream_over(sock: FakeSocket) -> transport_module._SocketStream:
    return transport_module._SocketStream(cast(socket.socket, sock))


@pytest.fixture
def release() -> Iterator[threading.Event]:
    event = threading.Event()
    yield event
    event.set()


def stalled_resolver(
    release: threading.Event,
) -> Callable[[str, int], Sequence[AddressInfo]]:
    def resolve(host: str, port: int) -> Sequence[AddressInfo]:
        release.wait(5)
        return [address()]

    return resolve


# Deadline arithmetic


def test_bounded_outside_scope_keeps_timeout() -> None:
    assert remaining_time() is None
    assert transport_module._bounded(5.0, httpcore.ReadTimeout) == 5.0
    assert transport_module._bounded(None, httpcore.ReadTimeout) is None


def test_bounded_inside_scope_uses_remaining_time() -> None:
    with deadline_scope(monotonic() + 1.0):
        remaining = remaining_time()
        assert remaining is not None
        assert 0.9 < remaining <= 1.0
        bounded = transport_module._bounded(5.0, httpcore.ReadTimeout)
        assert bounded is not None
        assert bounded <= 1.0
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


# Socket stream


def test_read_is_bounded_and_mapped() -> None:
    sock = FakeSocket()
    with deadline_scope(monotonic() + 1.0):
        assert stream_over(sock).read(10, 5.0) == b"data"
    assert sock.timeouts[0] is not None and sock.timeouts[0] <= 1.0
    with pytest.raises(httpcore.ReadTimeout):
        stream_over(FakeSocket(recv_error=TimeoutError())).read(10, 5.0)
    with pytest.raises(httpcore.ReadError, match="ConnectionResetError"):
        stream_over(FakeSocket(recv_error=ConnectionResetError())).read(10, 5.0)
    with deadline_scope(monotonic() - 1.0), pytest.raises(httpcore.ReadTimeout):
        stream_over(FakeSocket()).read(10, 5.0)


def test_partial_sends_recompute_remaining_time() -> None:
    sock = FakeSocket(send_delay=0.02, send_size=1)
    start = monotonic()
    with deadline_scope(start + 0.05), pytest.raises(httpcore.WriteTimeout):
        stream_over(sock).write(b"x" * 1000, timeout=5.0)
    elapsed = monotonic() - start
    assert 0.04 <= elapsed < 0.05 + EPSILON
    assert 1 <= sock.sends <= 3
    timeouts = [value for value in sock.timeouts if value is not None]
    assert timeouts == sorted(timeouts, reverse=True)
    assert all(value <= 0.05 for value in timeouts)


def test_partial_sends_complete() -> None:
    sock = FakeSocket(send_size=3)
    with deadline_scope(monotonic() + 1.0):
        stream_over(sock).write(b"0123456789", timeout=5.0)
        stream_over(sock).write(b"", timeout=5.0)
    assert bytes(sock.sent) == b"0123456789"
    assert sock.sends == 4


def test_send_errors_are_mapped() -> None:
    with pytest.raises(httpcore.WriteError, match="BrokenPipeError"):
        stream_over(FakeSocket(send_error=BrokenPipeError())).write(b"x", 5.0)


def test_start_tls_keeps_hostname_and_bounds_handshake() -> None:
    sock = FakeSocket()
    context = FakeTlsContext()
    with deadline_scope(monotonic() + 1.0):
        tls = stream_over(sock).start_tls(
            cast(ssl.SSLContext, context), "relay.example.com", 5.0
        )
    assert isinstance(tls, transport_module._SocketStream)
    hostname, timeout = context.calls[0]
    assert hostname == "relay.example.com"
    assert timeout is not None and timeout <= 1.0
    assert tls.get_extra_info("ssl_object") is None


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (ssl.SSLCertVerificationError("hostname mismatch"), httpcore.ConnectError),
        (TimeoutError(), httpcore.ConnectTimeout),
    ],
)
def test_failed_handshake_closes_socket(
    error: BaseException, expected: type[Exception]
) -> None:
    sock = FakeSocket()
    with pytest.raises(expected):
        stream_over(sock).start_tls(
            cast(ssl.SSLContext, FakeTlsContext(error)), "relay.example.com", 5.0
        )
    assert sock.closed


def test_handshake_after_deadline_closes_socket() -> None:
    sock = FakeSocket()
    context = FakeTlsContext()
    with deadline_scope(monotonic() - 1.0), pytest.raises(httpcore.ConnectTimeout):
        stream_over(sock).start_tls(
            cast(ssl.SSLContext, context), "relay.example.com", 5.0
        )
    assert sock.closed
    assert context.calls == []


def test_extra_info_on_real_socket() -> None:
    left, right = socket.socketpair()
    stream = transport_module._SocketStream(left)
    try:
        assert stream.get_extra_info("socket") is left
        assert stream.get_extra_info("ssl_object") is None
        assert stream.get_extra_info("client_addr") == left.getsockname()
        assert stream.get_extra_info("server_addr") == left.getpeername()
        assert stream.get_extra_info("unknown") is None
        assert stream.get_extra_info("is_readable") is False
        right.sendall(b"x")
        time.sleep(0.01)
        assert stream.get_extra_info("is_readable") is True
    finally:
        stream.close()
        right.close()
    assert stream.get_extra_info("is_readable") is True


# Name resolution


def test_resolver_stall_stops_at_deadline(release: threading.Event) -> None:
    resolver = transport_module._BoundedResolver(stalled_resolver(release))
    start = monotonic()
    with deadline_scope(start + 0.05), pytest.raises(transport_module._CoreDnsTimeout):
        resolver.lookup("relay.example.com", 443, 5.0)
    assert monotonic() - start < 0.05 + EPSILON
    release.set()
    resolver.close()


def test_saturated_resolver_fails_fast(release: threading.Event) -> None:
    resolver = transport_module._BoundedResolver(stalled_resolver(release))
    for _ in range(DNS_WORKERS):
        with deadline_scope(monotonic() + 0.02), pytest.raises(DNS_TIMEOUT):
            resolver.lookup("relay.example.com", 443, 5.0)
    start = monotonic()
    with deadline_scope(start + 5.0), pytest.raises(DNS_TIMEOUT, match="busy"):
        resolver.lookup("relay.example.com", 443, 5.0)
    assert monotonic() - start < 0.05
    release.set()
    deadline = monotonic() + 2.0
    while monotonic() < deadline:
        try:
            with deadline_scope(monotonic() + 1.0):
                assert resolver.lookup("relay.example.com", 443, 5.0) == [address()]
            break
        except transport_module._CoreDnsTimeout:
            time.sleep(0.01)
    else:
        pytest.fail("resolver workers were not released")
    resolver.close()


def test_resolver_errors_are_connect_errors() -> None:
    def failing(host: str, port: int) -> Sequence[AddressInfo]:
        raise socket.gaierror(socket.EAI_NONAME, "relay.example.com not known")

    resolver = transport_module._BoundedResolver(failing)
    with pytest.raises(httpcore.ConnectError, match="gaierror"):
        resolver.lookup("relay.example.com", 443, 1.0)
    resolver.close()


@pytest.mark.parametrize(
    ("host", "family"),
    [
        ("127.0.0.1", socket.AF_INET),
        ("::1", socket.AF_INET6),
        ("[::1]", socket.AF_INET6),
    ],
)
def test_ip_literals_skip_resolver(host: str, family: int) -> None:
    def unused(host: str, port: int) -> Sequence[AddressInfo]:
        raise AssertionError("resolver called for an IP literal")

    resolver = transport_module._BoundedResolver(unused)
    (info,) = resolver.lookup(host, 443, 1.0)
    assert info[0] == family
    resolver.close()


def test_lookup_after_deadline_and_after_close() -> None:
    resolver = transport_module._BoundedResolver(lambda host, port: [address()])
    with (
        deadline_scope(monotonic() - 1.0),
        pytest.raises(httpcore.ConnectTimeout) as excinfo,
    ):
        resolver.lookup("relay.example.com", 443, 1.0)
    assert not isinstance(excinfo.value, DNS_TIMEOUT)
    resolver.close()
    with pytest.raises(httpcore.ConnectError, match="closed"):
        resolver.lookup("relay.example.com", 443, 1.0)


def test_unexpected_resolver_errors_propagate_and_free_the_worker() -> None:
    calls = 0

    def flaky(host: str, port: int) -> Sequence[AddressInfo]:
        nonlocal calls
        calls += 1
        if calls <= DNS_WORKERS:
            raise LookupError("fictitious resolver bug")
        return [address()]

    resolver = transport_module._BoundedResolver(flaky)
    for _ in range(DNS_WORKERS):
        with pytest.raises(LookupError, match="fictitious"):
            resolver.lookup("relay.example.com", 443, 1.0)
    assert resolver.lookup("relay.example.com", 443, 1.0) == [address()]
    resolver.close()


def test_worker_start_failures_release_their_slots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    failures = DNS_WORKERS

    class FailingThread(threading.Thread):
        def start(self) -> None:
            nonlocal failures
            if failures:
                failures -= 1
                raise RuntimeError("can't start new thread")
            super().start()

    monkeypatch.setattr(threading, "Thread", FailingThread)
    resolver = transport_module._BoundedResolver(lambda host, port: [address()])
    for _ in range(DNS_WORKERS):
        with pytest.raises(RuntimeError, match="start new thread"):
            resolver.lookup("relay.example.com", 443, 1.0)
    assert resolver._workers == []
    assert resolver.lookup("relay.example.com", 443, 1.0) == [address()]
    assert len(resolver._workers) == DNS_WORKERS
    resolver.close()


def test_job_construction_failure_takes_no_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = transport_module._Lookup
    failures = DNS_WORKERS

    def failing(host: str, port: int) -> transport_module._Lookup:
        nonlocal failures
        if failures:
            failures -= 1
            raise MemoryError("fictitious allocation failure")
        return real(host, port)

    monkeypatch.setattr(transport_module, "_Lookup", failing)
    resolver = transport_module._BoundedResolver(lambda host, port: [address()])
    for _ in range(DNS_WORKERS):
        with pytest.raises(MemoryError, match="fictitious"):
            resolver.lookup("relay.example.com", 443, 1.0)
    assert resolver.lookup("relay.example.com", 443, 1.0) == [address()]
    resolver.close()


def test_worker_started_before_start_raises_is_kept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[threading.Thread] = []
    raised = False

    class LateFailingThread(threading.Thread):
        def start(self) -> None:
            nonlocal raised
            created.append(self)
            super().start()
            if not raised:
                raised = True
                raise KeyboardInterrupt

    monkeypatch.setattr(threading, "Thread", LateFailingThread)
    resolver = transport_module._BoundedResolver(lambda host, port: [address()])
    with pytest.raises(KeyboardInterrupt):
        resolver.lookup("relay.example.com", 443, 1.0)
    assert resolver._workers == created
    assert created[0].is_alive()
    assert resolver.lookup("relay.example.com", 443, 1.0) == [address()]
    assert len(created) == DNS_WORKERS
    assert resolver._slots._value == DNS_WORKERS
    resolver.close()


def test_interrupt_after_recording_a_worker_forgets_it() -> None:
    resolver = transport_module._BoundedResolver(lambda host, port: [address()])
    interrupts = DNS_WORKERS

    class InterruptingList(list[threading.Thread]):
        def append(self, worker: threading.Thread) -> None:
            nonlocal interrupts
            super().append(worker)
            if interrupts:
                interrupts -= 1
                raise KeyboardInterrupt

    resolver._workers = InterruptingList()
    for _ in range(DNS_WORKERS):
        with pytest.raises(KeyboardInterrupt):
            resolver.lookup("relay.example.com", 443, 1.0)
        assert resolver._workers == []
    assert resolver._slots._value == DNS_WORKERS
    assert resolver.lookup("relay.example.com", 443, 1.0) == [address()]
    assert len(resolver._workers) == DNS_WORKERS
    assert all(worker.is_alive() for worker in resolver._workers)
    resolver.close()


class InterruptingQueue:
    """Job queue that raises KeyboardInterrupt once a job has been handed over."""

    def __init__(
        self, inner: Any, *, deliver: bool, after: Callable[[], object]
    ) -> None:
        self.inner = inner
        self.deliver = deliver
        self.after = after
        self.held: list[Any] = []
        self.armed = True

    def put(self, item: Any) -> None:
        if not self.armed or item is None:
            self.inner.put(item)
            return
        self.armed = False
        if self.deliver:
            self.inner.put(item)
        else:
            self.held.append(item)
        self.after()
        raise KeyboardInterrupt

    def get(self) -> Any:
        return self.inner.get()


def _wait_for_free_slots(resolver: transport_module._BoundedResolver) -> None:
    deadline = monotonic() + 2.0
    while resolver._slots._value < DNS_WORKERS and monotonic() < deadline:
        time.sleep(0.005)


def test_interrupt_after_handover_to_waiting_worker_releases_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = threading.Event()
    release = threading.Event()

    def resolve(host: str, port: int) -> Sequence[AddressInfo]:
        if host == "slow.example.com":
            started.set()
            release.wait(2.0)
        return [address()]

    resolver = transport_module._BoundedResolver(resolve)
    jobs = InterruptingQueue(
        resolver._jobs, deliver=True, after=lambda: started.wait(2.0)
    )
    monkeypatch.setattr(resolver, "_jobs", jobs)
    with pytest.raises(KeyboardInterrupt):
        resolver.lookup("slow.example.com", 443, 1.0)
    assert resolver._slots._value == DNS_WORKERS - 1
    release.set()
    _wait_for_free_slots(resolver)
    assert resolver._slots._value == DNS_WORKERS
    assert all(worker.is_alive() for worker in resolver._workers)
    for _ in range(DNS_WORKERS + 1):
        assert resolver.lookup("relay.example.com", 443, 1.0) == [address()]
    resolver.close()


def test_interrupt_before_a_worker_takes_the_job_releases_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def resolve(host: str, port: int) -> Sequence[AddressInfo]:
        calls.append(host)
        return [address()]

    resolver = transport_module._BoundedResolver(resolve)
    jobs = InterruptingQueue(resolver._jobs, deliver=False, after=lambda: None)
    monkeypatch.setattr(resolver, "_jobs", jobs)
    with pytest.raises(KeyboardInterrupt):
        resolver.lookup("abandoned.example.com", 443, 1.0)
    assert resolver._slots._value == DNS_WORKERS
    (abandoned,) = jobs.held
    jobs.inner.put(abandoned)
    for _ in range(DNS_WORKERS + 1):
        assert resolver.lookup("relay.example.com", 443, 1.0) == [address()]
    assert all(worker.is_alive() for worker in resolver._workers)
    resolver.close()
    for worker in resolver._workers:
        worker.join(2.0)
    assert "abandoned.example.com" not in calls
    assert resolver._slots._value == DNS_WORKERS


def test_resolver_workers_are_daemon_threads_that_stop_on_close() -> None:
    resolver = transport_module._BoundedResolver(lambda host, port: [address()])
    resolver.lookup("relay.example.com", 443, 1.0)
    workers = [
        thread
        for thread in threading.enumerate()
        if thread.name == "vrm-alert-relay-dns" and thread.is_alive()
    ]
    assert len(workers) >= DNS_WORKERS
    assert all(thread.daemon for thread in workers)
    own = resolver._workers
    assert len(own) == DNS_WORKERS
    resolver.close()
    for thread in own:
        thread.join(1.0)
        assert not thread.is_alive()


STUCK_RESOLVER_SCRIPT = """
import ssl, threading, time
import httpx
from vrm_alert_relay.net.transport import DNS_WORKERS, HardenedTransport, deadline_scope

def stuck(host, port):
    threading.Event().wait()

transport = HardenedTransport(ssl_context=ssl.create_default_context(), resolver=stuck)
client = httpx.Client(transport=transport)
for budget in [0.05] * DNS_WORKERS + [5.0]:
    started = time.monotonic()
    try:
        with deadline_scope(started + budget):
            client.get("https://relay.example.com/", timeout=budget)
    except httpx.ConnectTimeout as exc:
        print(type(exc).__name__, f"{time.monotonic() - started:.3f}", flush=True)
client.close()
print("main-finished", flush=True)
"""


def test_stuck_resolver_workers_do_not_block_interpreter_exit() -> None:
    src = Path(transport_module.__file__).resolve().parents[2]
    env = {**os.environ, "PYTHONPATH": str(src)}
    process = subprocess.Popen(  # noqa: S603 - fixed interpreter and script
        [sys.executable, "-c", STUCK_RESOLVER_SCRIPT],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    try:
        assert process.stdout is not None
        lines = [process.stdout.readline() for _ in range(DNS_WORKERS + 2)]
        finished = monotonic()
        assert lines[-1] == "main-finished\n", (lines, process.stderr)
        assert all(line.startswith("DnsTimeout ") for line in lines[:-1])
        assert float(lines[-2].split()[1]) < 1.0
        process.wait(timeout=5)
        exited = monotonic() - finished
    finally:
        process.kill()
        process.communicate()
    print(f"process exited {exited:.3f} s after main finished")
    assert process.returncode == 0
    assert exited < 1.0


# Address loop


def backend(
    addresses: Sequence[AddressInfo], factory: Factory
) -> transport_module._DeadlineBackend:
    resolver = transport_module._BoundedResolver(lambda host, port: list(addresses))
    return transport_module._DeadlineBackend(resolver, factory)


def test_slow_addresses_stop_at_deadline() -> None:
    sockets = [
        FakeSocket(connect_delay=0.04, connect_error=ConnectionRefusedError())
        for _ in range(4)
    ]
    factory = Factory(*sockets)
    start = monotonic()
    with deadline_scope(start + 0.05), pytest.raises(httpcore.ConnectTimeout):
        backend([address()] * 4, factory).connect_tcp("relay.example.com", 443, 5.0)
    elapsed = monotonic() - start
    assert 0.04 <= elapsed < 0.05 + EPSILON
    assert 1 <= len(factory.created) <= 3
    assert all(sock.closed for sock in factory.created)
    assert all(
        sock.timeouts[0] is not None and sock.timeouts[0] <= 0.05
        for sock in factory.created
    )


def test_address_loop_moves_past_failures() -> None:
    good = FakeSocket()
    refused = FakeSocket(connect_error=ConnectionRefusedError())
    slow = FakeSocket(connect_delay=1.0)
    factory = Factory(OSError("address family not supported"), refused, slow, good)
    addresses = [
        address(("192.0.2.1", 443)),
        address(("192.0.2.2", 443)),
        address(("192.0.2.3", 443)),
        address(("192.0.2.4", 443)),
    ]
    option = (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    stream = backend(addresses, factory).connect_tcp(
        "relay.example.com",
        443,
        0.05,
        local_address="198.51.100.7",
        socket_options=[option],
    )
    assert stream.get_extra_info("socket") is good
    assert refused.closed and slow.closed and not good.closed
    assert good.connected == ("192.0.2.4", 443)
    assert good.bound == ("198.51.100.7", 0)
    assert option in good.options
    assert (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1) in good.options


@pytest.mark.parametrize(
    ("addresses", "sockets", "expected"),
    [
        ([], [], httpcore.ConnectError),
        ([address()], [FakeSocket(connect_delay=1.0)], httpcore.ConnectTimeout),
        (
            [address()],
            [FakeSocket(connect_error=ConnectionRefusedError())],
            httpcore.ConnectError,
        ),
    ],
)
def test_last_connect_error_is_raised(
    addresses: list[AddressInfo], sockets: list[FakeSocket], expected: type[Exception]
) -> None:
    with pytest.raises(expected):
        backend(addresses, Factory(*sockets)).connect_tcp(
            "relay.example.com", 443, 0.02
        )


# Through the client


@pytest.fixture
def fake_network(monkeypatch: pytest.MonkeyPatch) -> Callable[..., Factory]:
    def install(
        *sockets: FakeSocket,
        resolver: Callable[[str, int], Sequence[AddressInfo]] | None = None,
    ) -> Factory:
        factory = Factory(*sockets)
        monkeypatch.setattr(transport_module, "_system_socket", factory)
        monkeypatch.setattr(
            transport_module,
            "_system_resolver",
            resolver or (lambda host, port: [address()]),
        )
        monkeypatch.setattr(client_module, "_tls_context", FakeTlsContext)
        return factory

    return install


def timed_timeout(deadline: float, **request: Any) -> tuple[HttpTimeout, float]:
    timeouts = Timeouts(connect=5.0, read=5.0, write=5.0, deadline=deadline)
    with SafeHttpClient(timeouts=timeouts) as client:
        start = monotonic()
        with pytest.raises(HttpTimeout) as excinfo:
            client.request(
                "POST", f"https://relay.example.com/api?token={QUERY_CANARY}", **request
            )
        elapsed = monotonic() - start
    assert excinfo.value.__context__ is None
    assert excinfo.value.__cause__ is None
    assert QUERY_CANARY not in str(excinfo.value)
    return excinfo.value, elapsed


def test_client_dns_stall_is_a_dns_timeout(
    fake_network: Callable[..., Factory], release: threading.Event
) -> None:
    factory = fake_network(resolver=stalled_resolver(release))
    error, elapsed = timed_timeout(0.1)
    assert error.phase == "dns"
    assert elapsed < 0.1 + EPSILON
    assert factory.created == []


def test_client_slow_addresses_stop_at_deadline(
    fake_network: Callable[..., Factory],
) -> None:
    fake_network(
        *(
            FakeSocket(connect_delay=0.04, connect_error=ConnectionRefusedError())
            for _ in range(4)
        ),
        resolver=lambda host, port: [address()] * 4,
    )
    error, elapsed = timed_timeout(0.05)
    assert error.phase == "deadline"
    assert elapsed < 0.05 + EPSILON


def test_client_trickling_send_stops_at_deadline(
    fake_network: Callable[..., Factory],
) -> None:
    sock = FakeSocket(send_delay=0.02, send_size=1)
    fake_network(sock)
    error, elapsed = timed_timeout(0.05, json={"message": "x" * 1000})
    assert error.phase == "deadline"
    assert 0.04 <= elapsed < 0.05 + EPSILON
    assert sock.sends <= 3
    assert sock.closed


def test_dns_timeout_maps_to_dns_phase() -> None:
    request = httpx.Request("GET", "https://relay.example.com/")
    with pytest.raises(DnsTimeout), transport_module._map_exceptions(request):
        raise transport_module._CoreDnsTimeout("busy")


# Exception mapping and pool


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

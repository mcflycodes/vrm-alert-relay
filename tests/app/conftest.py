"""Fixtures for the service tests. Every identifier and credential is fictitious."""

from __future__ import annotations

import logging
import socket
from typing import TYPE_CHECKING

import pytest
from app_helpers import FakeClock, FakeVoipms, FakeVrm, Harness, Network

from vrm_alert_relay.logs.redaction import default_registry
from vrm_alert_relay.net.transport import HardenedTransport

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    import httpx


@pytest.fixture(autouse=True)
def _clean_registry() -> Iterator[None]:
    """Each test registers its fictitious secrets in a fresh process-wide registry."""
    default_registry.clear()
    yield
    default_registry.clear()


@pytest.fixture(autouse=True)
def _restore_logging() -> Iterator[None]:
    """The CLI installs its own handlers; put pytest's back afterwards."""
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield
    for handler in list(root.handlers):
        if handler not in handlers:
            root.removeHandler(handler)
    for handler in handlers:
        if handler not in root.handlers:
            root.addHandler(handler)
    root.setLevel(level)
    logging.captureWarnings(capture=False)


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def network(monkeypatch: pytest.MonkeyPatch, clock: FakeClock) -> Network:
    net = Network(FakeVrm(now=clock.wall), FakeVoipms())

    def handle_request(_self: HardenedTransport, request: httpx.Request) -> httpx.Response:
        return net.handle(request)

    monkeypatch.setattr(HardenedTransport, "handle_request", handle_request)
    return net


@pytest.fixture
def harness(tmp_path: Path, clock: FakeClock, network: Network) -> Harness:
    root = tmp_path / "relay"
    root.mkdir(mode=0o700)
    return Harness(root, clock, network.vrm, network.voipms, network)


@pytest.fixture
def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port

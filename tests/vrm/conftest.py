"""Fixtures for the VRM adapter tests. Every identifier and token is fictitious."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest
from vrm_helpers import BASE_URL, FAKE_TOKEN, NOW, FakeClock, StubTransport

from vrm_alert_relay.config.secret import Secret
from vrm_alert_relay.logs.redaction import SecretRegistry
from vrm_alert_relay.net.client import SafeHttpClient
from vrm_alert_relay.net.transport import HardenedTransport
from vrm_alert_relay.vrm.adapter import VrmAdapter
from vrm_alert_relay.vrm.backoff import Backoff, BackoffPolicy

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    import httpx


@pytest.fixture(autouse=True)
def transport(monkeypatch: pytest.MonkeyPatch) -> StubTransport:
    stub = StubTransport()

    def handle_request(_self: HardenedTransport, req: httpx.Request) -> httpx.Response:
        return stub.handle(req)

    monkeypatch.setattr(HardenedTransport, "handle_request", handle_request)
    return stub


@pytest.fixture
def registry() -> SecretRegistry:
    return SecretRegistry()


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def http() -> Iterator[SafeHttpClient]:
    with SafeHttpClient() as client:
        yield client


@pytest.fixture
def make_adapter(
    http: SafeHttpClient, registry: SecretRegistry, clock: FakeClock
) -> Callable[..., VrmAdapter]:
    def build(**overrides: Any) -> VrmAdapter:
        options: dict[str, Any] = {
            "base_url": BASE_URL,
            "backoff": Backoff(BackoffPolicy(jitter=0.0)),
            "clock": clock,
            "wall_clock": lambda: NOW,
            "registry": registry,
        }
        options.update(overrides)
        return VrmAdapter(http, Secret(FAKE_TOKEN), **options)

    return build

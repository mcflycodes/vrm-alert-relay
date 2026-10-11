"""Fixtures for the provider tests. Every identifier and credential is fictitious."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from provider_helpers import StubTransport

from vrm_alert_relay.logs.redaction import SecretRegistry
from vrm_alert_relay.net import SafeHttpClient
from vrm_alert_relay.net.transport import HardenedTransport

if TYPE_CHECKING:
    from collections.abc import Iterator

    import httpx


@pytest.fixture(autouse=True)
def transport(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> StubTransport:
    """Stub the transport unless the test module sets ``REAL_SOCKETS = True``."""
    stub = StubTransport()
    if getattr(request.module, "REAL_SOCKETS", False):
        return stub

    def handle_request(_self: HardenedTransport, req: httpx.Request) -> httpx.Response:
        return stub.handle(req)

    monkeypatch.setattr(HardenedTransport, "handle_request", handle_request)
    return stub


@pytest.fixture
def registry() -> SecretRegistry:
    return SecretRegistry()


@pytest.fixture
def http() -> Iterator[SafeHttpClient]:
    with SafeHttpClient() as client:
        yield client


@pytest.fixture
def insecure_http() -> Iterator[SafeHttpClient]:
    with SafeHttpClient(allow_insecure_http=True) as client:
        yield client

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

Handler = Callable[[httpx.Request], httpx.Response]


class StubTransport:
    """Replaces httpx's real transport so no test can reach the network."""

    def __init__(self) -> None:
        self.handler: Handler | None = None
        self.requests: list[httpx.Request] = []

    def respond(self, handler: Handler) -> None:
        self.handler = handler

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.handler is None:
            raise AssertionError("unexpected network request")
        return self.handler(request)


@pytest.fixture(autouse=True)
def transport(monkeypatch: pytest.MonkeyPatch) -> StubTransport:
    stub = StubTransport()

    def handle_request(
        _self: httpx.HTTPTransport, request: httpx.Request
    ) -> httpx.Response:
        return stub.handle(request)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", handle_request)
    return stub

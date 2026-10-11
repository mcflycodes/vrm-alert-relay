from __future__ import annotations

from collections.abc import Callable, Iterator

import httpx
import pytest

from vrm_alert_relay.net.transport import HardenedTransport

Handler = Callable[[httpx.Request], httpx.Response]


class StubTransport:
    """Replaces the client's real transport so no test can reach the network."""

    def __init__(self) -> None:
        self.handler: Handler | None = None
        self.requests: list[httpx.Request] = []

    def respond(self, handler: Handler) -> None:
        self.handler = handler

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.handler is None:
            raise AssertionError("unexpected network request")
        response = self.handler(request)
        if not response.is_stream_consumed:
            return response
        # httpx reads ``content=`` bodies eagerly; the real transport never does.
        body = b"".join(response.stream)  # type: ignore[arg-type]
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            stream=UnreadStream(body),
            request=request,
        )


class UnreadStream(httpx.SyncByteStream):
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __iter__(self) -> Iterator[bytes]:
        yield self._body


@pytest.fixture(autouse=True)
def transport(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> StubTransport:
    """Stub the transport unless the test module sets ``REAL_SOCKETS = True``.

    Real-socket modules talk only to servers they start on 127.0.0.1.
    """
    stub = StubTransport()
    if getattr(request.module, "REAL_SOCKETS", False):
        return stub

    def handle_request(_self: HardenedTransport, req: httpx.Request) -> httpx.Response:
        return stub.handle(req)

    monkeypatch.setattr(HardenedTransport, "handle_request", handle_request)
    return stub

"""Shared helpers for the VRM adapter tests. Every identifier and token is fictitious."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from datetime import UTC, datetime

import httpx

from vrm_alert_relay.config.models import Installation, Measurement

FAKE_TOKEN = "fake-vrm-token-0000-not-real-0000-abcdef"  # noqa: S105  # fictitious test token
NOW = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
NOW_TS = int(NOW.timestamp())
BASE_URL = "https://vrm.example.invalid/v2"

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
        body = b"".join(response.stream)  # type: ignore[arg-type]
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            stream=_UnreadStream(body),
            request=request,
        )


class _UnreadStream(httpx.SyncByteStream):
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __iter__(self) -> Iterator[bytes]:
        yield self._body


class FakeClock:
    """A settable monotonic clock."""

    def __init__(self, now: float = 1000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def installation(name: str = "home", site_id: int = 123456) -> Installation:
    return Installation(id=name, site_id=site_id)


def measurement(code: str, instance: int, service_type: str | None = None) -> Measurement:
    return Measurement(code=code, instance=instance, service_type=service_type)


def record(
    code: str,
    instance: int,
    raw_value: object,
    *,
    service_type: str = "battery",
    timestamp: object = NOW_TS,
    description: object = "Fictitious attribute",
) -> dict[str, object]:
    return {
        "idSite": 123456,
        "timestamp": timestamp,
        "Device": "Fictitious device",
        "instance": instance,
        "idDataAttribute": 51,
        "description": description,
        "formatWithUnit": "%.2F V",
        "dbusServiceType": service_type,
        "dbusPath": "/Fictitious/Path",
        "code": code,
        "rawValue": raw_value,
        "formattedValue": f"{raw_value} V",
    }


def diagnostics(*records: dict[str, object]) -> dict[str, object]:
    return {"success": True, "records": list(records)}


def json_response(payload: object, status: int = 200, **headers: str) -> httpx.Response:
    return httpx.Response(
        status,
        content=json.dumps(payload).encode(),
        headers={"content-type": "application/json", **headers},
    )

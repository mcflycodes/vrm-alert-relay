"""A mocked VRM API and VoIP.ms API, a fake clock, and a configuration builder.

Every identifier, number, token and address here is fictitious. No test can
reach the network: the hardened transport is replaced by :class:`Network`,
which answers only for the two fictitious hosts below.
"""

from __future__ import annotations

import json
import re
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

import httpx

from vrm_alert_relay.app import Service, open_runtime
from vrm_alert_relay.vrm import Backoff, BackoffPolicy

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator
    from pathlib import Path

VRM_HOST = "vrm.example.invalid"
VRM_BASE = f"https://{VRM_HOST}/v2"
VOIPMS_HOST = "voipms.example.invalid"
VOIPMS_URL = f"https://{VOIPMS_HOST}/api/v1/rest.php"
VRM_TOKEN = "fake-vrm-token-app-0000-not-real"  # noqa: S105  # fictitious test token
VOIPMS_USER = "fake-voipms-user-app@example.test"
VOIPMS_PASSWORD = "fake-voipms-pass-app-0000"  # noqa: S105  # fictitious test credential
SECRETS = (VRM_TOKEN, VOIPMS_USER, VOIPMS_PASSWORD)
OWNER_PHONE = "2025550142"
PARTNER_PHONE = "2025550177"
DID = "2025550100"
CABIN_SITE = 123456
BARN_SITE = 234567
START = datetime(2035, 1, 1, tzinfo=UTC)
CYCLE = timedelta(seconds=60)


@dataclass
class FakeClock:
    """Wall-clock and monotonic time that tests move explicitly."""

    now: datetime = START
    mono: float = 50_000.0

    def wall(self) -> datetime:
        return self.now

    def monotonic(self) -> float:
        return self.mono

    def advance(self, delta: timedelta) -> None:
        self.now += delta
        self.mono += delta.total_seconds()


class _Body(httpx.SyncByteStream):
    def __init__(self, body: bytes) -> None:
        self._body = body

    def __iter__(self) -> Iterator[bytes]:
        yield self._body


def respond(request: httpx.Request, status: int, payload: object) -> httpx.Response:
    return httpx.Response(
        status,
        headers={"content-type": "application/json"},
        stream=_Body(json.dumps(payload).encode()),
        request=request,
    )


@dataclass
class FakeVrm:
    """VRM Diagnostics for fictitious sites; records are stamped with ``now()``."""

    now: Callable[[], datetime]
    values: dict[tuple[int, str, int], object] = field(default_factory=dict)
    labels: dict[tuple[int, str, int], object] = field(default_factory=dict)
    formats: dict[tuple[int, str, int], object] = field(default_factory=dict)
    """``formatWithUnit`` per record; records without one carry none."""
    failures: dict[int, int] = field(default_factory=dict)
    extra_records: list[dict[str, object]] = field(default_factory=list)
    requests: list[httpx.Request] = field(default_factory=list)
    on_request: Callable[[], None] | None = None
    skew: timedelta = timedelta(0)
    """Added to every record's timestamp, as by a GX device with a wrong clock."""

    def set(
        self,
        code: str,
        instance: int,
        value: object,
        *,
        site: int = CABIN_SITE,
        label: object = None,
    ) -> None:
        self.values[site, code, instance] = value
        if label is not None:
            self.labels[site, code, instance] = label

    def fail(self, status: int, *sites: int) -> None:
        for site in sites or (CABIN_SITE, BARN_SITE):
            self.failures[site] = status

    def heal(self) -> None:
        self.failures.clear()

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.on_request is not None:
            self.on_request()
        match = re.fullmatch(r"/v2/installations/(\d+)/diagnostics", request.url.path)
        if match is None:
            return respond(request, 404, {"success": False})
        site = int(match.group(1))
        if site in self.failures:
            return respond(request, self.failures[site], {"success": False, "errors": "down"})
        stamp = int((self.now() + self.skew).timestamp())
        records: list[dict[str, object]] = [
            {
                "idSite": site,
                "timestamp": stamp,
                "instance": instance,
                "code": code,
                "description": self.labels.get((s, code, instance), f"Fictitious {code}"),
                "dbusServiceType": "temperature",
                "rawValue": value,
            }
            for (s, code, instance), value in self.values.items()
            if s == site
        ]
        for entry in records:
            key = (site, str(entry["code"]), int(str(entry["instance"])))
            if key in self.formats:
                entry["formatWithUnit"] = self.formats[key]
        records.extend(self.extra_records)
        return respond(request, 200, {"success": True, "records": records})


_FIELD = re.compile(rb'name="([a-z_]+)"\r\n\r\n([^\r]*)\r\n')


@dataclass
class FakeVoipms:
    """The VoIP.ms REST API: scripted ``sendSMS`` and ``getSMS`` answers."""

    sends: deque[Any] = field(default_factory=deque)
    lookups: deque[Any] = field(default_factory=deque)
    calls: list[dict[str, str]] = field(default_factory=list)
    next_id: int = 9000

    def handle(self, request: httpx.Request) -> httpx.Response:
        fields = {
            name.decode(): value.decode("utf-8") for name, value in _FIELD.findall(request.read())
        }
        self.calls.append(fields)
        script = self.sends if fields.get("method") == "sendSMS" else self.lookups
        if script:
            answer = script.popleft()
        elif fields.get("method") == "sendSMS":
            self.next_id += 1
            answer = {"status": "success", "sms": self.next_id}
        else:
            answer = {"status": "no_sms"}
        if isinstance(answer, int):
            return respond(request, answer, {})
        return respond(request, 200, answer)

    def methods(self) -> list[str]:
        return [call["method"] for call in self.calls]

    def sent(self) -> list[tuple[str, str]]:
        """(destination, text) of every sendSMS call."""
        return [(c["dst"], c["message"]) for c in self.calls if c["method"] == "sendSMS"]

    def texts(self) -> list[str]:
        return [text for _, text in self.sent()]


class Network:
    """Stands in for every HTTP connection the relay makes."""

    def __init__(self, vrm: FakeVrm, voipms: FakeVoipms) -> None:
        self.vrm = vrm
        self.voipms = voipms
        self.hosts: list[str] = []

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.hosts.append(request.url.host)
        if request.url.host == VRM_HOST:
            return self.vrm.handle(request)
        if request.url.host == VOIPMS_HOST:
            return self.voipms.handle(request)
        raise AssertionError("unexpected network request")


def freezer_rule(**overrides: Any) -> dict[str, Any]:
    rule: dict[str, Any] = {
        "id": "freezer",
        "installation": "cabin",
        "measurement": {"code": "tsT", "instance": 20},
        "direction": "rising",
        "levels": [
            {"name": "warning", "threshold": -12},
            {"name": "alert", "threshold": -8},
            {"name": "critical", "threshold": -4},
        ],
        "hysteresis": 1,
        "recipients": ["owner_sms", "audit"],
    }
    rule.update(overrides)
    return rule


@dataclass
class Harness:
    """Writes configuration and secret files and opens services against the fakes."""

    root: Path
    clock: FakeClock
    vrm: FakeVrm
    voipms: FakeVoipms
    network: Network

    @property
    def config_path(self) -> Path:
        return self.root / "config.yaml"

    @property
    def state_dir(self) -> Path:
        path = self.root / "state"
        path.mkdir(mode=0o700, exist_ok=True)
        return path

    def secret(self, name: str, value: str) -> str:
        path = self.root / "secrets" / name
        path.parent.mkdir(mode=0o700, exist_ok=True)
        path.write_text(value + "\n")
        path.chmod(0o600)
        return str(path)

    def write_config(  # every knob is a keyword with a default
        self,
        *,
        sending: bool = True,
        voipms: bool = True,
        per_hour: int = 20,
        per_day: int = 60,
        rules: list[dict[str, Any]] | None = None,
        system: list[str] | None = None,
        installations: list[dict[str, Any]] | None = None,
        recipients: dict[str, Any] | None = None,
        health: dict[str, Any] | None = None,
    ) -> Path:
        config: dict[str, Any] = {
            "version": 1,
            "sending": {"enabled": sending},
            "vrm": {
                "base_url": VRM_BASE,
                "token_file": self.secret("vrm_token", VRM_TOKEN),
                "poll_interval": 60,
                "installations": installations or [{"id": "cabin", "site_id": CABIN_SITE}],
            },
            "rate_limits": {"global_per_hour": per_hour, "global_per_day": per_day, "retries": 3},
            "recipients": recipients
            or {
                "owner_sms": {"provider": "voipms", "phone": "+1 202 555 0142"},
                "partner_sms": {"provider": "voipms", "phone": "+1 202 555 0177"},
                "audit": {"provider": "log"},
            },
            "providers": {
                "voipms": {
                    "enabled": voipms,
                    "base_url": VOIPMS_URL,
                    "username_file": self.secret("voipms_user", VOIPMS_USER),
                    "password_file": self.secret("voipms_password", VOIPMS_PASSWORD),
                    "did": DID,
                }
            },
            "rules": [freezer_rule()] if rules is None else rules,
            "system_recipients": ["owner_sms"] if system is None else system,
        }
        if health is not None:
            config["health"] = health
        # JSON is valid YAML, and the loader accepts it.
        self.config_path.write_text(json.dumps(config, indent=2))
        return self.config_path

    def open(self, *, state_dir: Path | None = None) -> Service:
        runtime = open_runtime(
            self.config_path,
            state_dir if state_dir is not None else self.state_dir,
            clock=self.clock,
        )
        return Service(runtime, backoff=Backoff(BackoffPolicy(jitter=0.0)))

    @contextmanager
    def service(self, *, state_dir: Path | None = None) -> Iterator[Service]:
        service = self.open(state_dir=state_dir)
        try:
            yield service
        finally:
            service.close()

    def cycle(self, service: Service, count: int = 1) -> None:
        """Run ``count`` cycles, a poll interval apart."""
        for _ in range(count):
            service.relay.run_cycle()
            self.clock.advance(CYCLE)


@dataclass
class FakeStop:
    """Stops after ``limit`` waits; records how long each wait was."""

    limit: int = 1_000
    waits: list[float] = field(default_factory=list)
    stopped: bool = False

    def is_set(self) -> bool:
        return self.stopped

    def wait(self, timeout: float | None = None) -> bool:
        assert timeout is not None
        self.waits.append(timeout)
        if len(self.waits) >= self.limit:
            self.stopped = True
        return self.stopped

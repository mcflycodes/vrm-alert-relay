"""The health endpoint (R28): informational, loopback by default, no secrets or recipients."""

from __future__ import annotations

import http.client
import json
import logging
import socket
from typing import TYPE_CHECKING

import pytest
from app_helpers import CABIN_SITE, OWNER_PHONE, SECRETS, FakeStop

from vrm_alert_relay.app import HealthServer, HealthState
from vrm_alert_relay.app.health import SCHEMA_VERSION

if TYPE_CHECKING:
    from collections.abc import Iterator

    from app_helpers import Harness


def request(
    address: tuple[str, int], method: str = "GET", path: str = "/health"
) -> tuple[int, dict[str, str], bytes]:
    host, port = address
    connection = http.client.HTTPConnection(host, port, timeout=5)
    try:
        connection.request(method, path)
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


@pytest.fixture
def server() -> Iterator[HealthServer]:
    state = HealthState()
    state.publish({"schema": SCHEMA_VERSION, "status": "ok"})
    health = HealthServer("127.0.0.1", 0, state)
    health.start()
    yield health
    health.close()


def test_health_serves_the_published_document(server: HealthServer) -> None:
    status, headers, body = request(server.address)

    assert status == 200
    assert json.loads(body) == {"schema": SCHEMA_VERSION, "status": "ok"}
    assert headers["Content-Type"] == "application/json"
    assert headers["Cache-Control"] == "no-store"
    assert headers["Server"] == "vrm-alert-relay"
    assert not any(name.lower().startswith("access-control") for name in headers)


def test_root_path_and_query_strings_serve_the_same_document(server: HealthServer) -> None:
    assert request(server.address, path="/")[2] == request(server.address, path="/health?x=1")[2]


def test_head_sends_headers_only(server: HealthServer) -> None:
    status, headers, body = request(server.address, method="HEAD")

    assert status == 200
    assert body == b""
    assert int(headers["Content-Length"]) > 0


def test_other_paths_are_not_found(server: HealthServer) -> None:
    status, _, body = request(server.address, path="/metrics")

    assert status == 404
    assert json.loads(body) == {"error": "not found"}


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "OPTIONS"])
def test_only_get_and_head_are_served(server: HealthServer, method: str) -> None:
    status, headers, body = request(server.address, method=method)

    assert status == 501
    assert headers["Content-Type"].startswith("text/plain")
    assert len(body) < 100


def test_requests_are_not_logged(server: HealthServer, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG):
        request(server.address, path="/health?token=fake-query-0000")

    assert "fake-query-0000" not in caplog.text


def test_a_state_starts_with_a_starting_document() -> None:
    assert json.loads(HealthState().body()) == {"schema": SCHEMA_VERSION, "status": "starting"}


def test_close_without_start_releases_the_socket() -> None:
    server = HealthServer("127.0.0.1", 0, HealthState())
    host, port = server.address
    server.close()

    with socket.socket() as probe:
        probe.bind((host, port))


def test_ipv6_loopback_is_supported() -> None:
    if not socket.has_ipv6:
        pytest.skip("no IPv6 support")
    try:
        server = HealthServer("::1", 0, HealthState())
    except OSError:
        pytest.skip("IPv6 loopback is not available")
    server.start()
    try:
        assert request(server.address)[0] == 200
    finally:
        server.close()


def test_service_health_binds_loopback_and_holds_no_secrets_or_recipients(
    harness: Harness, free_port: int
) -> None:
    harness.write_config(health={"enabled": True, "port": free_port})
    harness.vrm.set("tsT", 20, -10)
    with harness.service() as service:
        service.start_health()
        assert service.health_server is not None
        assert service.health_server.address == ("127.0.0.1", free_port)
        harness.cycle(service, 2)
        service.publish_health()
        _, _, body = request(service.health_server.address)

    document = json.loads(body)
    assert document["status"] == "ok"
    assert document["dry_run"] is False
    assert document["config_fingerprint"] == service.config_fingerprint
    assert len(document["config_fingerprint"]) == 16
    assert document["monitoring"] == {
        "status": "ok",
        "cycles": 2,
        "last_cycle_failed": False,
        "last_cycle_at": "2035-01-01T00:01:00+00:00",
        "last_successful_poll_at": "2035-01-01T00:01:00+00:00",
        "installations": 1,
        "failing_installations": 0,
        "degraded_installations": 0,
    }
    assert document["state_persistence"] == {
        "healthy": True,
        "durable_accounting": True,
        "error": None,
    }
    assert document["delivery"]["sent_last_hour"] == 1
    assert document["delivery"]["would_send_last_hour"] == 1  # the audit log recipient
    text = body.decode()
    for forbidden in (*SECRETS, OWNER_PHONE, "owner_sms", "audit", "cabin", str(CABIN_SITE)):
        assert forbidden not in text
    assert len(body) < 1024


def test_service_health_reports_degraded_monitoring(harness: Harness) -> None:
    harness.write_config()
    harness.vrm.fail(503)
    with harness.service() as service:
        harness.cycle(service, 3)
        service.publish_health()
        document = json.loads(service.health_state.body())

    assert document["status"] == "degraded"
    assert document["monitoring"]["status"] == "degraded"
    assert document["monitoring"]["degraded_installations"] == 1
    assert document["monitoring"]["last_successful_poll_at"] is None


def test_health_is_not_started_unless_enabled(harness: Harness) -> None:
    harness.write_config()
    with harness.service() as service:
        service.start_health()
        assert service.health_server is None


def test_health_bind_failure_is_logged_and_the_relay_keeps_running(
    harness: Harness, caplog: pytest.LogCaptureFixture, free_port: int
) -> None:
    harness.write_config(health={"enabled": True, "port": free_port})
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", free_port))
        taken.listen()
        with harness.service() as service, caplog.at_level(logging.ERROR):
            service.start_health()
            assert service.health_server is None
            harness.cycle(service)

    failures = [r for r in caplog.records if getattr(r, "event", None) == "health.bind_failed"]
    assert len(failures) == 1


def test_service_can_override_the_health_port(harness: Harness) -> None:
    harness.write_config(health={"enabled": True})
    with harness.service() as service:
        service.start_health(port=0)
        assert service.health_server is not None
        assert request(service.health_server.address)[0] == 200


def test_health_reports_starting_until_the_first_cycle_completes(
    harness: Harness, free_port: int
) -> None:
    harness.write_config(health={"enabled": True, "port": free_port})
    harness.vrm.set("tsT", 20, -20)
    with harness.service() as service:
        service.start_health()
        assert service.health_server is not None
        before = json.loads(request(service.health_server.address)[2])
        service.run(FakeStop(limit=1), max_cycles=1)
        after = json.loads(request(service.health_server.address)[2])

    assert before["status"] == "starting"
    assert before["monitoring"]["cycles"] == 0
    assert after["status"] == "ok"


def test_a_first_cycle_that_raises_reports_degraded_never_ok(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -20)
    with harness.service() as service:
        real = service.relay.run_cycle
        calls: list[int] = []

        def first_fails() -> object:
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("cycle bug")
            return real()

        monkeypatch.setattr(service.relay, "run_cycle", first_fails)
        service.run(FakeStop(limit=1), max_cycles=1)
        failed = json.loads(service.health_state.body())
        service.run(FakeStop(limit=1), max_cycles=1)
        recovered = json.loads(service.health_state.body())

    assert failed["status"] == "degraded"
    assert failed["monitoring"]["last_cycle_failed"] is True
    assert failed["monitoring"]["cycles"] == 0
    assert recovered["status"] == "ok"
    assert recovered["monitoring"]["last_cycle_failed"] is False


def test_failing_persistence_before_the_first_cycle_is_degraded_not_starting(
    harness: Harness,
) -> None:
    harness.write_config()
    real = harness.root / "real-state"
    real.mkdir(mode=0o700)
    link = harness.root / "linked-state"
    link.symlink_to(real)
    with harness.service(state_dir=link) as service:
        service.publish_health()
        document = json.loads(service.health_state.body())

    assert document["status"] == "degraded"

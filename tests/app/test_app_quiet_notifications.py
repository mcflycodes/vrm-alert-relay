"""Alarms only: ``stale_notify: false`` and ``system_recipients: []``.

Mocked VRM and VoIP.ms APIs, real everything else. Every value is fictitious.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any

from app_helpers import FakeClock, FakeVoipms, FakeVrm, Harness, Network, freezer_rule

from vrm_alert_relay.app import relay as relay_module
from vrm_alert_relay.net.transport import HardenedTransport

if TYPE_CHECKING:
    from pathlib import Path

    import httpx
    import pytest

    from vrm_alert_relay.engine import Event, RuleState


def records(caplog: pytest.LogCaptureFixture, event: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if getattr(r, "event", None) == event]


def stale_texts(texts: list[str]) -> list[str]:
    return [t for t in texts if t.startswith(("Stale data:", "Data restored:"))]


def run_stale_cycle(harness: Harness, *, rule: dict[str, Any] | None = None) -> None:
    """A reading, then 40 minutes without one, then readings again."""
    harness.write_config(rules=[rule or freezer_rule(stale_notify=False)])
    harness.vrm.set("tsT", 20, -20)
    with harness.service() as service:
        harness.cycle(service)
        harness.vrm.values.clear()
        harness.clock.advance(timedelta(minutes=40))
        harness.cycle(service)
        service.publish_health()
        stale = json.loads(service.health_state.body())
        harness.vrm.set("tsT", 20, -20)
        harness.cycle(service)
        service.publish_health()
        restored = json.loads(service.health_state.body())
        assert service.relay.status.events_total == 2
    assert stale["monitoring"]["stale_rules"] == 1
    assert restored["monitoring"]["stale_rules"] == 0


def test_stale_notify_true_still_sends_stale_and_restored(harness: Harness) -> None:
    run_stale_cycle(harness, rule=freezer_rule())

    texts = harness.voipms.texts()
    assert len(stale_texts(texts)) == 2
    assert texts == stale_texts(texts)


def test_stale_notify_false_logs_stale_and_restored_without_sending(
    harness: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO):
        run_stale_cycle(harness)

    assert harness.voipms.texts() == []
    (stale,) = records(caplog, "relay.stale_suppressed")
    (restored,) = records(caplog, "relay.restored_suppressed")
    assert stale.levelno == logging.WARNING
    assert restored.levelno == logging.INFO
    for record in (stale, restored):
        assert getattr(record, "rule_id", None) == "freezer"
        assert getattr(record, "installation", None) == "cabin"
        assert str(getattr(record, "event_id", "")).strip()
    assert getattr(stale, "sample_time", None) == "2035-01-01T00:00:00+00:00"
    # Nothing was queued for any recipient, not even the log-only one.
    with harness.service() as service:
        for record in (stale, restored):
            for recipient in ("owner_sms", "audit"):
                assert service.runtime.delivery.record(record.event_id, recipient) is None


def test_a_failing_log_handler_does_not_stop_the_cycle(harness: Harness) -> None:
    class Broken(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            raise RuntimeError

        def handleError(self, record: logging.LogRecord) -> None:  # noqa: N802  # logging API
            raise RuntimeError

    handler = Broken()
    relay_module.logger.addHandler(handler)
    try:
        run_stale_cycle(harness)
    finally:
        relay_module.logger.removeHandler(handler)

    assert harness.voipms.texts() == []


_REAL_EVALUATE = relay_module.evaluate

type Trace = list[tuple[str, tuple[Event, ...], RuleState]]


def _alarm_run(root: Path, monkeypatch: pytest.MonkeyPatch, *, stale_notify: bool) -> Any:
    """Escalation, reminders, a stale spell, restoration and recovery, recorded."""
    clock = FakeClock()
    net = Network(FakeVrm(now=clock.wall), FakeVoipms())

    def handle_request(_self: HardenedTransport, request: httpx.Request) -> httpx.Response:
        return net.handle(request)

    monkeypatch.setattr(HardenedTransport, "handle_request", handle_request)
    trace: Trace = []

    def evaluate(*args: Any) -> Any:
        new_state, events = _REAL_EVALUATE(*args)
        trace.append((args[0].rule_id, tuple(events), new_state))
        return new_state, events

    monkeypatch.setattr(relay_module, "evaluate", evaluate)
    root.mkdir(mode=0o700)
    harness = Harness(root, clock, net.vrm, net.voipms, net)
    rule = freezer_rule(
        stale_notify=stale_notify, reminder_interval_minutes=5, reminder_max=2, cooldown_minutes=1
    )
    harness.write_config(rules=[rule])
    with harness.service() as service:
        for value in (-20, -10, -6, -6, -2):
            harness.vrm.set("tsT", 20, value)
            harness.cycle(service)
        harness.clock.advance(timedelta(minutes=10))
        harness.cycle(service)  # a reminder
        harness.vrm.values.clear()
        harness.clock.advance(timedelta(minutes=40))
        harness.cycle(service, 2)  # stale while active
        harness.vrm.set("tsT", 20, -3)
        harness.cycle(service)  # restored
        harness.clock.advance(timedelta(minutes=10))
        harness.cycle(service)  # another reminder
        harness.vrm.set("tsT", 20, -30)
        harness.cycle(service, 2)  # recovered
        state = service.runtime.delivery.rule_state("freezer")
    return trace, harness.voipms.texts(), state


def test_stale_notify_changes_only_stale_and_restored_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    loud_trace, loud_texts, loud_state = _alarm_run(
        tmp_path / "loud", monkeypatch, stale_notify=True
    )
    quiet_trace, quiet_texts, quiet_state = _alarm_run(
        tmp_path / "quiet", monkeypatch, stale_notify=False
    )

    # Evaluation, event IDs and saved state are identical...
    assert quiet_trace == loud_trace
    assert quiet_state == loud_state
    kinds = {event.kind.value for _, events, _ in loud_trace for event in events}
    assert kinds == {"escalated", "reminder", "stale", "restored", "recovered"}
    # ...and so is every alarm message; only stale and restored are not sent.
    alarms = [t for t in loud_texts if t not in stale_texts(loud_texts)]
    assert len(stale_texts(loud_texts)) == 2
    assert quiet_texts == alarms
    assert any(t.startswith("Reminder") for t in alarms)
    assert any(t.startswith("Recovered") for t in alarms)


# system_recipients: [] ----------------------------------------------------------


def test_empty_system_recipients_log_a_vrm_outage_without_sending(
    harness: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    harness.write_config(system=[])
    harness.vrm.set("tsT", 20, -10)
    with caplog.at_level(logging.INFO), harness.service() as service:
        harness.cycle(service)
        harness.vrm.fail(503)
        harness.cycle(service, 5)
        assert service.relay.status.degraded == 1
        harness.vrm.heal()
        harness.clock.advance(timedelta(minutes=30))  # past the VRM backoff
        harness.cycle(service, 3)
        assert service.relay.status.degraded == 0

    texts = harness.voipms.texts()
    assert len(texts) == 1
    assert texts[0].startswith("warning: freezer at cabin")
    assert len(records(caplog, "monitoring.degraded")) == 1
    assert len(records(caplog, "monitoring.restored")) == 1


def test_empty_system_recipients_send_no_storage_notice(harness: Harness) -> None:
    harness.write_config(system=[])
    real = harness.root / "real-state"
    real.mkdir(mode=0o700)
    link = harness.root / "linked-state"
    link.symlink_to(real)  # refused: the relay runs from memory instead
    harness.vrm.set("tsT", 20, -10)
    with harness.service(state_dir=link) as service:
        harness.cycle(service, 2)
        health = service.runtime.delivery.health()

    texts = harness.voipms.texts()
    assert len(texts) == 1
    assert texts[0].startswith("warning: freezer at cabin")
    assert not health.persistence_healthy


def test_empty_system_recipients_send_no_rate_limit_summary(harness: Harness) -> None:
    rules = [
        freezer_rule(
            id=f"probe-{n}",
            measurement={"code": "tsT", "instance": n},
            recipients=["owner_sms"],
            levels=[{"name": "warning", "threshold": 0}],
            reminder_max=0,
        )
        for n in range(6)
    ]
    harness.write_config(per_hour=4, per_day=10, rules=rules, system=[])
    for n in range(6):
        harness.vrm.set("tsT", n, 5)
    with harness.service() as service:
        harness.cycle(service, 3)
        harness.clock.advance(timedelta(minutes=70))
        harness.cycle(service, 3)
        health = service.runtime.delivery.health()

    texts = harness.voipms.texts()
    assert len(texts) == 4
    assert not any("held back" in t for t in texts)
    assert health.suppressed_pending == 2

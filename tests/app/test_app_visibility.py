"""What an operator can see: the loaded configuration and escalations the cooldown holds.

Every identifier, number and address here is fictitious.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock

import pytest
from app_helpers import DID, OWNER_PHONE, PARTNER_PHONE, SECRETS, FakeStop, freezer_rule

from vrm_alert_relay.app import relay as relay_module
from vrm_alert_relay.app import rules as rules_module
from vrm_alert_relay.app import service as service_module
from vrm_alert_relay.app.rules import (
    FINGERPRINT_LENGTH,
    FINGERPRINT_UNAVAILABLE,
    bind_rules,
    config_fingerprint,
)
from vrm_alert_relay.config import load_config
from vrm_alert_relay.engine import RuleState

if TYPE_CHECKING:
    from pathlib import Path

    from app_helpers import Harness

FORBIDDEN = (
    *SECRETS,
    OWNER_PHONE,
    PARTNER_PHONE,
    DID,
    "202 555 0142",
    "5550142",
    "5550177",
    "example.invalid",
    "https://",
)


def records(caplog: pytest.LogCaptureFixture, event: str) -> list[logging.LogRecord]:
    return [r for r in caplog.records if getattr(r, "event", None) == event]


def fingerprint_of(path: Path) -> str:
    return config_fingerprint(load_config(path))


def rewrite(path: Path, change: Any) -> None:
    data = json.loads(path.read_text())
    change(data)
    path.write_text(json.dumps(data))


# The configuration fingerprint


def test_fingerprint_is_short_hex_and_stable_across_loads(harness: Harness) -> None:
    path = harness.write_config()

    first = fingerprint_of(path)

    assert re.fullmatch(f"[0-9a-f]{{{FINGERPRINT_LENGTH}}}", first)
    assert fingerprint_of(path) == first
    path.write_text(json.dumps(json.loads(path.read_text()), indent=4, sort_keys=True))
    assert fingerprint_of(path) == first


def test_fingerprint_changes_when_only_one_threshold_changes(harness: Harness) -> None:
    path = harness.write_config()
    before = fingerprint_of(path)

    rewrite(path, lambda data: data["rules"][0]["levels"][1].update(threshold=-7.5))

    assert fingerprint_of(path) != before


@pytest.mark.parametrize(
    "change",
    [
        lambda data: data["rules"][0].update(hysteresis=2),
        lambda data: data["rules"][0].update(cooldown_minutes=30),
        lambda data: data["rules"][0].update(reminder_max=1),
        lambda data: data["rules"][0].update(stale_after_minutes=90),
        lambda data: data["rules"][0].update(display_unit="degF"),
        lambda data: data["rules"][0].update(stale_notify=False),
        lambda data: data["rules"][0].update(recipients=["owner_sms"]),
        lambda data: data["rules"][0]["levels"][0].update(name="watch"),
        lambda data: data["sending"].update(enabled=False),
        lambda data: data["providers"]["voipms"].update(enabled=False),
    ],
)
def test_fingerprint_follows_alerting_settings(harness: Harness, change: Any) -> None:
    path = harness.write_config()
    before = fingerprint_of(path)

    rewrite(path, change)

    assert fingerprint_of(path) != before


def test_fingerprint_derives_from_no_recipient_destination_or_secret(harness: Harness) -> None:
    path = harness.write_config()
    before = fingerprint_of(path)

    def change_destinations(data: dict[str, Any]) -> None:
        data["recipients"]["owner_sms"]["phone"] = "+1 202 555 0199"
        data["recipients"]["partner_sms"]["phone"] = "+1 202 555 0188"
        data["providers"]["voipms"]["did"] = "2025550111"
        data["providers"]["voipms"]["base_url"] = "https://other.example.invalid/api"
        data["vrm"]["base_url"] = "https://vrm-other.example.invalid/v2"
        data["vrm"]["installations"][0]["site_id"] = 777777

    rewrite(path, change_destinations)
    for name in ("vrm_token", "voipms_user", "voipms_password"):
        harness.secret(name, f"fake-different-{name}-0000")

    assert fingerprint_of(path) == before


PHONE_NAMED = {
    "2025550142": {"provider": "voipms", "phone": "+1 202 555 0142"},
    "audit": {"provider": "log"},
}


def rename_recipient(old: str, new: str) -> Any:
    """Rename a recipient in place, keeping its position, and every reference to it."""

    def change(data: dict[str, Any]) -> None:
        data["recipients"] = {
            (new if name == old else name): value for name, value in data["recipients"].items()
        }
        for names in (data["system_recipients"], *(rule["recipients"] for rule in data["rules"])):
            names[:] = [new if name == old else name for name in names]

    return change


def test_a_phone_shaped_recipient_name_feeds_only_its_placeholder(harness: Harness) -> None:
    path = harness.write_config(
        recipients=PHONE_NAMED,
        rules=[freezer_rule(recipients=["2025550142", "audit"])],
        system=["2025550142"],
    )
    before = fingerprint_of(path)

    rewrite(path, rename_recipient("2025550142", "2025550177"))

    assert fingerprint_of(path) == before


def test_renaming_a_displayable_recipient_changes_the_fingerprint(harness: Harness) -> None:
    path = harness.write_config(
        recipients=PHONE_NAMED,
        rules=[freezer_rule(recipients=["2025550142", "audit"])],
        system=["2025550142"],
    )
    before = fingerprint_of(path)

    rewrite(path, rename_recipient("audit", "audit_log"))

    assert fingerprint_of(path) != before


def test_a_fingerprint_that_cannot_be_computed_does_not_stop_startup(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: object) -> dict[str, object]:
        raise RuntimeError

    monkeypatch.setattr(rules_module, "_rule_settings", broken)
    harness.write_config(health={"enabled": True})
    with harness.service() as service:
        assert service.run(FakeStop(limit=1), max_cycles=1) == 1
        service.publish_health()
        document = json.loads(service.health_state.body())

    assert service.config_fingerprint == FINGERPRINT_UNAVAILABLE
    assert document["config_fingerprint"] == FINGERPRINT_UNAVAILABLE


def raising_loggers(monkeypatch: pytest.MonkeyPatch) -> Mock:
    """Make every INFO record of the service, relay and rule modules raise."""
    raising = Mock(side_effect=RuntimeError("log handler failed"))
    for module in (service_module, relay_module, rules_module):
        monkeypatch.setattr(module.logger, "info", raising)
    return raising


def test_startup_and_cycles_proceed_when_logging_raises(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -10)
    raising = raising_loggers(monkeypatch)
    with harness.service() as service:
        assert service.run(FakeStop(limit=2), max_cycles=2) == 2

    assert raising.call_count > 0
    assert harness.voipms.texts() == [
        "warning: freezer at cabin: Fictitious tsT is -10 (2035-01-01 00:00 UTC)"
    ]


def test_a_released_escalation_is_delivered_in_its_cycle_when_logging_raises(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.write_config()
    with harness.service() as service:
        for value in (-10, -30, -10):
            harness.vrm.set("tsT", 20, value)
            harness.cycle(service)
        harness.cycle(service, 12)
        assert len(harness.voipms.texts()) == 2  # the warning and its recovery
        raising = raising_loggers(monkeypatch)
        report = service.relay.run_cycle()

    assert raising.call_count > 0
    assert report.events == 1
    assert len(harness.voipms.texts()) == 3
    assert harness.voipms.texts()[-1].startswith("warning: freezer at cabin")


def test_a_held_escalation_is_counted_when_logging_raises(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.write_config()
    with harness.service() as service:
        for value in (-10, -30):
            harness.vrm.set("tsT", 20, value)
            harness.cycle(service)
        raising_loggers(monkeypatch)
        harness.vrm.set("tsT", 20, -10)
        report = service.relay.run_cycle()

    assert report.held == 1
    assert report.events == 0


def test_startup_logs_the_fingerprint_and_every_rule_without_destinations(
    harness: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    second = freezer_rule(
        id="cabin-cold",
        direction="falling",
        levels=[{"name": "cold", "threshold": 5}],
        hysteresis=0.5,
        display_unit="degF",
        recipients=["partner_sms"],
    )
    harness.write_config(rules=[freezer_rule(), second])
    with caplog.at_level(logging.INFO), harness.service() as service:
        service.run(FakeStop(limit=1), max_cycles=1)
        fingerprint = service.config_fingerprint

    (started,) = records(caplog, "service.started")
    assert started.__dict__["config_fingerprint"] == fingerprint
    loaded = [record.__dict__ for record in records(caplog, "relay.rule_loaded")]
    assert [
        {
            key: entry[key]
            for key in ("rule_id", "direction", "levels", "hysteresis", "display_unit")
        }
        for entry in loaded
    ] == [
        {
            "rule_id": "freezer",
            "direction": "rising",
            "levels": [
                {"name": "warning", "threshold": -12},
                {"name": "alert", "threshold": -8},
                {"name": "critical", "threshold": -4},
            ],
            "hysteresis": 1,
            "display_unit": None,
        },
        {
            "rule_id": "cabin-cold",
            "direction": "falling",
            "levels": [{"name": "cold", "threshold": 5}],
            "hysteresis": 0.5,
            "display_unit": "degF",
        },
    ]
    for record in (started, *records(caplog, "relay.rule_loaded")):
        text = json.dumps(record.__dict__, default=str)
        assert "recipients" not in record.__dict__
        for forbidden in FORBIDDEN:
            assert forbidden not in text, forbidden


# Escalations held by the cooldown


def cycle_records(caplog: pytest.LogCaptureFixture) -> list[dict[str, Any]]:
    return [record.__dict__ for record in records(caplog, "relay.cycle")]


def test_a_held_escalation_is_counted_logged_and_released(
    harness: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    harness.write_config()
    with harness.service() as service, caplog.at_level(logging.INFO):
        for value in (-10, -30, -10):
            harness.vrm.set("tsT", 20, value)
            harness.cycle(service)
        held_cycle = cycle_records(caplog)[-1]
        harness.cycle(service, 12)
        assert len(harness.voipms.texts()) == 2  # the warning and its recovery
        harness.cycle(service, 2)

    assert held_cycle["events"] == 0
    assert held_cycle["suppressed"] == 0
    assert held_cycle["held"] == 1
    (held,) = records(caplog, "relay.escalation_held")
    assert held.__dict__["rule_id"] == "freezer"
    assert held.__dict__["level"] == "warning"
    assert held.__dict__["cooldown_expires_at"] == "2035-01-01T00:15:00+00:00"
    (released,) = records(caplog, "relay.escalation_released")
    assert released.__dict__["rule_id"] == "freezer"
    assert released.__dict__["level"] == "warning"
    assert released.__dict__["notified"] is True
    assert [entry["held"] for entry in cycle_records(caplog)] == [0, 0] + [1] * 13 + [0, 0]
    assert harness.voipms.texts()[-1].startswith("warning: freezer at cabin")
    assert len(harness.voipms.texts()) == 3


def test_a_held_escalation_ended_by_recovery_is_released_without_a_message(
    harness: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    harness.write_config()
    with harness.service() as service, caplog.at_level(logging.INFO):
        for value in (-10, -30, -10, -30):
            harness.vrm.set("tsT", 20, value)
            harness.cycle(service)

    assert len(records(caplog, "relay.escalation_held")) == 1
    (released,) = records(caplog, "relay.escalation_released")
    assert released.__dict__["level"] == "warning"
    assert released.__dict__["notified"] is False
    assert [entry["held"] for entry in cycle_records(caplog)] == [0, 0, 1, 0]
    assert len(harness.voipms.texts()) == 2  # the first warning and its recovery only


def test_a_hold_without_a_known_send_time_is_logged_without_an_expiry(
    harness: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    binding = bind_rules(load_config(harness.write_config()))[0]
    held = RuleState(active_level="warning", episode=1, pending_escalation="warning")
    cycle = relay_module._CycleState()

    with caplog.at_level(logging.INFO):
        relay_module._report_hold(binding, RuleState(), held, [], cycle)

    assert cycle.held == 1
    (record,) = records(caplog, "relay.escalation_held")
    assert record.__dict__["cooldown_expires_at"] is None

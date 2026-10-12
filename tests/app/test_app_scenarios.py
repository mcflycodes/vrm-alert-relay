"""End-to-end scenarios (R32): mocked VRM and VoIP.ms APIs, real everything else.

Each test drives the real VRM adapter, rules engine, templates, delivery
engine, state store and VoIP.ms provider through the service's poll cycle.
"""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from app_helpers import (
    BARN_SITE,
    CABIN_SITE,
    OWNER_PHONE,
    SECRETS,
    START,
    VOIPMS_HOST,
    freezer_rule,
)

from vrm_alert_relay.delivery import STORAGE_NOTICE_TEXT
from vrm_alert_relay.engine import FUTURE_TOLERANCE, RuleState
from vrm_alert_relay.vrm import TimestampPolicy

if TYPE_CHECKING:
    import httpx
    from app_helpers import Harness

DEGRADED = "monitoring of cabin is degraded"
RESTORED = "monitoring of cabin is restored"


def monitoring_texts(harness: Harness) -> list[str]:
    return [text for text in harness.voipms.texts() if "VRM Alert Relay: monitoring" in text]


def test_escalation_ladder_sends_one_sms_per_level(harness: Harness) -> None:
    harness.write_config()
    with harness.service() as service:
        for value in (-20, -10, -10, -6, -2, -2):
            harness.vrm.set("tsT", 20, value)
            harness.cycle(service)

    assert harness.voipms.sent() == [
        (OWNER_PHONE, "warning: freezer at cabin: Fictitious tsT is -10 (2035-01-01 00:01 UTC)"),
        (OWNER_PHONE, "alert: freezer at cabin: Fictitious tsT is -6 (2035-01-01 00:03 UTC)"),
        (OWNER_PHONE, "critical: freezer at cabin: Fictitious tsT is -2 (2035-01-01 00:04 UTC)"),
    ]


def test_level_messages_and_recovery_reach_sms(harness: Harness) -> None:
    rule = freezer_rule(
        levels=[
            {"name": "warning", "threshold": -12, "message": "Freezer warming: {value}"},
            {"name": "critical", "threshold": -4},
        ],
    )
    harness.write_config(rules=[rule])
    with harness.service() as service:
        for value in (-10, -1, -30):
            harness.vrm.set("tsT", 20, value)
            harness.cycle(service)

    texts = harness.voipms.texts()
    assert texts[0] == "Freezer warming: -10"
    assert texts[1].startswith("critical: freezer at cabin")
    assert texts[2].startswith("Recovered: freezer at cabin is back to normal")
    assert len(texts) == 3


def test_restart_mid_episode_sends_no_duplicates(harness: Harness) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -10)
    with harness.service() as service:
        harness.cycle(service, 3)
    assert len(harness.voipms.sent()) == 1

    with harness.service() as service:
        harness.cycle(service, 3)
        assert len(harness.voipms.sent()) == 1
        harness.vrm.set("tsT", 20, -2)
        harness.cycle(service)

    texts = harness.voipms.texts()
    assert len(texts) == 2
    assert texts[1].startswith("critical:")


def test_ambiguous_send_is_reconciled_before_it_is_retried(harness: Harness) -> None:
    harness.write_config()
    harness.voipms.sends.append({"status": "mystery"})
    harness.vrm.set("tsT", 20, -10)
    with harness.service() as service:
        harness.cycle(service)
        assert harness.voipms.methods() == ["sendSMS"]
        harness.cycle(service)

    assert harness.voipms.methods() == ["sendSMS", "getSMS", "sendSMS"]
    lookup = harness.voipms.calls[1]
    assert lookup["contact"] == OWNER_PHONE
    assert lookup["did"] == "2025550100"


def test_send_interrupted_by_a_crash_is_reconciled_after_restart(harness: Harness) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -10)
    service = harness.open()

    def power_cut(request: httpx.Request) -> httpx.Response:
        del harness.voipms.handle  # only the first call is cut off
        raise SystemExit("power cut")

    harness.voipms.handle = power_cut  # type: ignore[method-assign]
    with pytest.raises(SystemExit):
        service.relay.run_cycle()
    # The process "died" mid-send: release the lock without flushing anything more.
    service.runtime.store.close()
    service.runtime.providers.close()
    harness.clock.advance(timedelta(minutes=1))

    with harness.service() as service:
        harness.cycle(service)

    assert harness.voipms.methods() == ["getSMS", "sendSMS"]


def test_global_cap_holds_under_a_flood_and_one_summary_follows(harness: Harness) -> None:
    rules = [
        freezer_rule(
            id=f"probe-{n}",
            measurement={"code": "tsT", "instance": n},
            recipients=["owner_sms"],
            levels=[{"name": "warning", "threshold": 0}],
            reminder_max=0,
        )
        for n in range(12)
    ]
    harness.write_config(per_hour=4, per_day=10, rules=rules)
    for n in range(12):
        harness.vrm.set("tsT", n, 5)
    with harness.service() as service:
        harness.cycle(service, 5)
        assert len(harness.voipms.sent()) == 4
        harness.clock.advance(timedelta(minutes=56))
        harness.cycle(service, 3)
        health = service.runtime.delivery.health()

    texts = harness.voipms.texts()
    summaries = [text for text in texts if "held back by the global rate limit" in text]
    assert summaries == [
        "VRM Alert Relay: 8 alert(s) held back by the global rate limit since 2035-01-01 00:00 UTC"
    ]
    assert len(texts) == 5
    assert health.sent_last_hour <= 4
    assert health.suppressed_pending == 0


def test_malicious_vrm_labels_cannot_change_recipients_or_inject_links(
    harness: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    harness.write_config()
    harness.vrm.set(
        "tsT",
        20,
        -10,
        label="https://evil.example.test/x\r\ntel:+12025550199 {rule}",
    )
    harness.vrm.extra_records.append(
        {"code": "dst", "instance": 0, "rawValue": "+12025550199", "recipient": "attacker"}
    )
    with caplog.at_level(logging.INFO), harness.service() as service:
        harness.cycle(service, 2)

    ((dst, text),) = harness.voipms.sent()
    assert dst == OWNER_PHONE
    assert "https://" not in text
    assert "hxxps[:]//evil[.]example[.]test/x" in text
    assert "tel[:]" in text
    assert "{rule}" in text  # inserted literally, never re-parsed
    assert "\r" not in text
    assert "\n" not in text
    assert {call["dst"] for call in harness.voipms.calls if "dst" in call} == {OWNER_PHONE}
    assert not any(secret in caplog.text for secret in SECRETS)


def test_non_numeric_vrm_values_count_as_measurement_problems(harness: Harness) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, "-10; DROP TABLE")
    with harness.service() as service:
        harness.cycle(service, 3)

    # The rule never had a usable sample, so only the monitor reports it.
    assert harness.voipms.texts() == [
        (
            "VRM Alert Relay: monitoring of cabin is degraded since 2035-01-01 00:00 UTC; "
            "alerts may be delayed or missed"
        )
    ]


def test_vrm_outage_sends_one_degraded_and_one_restored_across_a_restart(
    harness: Harness,
) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -20)
    with harness.service() as service:
        harness.cycle(service, 2)
        harness.vrm.fail(503)
        harness.cycle(service)
        assert monitoring_texts(harness) == []  # one failed poll is not an outage
        harness.cycle(service, 4)
        assert service.relay.status.degraded == 1

    with harness.service() as service:
        harness.cycle(service, 4)
        assert sum(DEGRADED in text for text in harness.voipms.texts()) == 1
        harness.vrm.heal()
        harness.cycle(service, 3)
        assert service.relay.status.degraded == 0

    texts = monitoring_texts(harness)
    assert texts[0] == (
        "VRM Alert Relay: monitoring of cabin is degraded since 2035-01-01 00:02 UTC; "
        "alerts may be delayed or missed"
    )
    assert texts[1].startswith("VRM Alert Relay: monitoring of cabin is restored (2035-01-01 ")
    assert len(harness.voipms.texts()) == 2


def test_restart_after_an_outage_ended_sends_the_restored_notice(harness: Harness) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -20)
    harness.vrm.fail(503)
    with harness.service() as service:
        harness.cycle(service, 3)
    harness.vrm.heal()
    with harness.service() as service:
        harness.cycle(service, 2)

    texts = harness.voipms.texts()
    assert [DEGRADED in t for t in texts] == [True, False]
    assert RESTORED in texts[1]


def test_flapping_vrm_is_bounded_by_the_monitor_cooldown(harness: Harness) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -20)
    with harness.service() as service:
        harness.cycle(service)
        for _ in range(3):
            harness.vrm.fail(503)
            harness.cycle(service, 2)
            harness.vrm.heal()
            harness.cycle(service, 1)

    texts = monitoring_texts(harness)
    assert [DEGRADED in text for text in texts] == [True, False]
    assert len(harness.voipms.texts()) == 2


def test_one_installation_down_degrades_only_that_installation(harness: Harness) -> None:
    harness.write_config(
        installations=[
            {"id": "cabin", "site_id": CABIN_SITE},
            {"id": "barn", "site_id": BARN_SITE},
        ]
    )
    harness.vrm.set("tsT", 20, -20)
    harness.vrm.fail(503, BARN_SITE)
    with harness.service() as service:
        harness.cycle(service, 3)
        status = service.relay.status

    assert harness.voipms.texts() == [
        (
            "VRM Alert Relay: monitoring of barn is degraded since 2035-01-01 00:00 UTC; "
            "alerts may be delayed or missed"
        )
    ]
    assert (status.failing, status.degraded, status.last_successful_poll_at) == (1, 1, None)


def test_auth_failure_alerts_at_once_and_only_once(harness: Harness) -> None:
    harness.write_config()
    harness.vrm.fail(401)
    with harness.service() as service:
        harness.cycle(service)
        assert monitoring_texts(harness) == [
            (
                "VRM Alert Relay: monitoring of cabin is degraded since 2035-01-01 00:00 UTC; "
                "alerts may be delayed or missed"
            )
        ]
        harness.cycle(service, 10)

    assert len(harness.vrm.requests) == 1  # 401 is not retried as transient; it waits an hour
    assert len(monitoring_texts(harness)) == 1


def test_auth_failure_after_running_alerts_and_recovers(harness: Harness) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -20)
    with harness.service() as service:
        harness.cycle(service)
        harness.vrm.fail(403)
        harness.cycle(service)
        assert len(harness.voipms.texts()) == 1
        harness.vrm.heal()
        harness.clock.advance(timedelta(hours=1))
        harness.cycle(service)

    texts = harness.voipms.texts()
    assert DEGRADED in texts[0]
    assert RESTORED in texts[1]


def test_state_persistence_failure_keeps_alerting(harness: Harness) -> None:
    harness.write_config()
    real = harness.root / "real-state"
    real.mkdir(mode=0o700)
    link = harness.root / "linked-state"
    link.symlink_to(real)  # refused: the relay runs from memory instead
    harness.vrm.set("tsT", 20, -10)
    with harness.service(state_dir=link) as service:
        harness.cycle(service, 2)
        health = service.runtime.delivery.health()
        service.publish_health()
        body = service.health_state.body()

    texts = harness.voipms.texts()
    assert texts[0].startswith("warning: freezer at cabin")
    assert texts[1] == STORAGE_NOTICE_TEXT
    assert len(texts) == 2
    assert not health.persistence_healthy
    assert not health.durable_accounting
    assert b'"status":"degraded"' in body
    assert list(real.iterdir()) == []


def test_dry_run_default_sends_nothing_live(
    harness: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    harness.write_config(sending=False)
    harness.vrm.set("tsT", 20, -2)
    with caplog.at_level(logging.INFO), harness.service() as service:
        assert service.dry_run
        harness.cycle(service, 2)
        health = service.runtime.delivery.health()

    assert VOIPMS_HOST not in harness.network.hosts
    dry = [r for r in caplog.records if getattr(r, "event", None) == "provider.dry_run"]
    assert sorted(r.__dict__["provider"] for r in dry) == ["log", "voipms"]
    sms = next(r for r in dry if r.__dict__["provider"] == "voipms")
    assert sms.__dict__["recipient"].endswith("0142")
    assert OWNER_PHONE not in sms.__dict__["recipient"]
    assert health.sent_last_hour == 0
    assert health.dry_run_sent_last_hour == 2


def test_enabled_provider_stays_dry_run_until_sending_is_enabled(harness: Harness) -> None:
    harness.write_config(sending=False, voipms=True)
    harness.vrm.set("tsT", 20, -2)
    with harness.service() as service:
        harness.cycle(service, 2)

    assert harness.voipms.calls == []


def test_log_output_never_holds_secrets_or_full_phone_numbers(
    harness: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -10)
    harness.vrm.fail(401)
    with caplog.at_level(logging.DEBUG), harness.service() as service:
        harness.cycle(service, 2)
        harness.vrm.heal()
        harness.clock.advance(timedelta(hours=1))
        harness.cycle(service, 2)

    for record in caplog.records:
        rendered = f"{record.getMessage()} {record.__dict__}"
        assert not any(secret in rendered for secret in SECRETS)
        assert OWNER_PHONE not in rendered.replace("-", "")


# Persisted failure streaks (monitoring across restarts) ---------------------------


def restart_cycles(harness: Harness, count: int) -> None:
    """Run ``count`` cycles, restarting the relay before each one."""
    for _ in range(count):
        with harness.service() as service:
            harness.cycle(service)


def test_a_restart_after_the_first_failed_poll_still_reports_the_outage(
    harness: Harness,
) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -20)
    restart_cycles(harness, 1)
    harness.vrm.fail(503)
    restart_cycles(harness, 1)
    assert monitoring_texts(harness) == []

    restart_cycles(harness, 1)

    assert monitoring_texts(harness) == [
        (
            "VRM Alert Relay: monitoring of cabin is degraded since 2035-01-01 00:01 UTC; "
            "alerts may be delayed or missed"
        )
    ]


def test_restarts_during_an_announced_outage_send_one_degraded_and_one_restored(
    harness: Harness,
) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -20)
    restart_cycles(harness, 1)
    harness.vrm.fail(503)
    restart_cycles(harness, 6)
    harness.vrm.heal()
    restart_cycles(harness, 2)

    texts = monitoring_texts(harness)
    assert [DEGRADED in t for t in texts] == [True, False]
    assert RESTORED in texts[1]
    assert len(harness.voipms.texts()) == 2


def test_restarts_during_cooldown_delayed_flapping_report_the_outage_once_it_is_due(
    harness: Harness,
) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -20)
    restart_cycles(harness, 1)
    harness.vrm.fail(503)
    restart_cycles(harness, 2)  # degraded at 00:02
    harness.vrm.heal()
    restart_cycles(harness, 1)  # restored at 00:03
    harness.vrm.fail(503)
    restart_cycles(harness, 4)  # a new outage inside the 15-minute cooldown waits
    assert [DEGRADED in t for t in monitoring_texts(harness)] == [True, False]

    harness.clock.advance(timedelta(minutes=10))
    restart_cycles(harness, 1)  # the cooldown is over and the outage is still open

    texts = monitoring_texts(harness)
    assert [DEGRADED in t for t in texts] == [True, False, True]
    assert texts[2] == (
        "VRM Alert Relay: monitoring of cabin is degraded since 2035-01-01 00:04 UTC; "
        "alerts may be delayed or missed"
    )


def test_an_unreadable_stored_streak_reports_the_outage_on_the_next_failure(
    harness: Harness,
) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -20)
    with harness.service() as service:
        harness.cycle(service)
        service.runtime.delivery.accept_cycle(
            rule_states={"monitoring-streak:cabin": RuleState(newest_value=0.5)},
            notifications=[],
        )
    harness.vrm.fail(503)

    restart_cycles(harness, 1)

    assert len(monitoring_texts(harness)) == 1


# Rules that never had a sample -----------------------------------------------------


def test_a_fresh_install_with_vrm_down_sends_only_the_monitoring_alert(harness: Harness) -> None:
    harness.write_config()
    harness.vrm.fail(503)
    with harness.service() as service:
        harness.cycle(service, 3)
        harness.clock.advance(timedelta(hours=1))
        harness.cycle(service, 2)

    assert harness.voipms.texts() == [
        (
            "VRM Alert Relay: monitoring of cabin is degraded since 2035-01-01 00:00 UTC; "
            "alerts may be delayed or missed"
        )
    ]


def test_stale_data_is_reported_once_a_rule_has_had_a_sample(harness: Harness) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -20)
    with harness.service() as service:
        harness.cycle(service)
        harness.vrm.values.clear()  # the measurement stops reporting
        harness.clock.advance(timedelta(minutes=40))
        harness.cycle(service)

    texts = harness.voipms.texts()
    assert texts[0] == (
        "Stale data: freezer at cabin has had no new Fictitious tsT reading "
        "since 2035-01-01 00:00 UTC"
    )


def test_a_restart_keeps_a_rule_observed(harness: Harness) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -20)
    with harness.service() as service:
        harness.cycle(service)
    harness.vrm.fail(503)
    harness.clock.advance(timedelta(minutes=40))
    with harness.service() as service:
        harness.cycle(service)

    texts = harness.voipms.texts()
    assert any(t.startswith("Stale data: freezer at cabin") for t in texts)
    assert monitoring_texts(harness) == []  # one failed poll is not yet an outage


def test_an_unusable_sample_leaves_a_rule_unobserved(harness: Harness) -> None:
    harness.write_config()
    # Accepted by the VRM adapter (within five minutes) but too far ahead for the engine.
    harness.vrm.skew = timedelta(minutes=3)
    harness.vrm.set("tsT", 20, -2)
    with harness.service() as service:
        harness.cycle(service)
        state = service.runtime.delivery.rule_state("freezer")

    assert harness.voipms.texts() == []
    assert state == RuleState()


# Sample usability: one bound, and no silent path -----------------------------------


def test_future_skewed_samples_degrade_monitoring_instead_of_vanishing(
    harness: Harness,
) -> None:
    harness.write_config()
    harness.vrm.skew = timedelta(minutes=3)
    harness.vrm.set("tsT", 20, -2)  # would be critical
    with harness.service() as service:
        harness.cycle(service, 3)
        service.publish_health()
        document = json.loads(service.health_state.body())

    assert harness.voipms.texts() == [
        (
            "VRM Alert Relay: monitoring of cabin is degraded since 2035-01-01 00:00 UTC; "
            "alerts may be delayed or missed"
        )
    ]
    assert document["status"] == "degraded"
    assert document["monitoring"]["degraded_installations"] == 1


def test_a_sample_the_engine_refuses_is_reported_to_the_monitor(
    harness: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    harness.write_config()
    harness.vrm.skew = timedelta(minutes=3)
    harness.vrm.set("tsT", 20, -2)
    with harness.service() as service, caplog.at_level(logging.WARNING):
        # Defence in depth: a parser that let the reading through anyway.
        service.adapter._timestamps = TimestampPolicy(max_future_skew=timedelta(minutes=10))
        harness.cycle(service, 2)
        service.publish_health()
        document = json.loads(service.health_state.body())

    assert monitoring_texts(harness) == [
        (
            "VRM Alert Relay: monitoring of cabin is degraded since 2035-01-01 00:00 UTC; "
            "alerts may be delayed or missed"
        )
    ]
    assert len(harness.voipms.texts()) == 1
    assert document["status"] == "degraded"
    rejected = [r for r in caplog.records if getattr(r, "event", None) == "relay.sample_rejected"]
    assert [r.__dict__["reason"] for r in rejected] == ["unusable", "unusable"]
    degraded = [r for r in caplog.records if getattr(r, "event", None) == "monitoring.degraded"]
    assert degraded[0].__dict__["reason"] == "measurement_unusable"


def test_a_sample_older_than_the_newest_is_reported_to_the_monitor(harness: Harness) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -20)
    with harness.service() as service:
        harness.cycle(service, 2)
        harness.vrm.skew = timedelta(minutes=-10)  # the device's clock jumped back
        harness.cycle(service, 2)

    assert monitoring_texts(harness) == [
        (
            "VRM Alert Relay: monitoring of cabin is degraded since 2035-01-01 00:02 UTC; "
            "alerts may be delayed or missed"
        )
    ]


def test_the_same_reading_again_is_not_a_problem(harness: Harness) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -20)
    harness.vrm.now = lambda: START  # the GX device logged nothing new
    with harness.service() as service:
        harness.cycle(service, 5)
        assert service.relay.status.failing == 0

    assert harness.voipms.texts() == []


def test_a_sample_within_the_tolerance_is_evaluated_normally(harness: Harness) -> None:
    harness.write_config()
    harness.vrm.skew = FUTURE_TOLERANCE
    harness.vrm.set("tsT", 20, -2)
    with harness.service() as service:
        harness.cycle(service, 3)
        assert service.relay.status.failing == 0

    assert harness.voipms.texts() == [
        "critical: freezer at cabin: Fictitious tsT is -2 (2035-01-01 00:01 UTC)"
    ]

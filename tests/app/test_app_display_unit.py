"""A rule's display_unit changes only rendered text, never evaluation or delivery."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest
from app_helpers import CABIN_SITE, OWNER_PHONE, START, freezer_rule

from vrm_alert_relay.app import rules as rules_module
from vrm_alert_relay.app.rules import RuleBinding, rule_spec
from vrm_alert_relay.config import Rule
from vrm_alert_relay.engine import Event, EventKind, RuleState, Sample, evaluate

if TYPE_CHECKING:
    from app_helpers import Harness

TIME = "(2035-01-01 00:00 UTC)"


def cold_rule(**overrides: Any) -> dict[str, Any]:
    """A falling rule: the cabin getting too cold."""
    return freezer_rule(
        id="cabin-cold",
        direction="falling",
        levels=[
            {"name": "warning", "threshold": 5},
            {"name": "critical", "threshold": 0},
        ],
        **overrides,
    )


def binding(rule: dict[str, Any]) -> RuleBinding:
    return RuleBinding.from_rule(Rule.model_validate(rule))


def event(
    kind: EventKind, value: float | None, level: str | None = "critical", rule_id: str = "freezer"
) -> Event:
    return Event(
        rule_id=rule_id,
        episode=1,
        kind=kind,
        level=level,
        value=value,
        sample_time=START,
        event_id="evt_fake_0001",
    )


@pytest.mark.parametrize(
    ("kind", "level", "text"),
    [
        (EventKind.ESCALATED, "critical", f"critical: freezer at cabin: Freezer is 25.7°F {TIME}"),
        (
            EventKind.REMINDER,
            "critical",
            f"Reminder, still critical: freezer at cabin: Freezer is 25.7°F {TIME}",
        ),
        (
            EventKind.RECOVERED,
            None,
            f"Recovered: freezer at cabin is back to normal: Freezer is 25.7°F {TIME}",
        ),
        (
            EventKind.RESTORED,
            None,
            f"Data restored: freezer at cabin is reporting again: Freezer is 25.7°F {TIME}",
        ),
    ],
)
def test_rising_rule_shows_fahrenheit(kind: EventKind, level: str | None, text: str) -> None:
    rule = binding(freezer_rule(display_unit="degF"))
    assert rule.render(event(kind, -3.5, level), "Freezer", "°C") == text


@pytest.mark.parametrize(
    ("value", "shown"),
    [(4.0, "39.2°F"), (0.0, "32°F"), (-1.0, "30.2°F"), (-17.8, "0°F"), (-23.33, "-10°F")],
)
def test_falling_rule_shows_fahrenheit_including_negative_values(value: float, shown: str) -> None:
    rule = binding(cold_rule(display_unit="degF"))
    text = rule.render(event(EventKind.ESCALATED, value, rule_id="cabin-cold"), "Cabin", "°C")
    assert text == f"critical: cabin-cold at cabin: Cabin is {shown} {TIME}"


def test_celsius_display_rounds_and_shows_the_unit() -> None:
    rule = binding(freezer_rule(display_unit="degC"))
    text = rule.render(event(EventKind.ESCALATED, -3.456), "Freezer", "°C")
    assert text == f"critical: freezer at cabin: Freezer is -3.5°C {TIME}"


def test_level_messages_use_the_display_unit() -> None:
    rule = binding(
        freezer_rule(
            display_unit="degF",
            levels=[{"name": "critical", "threshold": -4, "message": "Freezer at {value} {unit}"}],
        )
    )
    assert rule.render(event(EventKind.ESCALATED, -3.5), None, "°C") == "Freezer at 25.7 °F"
    assert rule.render(event(EventKind.REMINDER, -3.5), None, "°C") == (
        "Reminder: Freezer at 25.7 °F"
    )


def test_stale_data_text_is_unchanged() -> None:
    stale = event(EventKind.STALE, None, None)
    plain = binding(freezer_rule()).render(stale, "Freezer", "°C")
    assert binding(freezer_rule(display_unit="degF")).render(stale, "Freezer", "°C") == plain


@pytest.mark.parametrize(("reported", "shown"), [("V", "-3.5V"), ("°F", "-3.5°F"), (None, "-3.5")])
def test_a_unit_that_is_not_celsius_falls_back_to_the_reported_value(
    caplog: pytest.LogCaptureFixture, reported: str | None, shown: str
) -> None:
    rule = binding(freezer_rule(display_unit="degF"))
    with caplog.at_level(logging.WARNING, logger="vrm_alert_relay.app.rules"):
        text = rule.render(event(EventKind.ESCALATED, -3.5), "Freezer", reported)
    assert text == f"critical: freezer at cabin: Freezer is {shown} {TIME}"
    (record,) = caplog.records
    assert record.__dict__["event"] == "relay.display_unit_fallback"
    assert record.__dict__["rule_id"] == "freezer"


def test_a_reported_unit_in_the_fallback_is_untrusted() -> None:
    rule = binding(freezer_rule(display_unit="degF"))
    text = rule.render(event(EventKind.ESCALATED, -3.5), "Freezer", "ex.example")
    assert text == f"critical: freezer at cabin: Freezer is -3.5ex[.]example {TIME}"


def test_without_display_unit_the_reported_unit_is_not_shown(
    caplog: pytest.LogCaptureFixture,
) -> None:
    rule = binding(freezer_rule())
    with caplog.at_level(logging.WARNING):
        text = rule.render(event(EventKind.ESCALATED, -3.5), "Freezer", "°C")
    assert text == rule.render(event(EventKind.ESCALATED, -3.5), "Freezer", None)
    assert text == f"critical: freezer at cabin: Freezer is -3.5 {TIME}"
    assert caplog.records == []


@pytest.mark.parametrize("make_rule", [freezer_rule, cold_rule])
def test_engine_decisions_are_identical_with_and_without_display_unit(
    make_rule: Any,
) -> None:
    plain = Rule.model_validate(make_rule())
    shown = Rule.model_validate(make_rule(display_unit="degF"))
    assert rule_spec(plain) == rule_spec(shown)
    values = [-20.0, -10.0, 6.0, -6.0, 3.0, -2.0, -1.5, 0.5, -0.5, 7.0, -30.0, 9.0, 9.0]
    states = {"plain": RuleState(), "shown": RuleState()}
    events: dict[str, list[Event]] = {"plain": [], "shown": []}
    for step, value in enumerate(values):
        now = START + timedelta(minutes=20 * step)
        for name, rule in (("plain", plain), ("shown", shown)):
            states[name], new = evaluate(rule_spec(rule), states[name], Sample(value, now), now)
            events[name].extend(new)
        assert states["plain"] == states["shown"]
    later = START + timedelta(hours=24)
    for name, rule in (("plain", plain), ("shown", shown)):
        states[name], new = evaluate(rule_spec(rule), states[name], None, later)
        events[name].extend(new)
    assert states["plain"] == states["shown"]
    assert events["plain"] == events["shown"]
    assert {e.kind for e in events["plain"]} >= {EventKind.ESCALATED, EventKind.RECOVERED}


def test_vrm_celsius_reaches_sms_in_fahrenheit(harness: Harness) -> None:
    harness.write_config(rules=[freezer_rule(display_unit="degF")])
    harness.vrm.formats[CABIN_SITE, "tsT", 20] = "%.1F °C"
    with harness.service() as service:
        for value in (-20, -10, -30):
            harness.vrm.set("tsT", 20, value)
            harness.cycle(service)

    assert harness.voipms.sent() == [
        (OWNER_PHONE, "warning: freezer at cabin: Fictitious tsT is 14°F (2035-01-01 00:01 UTC)"),
        (
            OWNER_PHONE,
            (
                "Recovered: freezer at cabin is back to normal: Fictitious tsT is -22°F "
                "(2035-01-01 00:02 UTC)"
            ),
        ),
    ]


def test_a_measurement_not_in_celsius_still_alerts(harness: Harness) -> None:
    harness.write_config(rules=[freezer_rule(display_unit="degF")])
    harness.vrm.formats[CABIN_SITE, "tsT", 20] = "%.2F V"
    with harness.service() as service:
        harness.vrm.set("tsT", 20, -10)
        harness.cycle(service)

    assert harness.voipms.sent() == [
        (OWNER_PHONE, "warning: freezer at cabin: Fictitious tsT is -10V (2035-01-01 00:00 UTC)"),
    ]


def test_a_failing_conversion_still_sends_the_default_text(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError

    monkeypatch.setattr(rules_module, "for_display", broken)
    harness.write_config(rules=[freezer_rule(display_unit="degF")])
    harness.vrm.formats[CABIN_SITE, "tsT", 20] = "%.1F °C"
    with harness.service() as service:
        harness.vrm.set("tsT", 20, -10)
        harness.cycle(service)

    assert harness.voipms.sent() == [
        (OWNER_PHONE, "warning: freezer at cabin: Fictitious tsT is -10 (2035-01-01 00:00 UTC)"),
    ]

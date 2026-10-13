"""Unit tests for the rate limiter, retry policy, routing, and message helpers."""

from __future__ import annotations

import random
from datetime import timedelta
from typing import Any

import pytest
from delivery_fakes import BASE, FakeProvider, FakeReconcilingProvider, make_config

from vrm_alert_relay.config import DeliveryMode
from vrm_alert_relay.delivery import (
    Notification,
    Provider,
    RateLimiter,
    RecipientTarget,
    ReconcilingProvider,
    RetryPolicy,
    Route,
    Routing,
    RuleTarget,
    SystemClock,
    SystemTarget,
    UnknownTargetError,
    delivery_id,
    sanitize_text,
)
from vrm_alert_relay.engine import Event, EventKind
from vrm_alert_relay.state import DeliveryOrigin

# Rate limiter ---------------------------------------------------------------------


def key(n: int) -> tuple[str, str, int]:
    return (f"evt_{n}", "owner_sms", 1)


def test_rate_limiter_uses_sliding_hour_and_day_windows() -> None:
    limiter = RateLimiter(per_hour=2, per_day=3)
    assert limiter.available(0.0)
    limiter.consume(key(1), 0.0)
    limiter.consume(key(2), 1800.0)
    assert not limiter.available(3599.0)
    # The first send leaves the hour window exactly one hour later.
    assert limiter.available(3600.0)
    limiter.consume(key(3), 3600.0)
    assert limiter.counts(3600.0) == (2, 3)
    assert not limiter.available(3 * 3600.0)
    assert limiter.take_expired() == []
    assert limiter.available(86_400.0)
    assert limiter.take_expired() == [key(1)]
    assert limiter.counts(2 * 86_400.0) == (0, 0)
    assert limiter.take_expired() == [key(2), key(3)]
    assert limiter.take_expired() == []


def test_rate_limiter_restores_attempts_in_order() -> None:
    restored = [(float(60 * n), key(n)) for n in range(50)]
    limiter = RateLimiter(per_hour=5, per_day=10, restored=reversed(restored))
    assert not limiter.available(50 * 60.0)
    assert limiter.counts(50 * 60.0) == (50, 50)


@pytest.mark.parametrize(("per_hour", "per_day"), [(0, 1), (1, 0)])
def test_rate_limiter_rejects_non_positive_caps(per_hour: int, per_day: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        RateLimiter(per_hour, per_day)


# Retry policy ------------------------------------------------------------------------


def test_retry_delay_grows_exponentially_with_bounded_jitter() -> None:
    policy = RetryPolicy()
    assert policy.max_attempts == 4
    rng = random.Random(3)  # noqa: S311  # deterministic jitter, not cryptography
    for attempt, ceiling in [(0, 30), (1, 30), (2, 60), (3, 120), (6, 900), (99, 900)]:
        delay = policy.delay(attempt, rng)
        assert timedelta(seconds=ceiling / 2) <= delay <= timedelta(seconds=ceiling)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_retries": -1},
        {"max_retries": 11},
        {"base_delay": timedelta(0)},
        {"base_delay": timedelta(minutes=20), "max_delay": timedelta(minutes=10)},
    ],
)
def test_retry_policy_is_validated(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"max_retries|delays"):
        RetryPolicy(**kwargs)


# Routing ----------------------------------------------------------------------------


def test_routing_resolves_rules_and_recipients_from_config() -> None:
    config = make_config(sending=True, voipms=True)
    routing = Routing.from_config(config)
    names = [route.name for route in routing.resolve(RuleTarget("battery"))]
    assert names == ["owner_sms", "partner_sms", "audit"]
    assert [route.name for route in routing.resolve(SystemTarget())] == ["owner_sms"]
    assert routing.display("owner_sms") == "owner_sms"
    assert routing.display("r2025550123") == "[#4]"
    assert routing.display("r2025550999") == "[#?]"
    assert routing.display("retired") == "retired"
    (route,) = routing.resolve(RecipientTarget("hook"))
    assert route.recipient is config.recipients["hook"]
    assert route.mode is DeliveryMode.DRY_RUN
    assert routing.resolve(RecipientTarget("owner_sms"))[0].mode is DeliveryMode.LIVE


@pytest.mark.parametrize(
    "target", [RuleTarget("unknown"), RecipientTarget("unknown"), "owner_sms", None]
)
def test_routing_rejects_unknown_targets(target: Any) -> None:
    routing = Routing.from_config(make_config())
    with pytest.raises(UnknownTargetError):
        routing.resolve(target)


def test_routing_rejects_inconsistent_construction() -> None:
    config = make_config()
    route = Route("owner_sms", config.recipients["owner_sms"], DeliveryMode.LIVE)
    with pytest.raises(ValueError, match="match"):
        Routing({"partner_sms": route}, {})
    with pytest.raises(UnknownTargetError):
        Routing({"owner_sms": route}, {"freezer": ("owner_sms", "partner_sms")})
    with pytest.raises(UnknownTargetError):
        Routing({"owner_sms": route}, {}, ("partner_sms",))


def test_notification_for_event_targets_the_rule() -> None:
    event = Event(
        rule_id="freezer",
        episode=1,
        kind=EventKind.ESCALATED,
        level="critical",
        value=-3.0,
        sample_time=BASE,
        event_id="evt_" + "0" * 64,
    )
    note = Notification.for_event(event, "Freezer is critical")
    assert note == Notification(
        "evt_" + "0" * 64, "Freezer is critical", RuleTarget("freezer"), DeliveryOrigin.ALARM
    )


# Protocol helpers -------------------------------------------------------------------


def test_delivery_id_is_stable_and_distinct_per_recipient() -> None:
    first = delivery_id("evt_1", "owner_sms")
    assert first == delivery_id("evt_1", "owner_sms")
    assert first != delivery_id("evt_1", "partner_sms")
    assert first != delivery_id("evt_1owner", "_sms")
    assert first.startswith("dlv_")
    assert len(first) == 36


RIGHT_TO_LEFT_OVERRIDE = chr(0x202E)


@pytest.mark.parametrize(
    ("text", "max_length", "expected"),
    [
        ("plain", 10, "plain"),
        ("tab\tand\nnewline", 40, "tab and\nnewline"),
        (f"bell\x07 esc\x1b nul\x00 bidi{RIGHT_TO_LEFT_OVERRIDE}", 40, "bell  esc  nul  bidi "),
        ("x" * 10, 10, "x" * 10),
        ("x" * 11, 10, "x" * 9 + "\u2026"),
    ],
)
def test_sanitize_text(text: str, max_length: int, expected: str) -> None:
    assert sanitize_text(text, max_length=max_length) == expected


def test_protocols_are_runtime_checkable() -> None:
    assert isinstance(FakeProvider(), Provider)
    assert not isinstance(FakeProvider(), ReconcilingProvider)
    assert isinstance(FakeReconcilingProvider(), ReconcilingProvider)
    assert not isinstance(object(), Provider)


def test_system_clock_reads_real_time() -> None:
    clock = SystemClock()
    assert clock.wall().tzinfo is not None
    first = clock.monotonic()
    assert clock.monotonic() >= first

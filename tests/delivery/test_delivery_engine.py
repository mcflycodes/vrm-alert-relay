"""Edge cases of the delivery engine. Every value here is fictitious."""

from __future__ import annotations

import logging
from datetime import timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

import pytest
from delivery_fakes import (
    BASE,
    FailSwitch,
    FakeProvider,
    FakeReconcilingProvider,
    direct_note,
    event_id,
    flaky_store,
    make_config,
    make_engine,
    rule_note,
)

from vrm_alert_relay.delivery import (
    DeliveryEngine,
    DeliveryLimits,
    Notification,
    ReconcileStatus,
    RuleTarget,
    SendResult,
    SendStatus,
)
from vrm_alert_relay.delivery import engine as engine_module
from vrm_alert_relay.engine import RuleState
from vrm_alert_relay.state import (
    Changes,
    DeliveryKind,
    DeliveryRecord,
    DeliveryStatus,
    StateStore,
    Suppression,
)

if TYPE_CHECKING:
    from pathlib import Path


def events_logged(caplog: pytest.LogCaptureFixture) -> list[Any]:
    return [record.__dict__.get("event") for record in caplog.records]


def seed_store(
    path: Path, *records: DeliveryRecord, suppression: Suppression | None = None
) -> None:
    store = StateStore(path)
    assert store.flush(Changes(deliveries=records, suppression=suppression or Suppression()), BASE)
    store.close()


def pending(n: int, recipient: str = "owner_sms", **changes: Any) -> DeliveryRecord:
    fields: dict[str, Any] = {
        "event_id": event_id(n),
        "recipient": recipient,
        "kind": DeliveryKind.EVENT,
        "status": DeliveryStatus.PENDING,
        "text": "Freezer warming",
        "attempts": 0,
        "created_at": BASE,
        "updated_at": BASE,
        "next_attempt_at": BASE,
    }
    fields.update(changes)
    return DeliveryRecord(**fields)


# Construction ---------------------------------------------------------------


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_queue": 0},
        {"max_queue": 10, "max_records": 5},
        {"summary_interval": timedelta(0)},
    ],
)
def test_limits_are_validated(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match=r"must|need"):
        DeliveryLimits(**kwargs)


def test_rejects_objects_that_are_not_providers(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="Provider protocol"):
        DeliveryEngine.from_config(
            make_config(),
            providers={"voipms": FakeProvider()},
            dry_run=object(),  # type: ignore[arg-type]
            store=StateStore(tmp_path),
            now=BASE,
        )


def test_requires_a_provider_for_every_live_recipient(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="voipms"):
        DeliveryEngine.from_config(
            make_config(),
            providers={},
            dry_run=FakeProvider(),
            store=StateStore(tmp_path),
            now=BASE,
        )


def test_dry_run_needs_no_live_providers(tmp_path: Path) -> None:
    engine = DeliveryEngine.from_config(
        make_config(sending=False),
        providers={},
        dry_run=FakeProvider(),
        store=StateStore(tmp_path),
        now=BASE,
    )
    assert engine.health(BASE).queued == 0


def test_default_rng_is_used_when_none_is_given(tmp_path: Path) -> None:
    provider = FakeProvider(default=SendResult(SendStatus.FAILED, retryable=True))
    engine = DeliveryEngine.from_config(
        make_config(),
        providers={"voipms": provider},
        dry_run=FakeProvider(),
        store=StateStore(tmp_path),
        now=BASE,
    )
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    engine.run_due(BASE)
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.next_attempt_at is not None
    assert BASE + timedelta(seconds=15) <= record.next_attempt_at <= BASE + timedelta(seconds=30)


def test_loads_pending_records_and_sends_them(tmp_path: Path) -> None:
    seed_store(tmp_path, pending(1), pending(2, next_attempt_at=None))
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), voipms=provider)
    assert engine.health(BASE).queued == 2
    assert engine.run_due(BASE).delivered == 2


# Intake -------------------------------------------------------------------------


def test_malformed_notifications_are_dropped_and_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), voipms=provider)
    notes: list[Any] = [
        "not a notification",
        Notification(event_id="evt with spaces", text="x", target=RuleTarget("freezer")),
        Notification(event_id="e" * 129, text="x", target=RuleTarget("freezer")),
        Notification(event_id=event_id(1), text=None, target=RuleTarget("freezer")),  # type: ignore[arg-type]
        Notification(event_id=event_id(2), text="x", target="freezer"),  # type: ignore[arg-type]
    ]
    with caplog.at_level(logging.ERROR, logger="vrm_alert_relay.delivery"):
        assert engine.accept_cycle(rule_states={}, notifications=notes, now=BASE) == 0
    assert events_logged(caplog).count("delivery.notification_invalid") == 4
    assert events_logged(caplog).count("delivery.unknown_target") == 1
    engine.run_due(BASE)
    assert provider.sent == []


def test_message_text_is_sanitized_and_bounded(tmp_path: Path) -> None:
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), voipms=provider)
    engine.accept_cycle(
        rule_states={}, notifications=[rule_note(1, text="a\tb\r\nc" + "z" * 5000)], now=BASE
    )
    engine.run_due(BASE)
    text = provider.sent[0].message.text
    assert text.startswith("a b \nc")
    assert len(text) == 1000
    assert text.endswith("…")


def test_queue_bound_holds_back_and_counts_overflow(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    provider = FakeProvider()
    limits = DeliveryLimits(max_queue=2, max_records=3)
    engine = make_engine(StateStore(tmp_path), voipms=provider, limits=limits)
    with caplog.at_level(logging.WARNING, logger="vrm_alert_relay.delivery"):
        queued = engine.accept_cycle(
            rule_states={}, notifications=[rule_note(n) for n in range(10)], now=BASE
        )
    assert queued == 2
    assert "delivery.queue_full" in events_logged(caplog)
    health = engine.health(BASE)
    assert health.queued == 2
    assert health.suppressed_pending == 8
    engine.run_due(BASE)
    # The summary goes first, then the queued deliveries.
    assert [s.message.text[:28] for s in provider.sent] == [
        "VRM Alert Relay: 8 alerts he",
        "Freezer warming",
        "Freezer warming",
    ]


def test_memory_keeps_only_the_newest_finished_records(tmp_path: Path) -> None:
    provider = FakeProvider()
    limits = DeliveryLimits(max_queue=2, max_records=2)
    engine = make_engine(StateStore(tmp_path), voipms=provider, limits=limits)
    for n in range(4):
        now = BASE + timedelta(minutes=n)
        engine.accept_cycle(rule_states={}, notifications=[rule_note(n)], now=now)
        engine.run_due(now)
    assert engine.record(event_id(0), "owner_sms") is None
    assert engine.record(event_id(1), "owner_sms") is None
    assert engine.record(event_id(3), "owner_sms") is not None


def test_rule_states_are_validated_and_bounded(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(engine_module, "MAX_RULE_STATES", 2)
    engine = make_engine(StateStore(tmp_path))
    fresh = RuleState()
    bad: dict[str, Any] = {"bad id": fresh, "freezer": "not a state"}
    with caplog.at_level(logging.ERROR, logger="vrm_alert_relay.delivery"):
        engine.accept_cycle(rule_states=bad, notifications=[], now=BASE)
        engine.accept_cycle(
            rule_states={"a": fresh, "b": fresh, "c": fresh, "a2": fresh},
            notifications=[],
            now=BASE,
        )
        engine.accept_cycle(rule_states={"a": fresh}, notifications=[], now=BASE)
    assert events_logged(caplog).count("delivery.rule_state_invalid") == 2
    assert events_logged(caplog).count("delivery.rule_state_limit") == 2
    assert engine.rule_state("c") == fresh
    reopened = make_engine(StateStore(tmp_path))
    assert reopened.rule_state("a") == fresh
    assert reopened.rule_state("b") == fresh


# Sending outcomes --------------------------------------------------------------


@pytest.mark.parametrize(
    "result",
    [
        SendResult(SendStatus.FAILED, retryable=False),
        SendResult(SendStatus.FAILED, retryable=1),  # type: ignore[arg-type]
    ],
)
def test_definitive_failure_is_not_retried(tmp_path: Path, result: SendResult) -> None:
    provider = FakeProvider(default=result)
    engine = make_engine(StateStore(tmp_path), voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    assert engine.run_due(BASE).failed == 1
    engine.run_due(BASE + timedelta(hours=2))
    assert len(provider.sent) == 1


@pytest.mark.parametrize(
    "outcome",
    [RuntimeError("connection reset"), "delivered", SendResult("delivered")],  # type: ignore[arg-type]
)
def test_provider_errors_and_invalid_results_are_ambiguous(
    tmp_path: Path, outcome: Any, caplog: pytest.LogCaptureFixture
) -> None:
    provider = FakeProvider()
    provider.script(outcome)
    engine = make_engine(StateStore(tmp_path), voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    with caplog.at_level(logging.WARNING, logger="vrm_alert_relay.delivery"):
        assert engine.run_due(BASE).ambiguous == 1
    assert {"delivery.provider_error", "delivery.provider_invalid_result"} & set(
        events_logged(caplog)
    )
    engine.run_due(BASE + timedelta(minutes=5))
    assert len(provider.sent) == 2


def test_ambiguous_after_the_last_attempt_gives_up_with_unknown_outcome(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    provider = FakeProvider(default=SendResult(SendStatus.AMBIGUOUS))
    engine = make_engine(StateStore(tmp_path), config=make_config(retries=0), voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    engine.run_due(BASE)
    with caplog.at_level(logging.ERROR, logger="vrm_alert_relay.delivery"):
        assert engine.run_due(BASE + timedelta(minutes=5)).failed == 1
    exhausted = [
        r for r in caplog.records if r.__dict__.get("event") == "delivery.attempts_exhausted"
    ]
    assert exhausted[0].__dict__["outcome_unknown"] is True
    assert len(provider.sent) == 1


def test_reconcile_still_runs_after_the_last_attempt(tmp_path: Path) -> None:
    provider = FakeReconcilingProvider(default=SendResult(SendStatus.AMBIGUOUS))
    provider.lookups.append(ReconcileStatus.DELIVERED)
    engine = make_engine(StateStore(tmp_path), config=make_config(retries=0), voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    engine.run_due(BASE)
    assert engine.run_due(BASE + timedelta(minutes=5)).reconciled == 1
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.DELIVERED


def test_provider_message_id_is_kept_when_a_retry_reports_none(tmp_path: Path) -> None:
    provider = FakeReconcilingProvider()
    provider.script(
        SendResult(SendStatus.AMBIGUOUS, "provider-id-1"), SendResult(SendStatus.AMBIGUOUS)
    )
    provider.lookups.extend([ReconcileStatus.NOT_DELIVERED, ReconcileStatus.NOT_DELIVERED])
    engine = make_engine(StateStore(tmp_path), voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    engine.run_due(BASE)
    engine.run_due(BASE + timedelta(minutes=5))
    engine.run_due(BASE + timedelta(minutes=10))
    assert [q.provider_message_id for q in provider.queries] == ["provider-id-1"] * 2
    assert [q.attempted_at for q in provider.queries] == [BASE, BASE + timedelta(minutes=5)]


def test_reconcile_falls_back_to_creation_time_without_an_attempt_time(tmp_path: Path) -> None:
    seed_store(tmp_path, pending(1, status=DeliveryStatus.AMBIGUOUS, attempts=1))
    provider = FakeReconcilingProvider()
    provider.lookups.append(ReconcileStatus.DELIVERED)
    engine = make_engine(StateStore(tmp_path), voipms=provider)
    engine.run_due(BASE)
    assert provider.queries[0].attempted_at == BASE


def test_delivery_to_a_recipient_removed_from_config_is_dropped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    seed_store(tmp_path, pending(1, recipient="retired_pager"))
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), voipms=provider)
    with caplog.at_level(logging.ERROR, logger="vrm_alert_relay.delivery"):
        assert engine.run_due(BASE).failed == 1
    assert "delivery.recipient_removed" in events_logged(caplog)
    assert provider.sent == []


def test_records_that_are_not_due_wait(tmp_path: Path) -> None:
    seed_store(tmp_path, pending(1, next_attempt_at=BASE + timedelta(minutes=10)))
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), voipms=provider)
    assert engine.run_due(BASE).sent == 0
    assert engine.run_due(BASE + timedelta(minutes=10)).sent == 1


# Summaries ------------------------------------------------------------------------


def test_summary_waits_for_capacity_for_each_recipient(tmp_path: Path) -> None:
    provider = FakeProvider()
    engine = make_engine(
        StateStore(tmp_path), config=make_config(per_hour=1, per_day=10), voipms=provider
    )
    notes = [
        direct_note(1, "owner_sms"),
        direct_note(2, "owner_sms"),
        direct_note(3, "partner_sms"),
        direct_note(4, "partner_sms"),
    ]
    engine.accept_cycle(rule_states={}, notifications=notes, now=BASE)
    engine.run_due(BASE)
    assert len(provider.sent) == 1
    now = BASE + timedelta(hours=1, seconds=1)
    engine.run_due(now)
    # Held back while the partner summary still waits: no second summary yet.
    engine.accept_cycle(rule_states={}, notifications=[direct_note(5, "owner_sms")], now=now)
    engine.run_due(now)
    for _ in range(2):
        now += timedelta(hours=1, seconds=1)
        engine.run_due(now)
    summaries = [s for s in provider.sent if s.message.text.startswith("VRM Alert Relay:")]
    owner, partner = make_config().recipients["owner_sms"], make_config().recipients["partner_sms"]
    assert [(s.recipient, s.message.text.split(" held")[0]) for s in summaries] == [
        (owner, "VRM Alert Relay: 1 alert"),
        (partner, "VRM Alert Relay: 2 alerts"),
        (owner, "VRM Alert Relay: 1 alert"),
    ]
    assert summaries[0].message.delivery_id != summaries[1].message.delivery_id


def test_summary_skips_recipients_no_longer_configured(tmp_path: Path) -> None:
    suppression = Suppression(
        counts=MappingProxyType({"retired_pager": 4, "owner_sms": 2}), since=BASE
    )
    seed_store(tmp_path, suppression=suppression)
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), voipms=provider)
    engine.run_due(BASE)
    assert [s.message.text for s in provider.sent] == [
        "VRM Alert Relay: 2 alerts held back by the global rate limit since 2035-01-01 00:00 UTC."
    ]


def test_summary_is_not_blocked_by_a_clock_that_went_backwards(tmp_path: Path) -> None:
    suppression = Suppression(
        counts=MappingProxyType({"owner_sms": 1}),
        since=None,
        last_summary_at=BASE + timedelta(hours=5),
    )
    seed_store(tmp_path, suppression=suppression)
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), voipms=provider)
    engine.run_due(BASE)
    assert len(provider.sent) == 1
    assert "since 2035-01-01 00:00 UTC" in provider.sent[0].message.text


def test_summary_is_not_opened_without_capacity(tmp_path: Path) -> None:
    provider = FakeProvider()
    engine = make_engine(
        StateStore(tmp_path), config=make_config(per_hour=1, per_day=1), voipms=provider
    )
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1), rule_note(2)], now=BASE)
    engine.run_due(BASE)
    engine.run_due(BASE + timedelta(hours=2))
    assert len(provider.sent) == 1
    assert engine.health(BASE + timedelta(hours=2)).suppressed_pending == 1
    engine.run_due(BASE + timedelta(days=1, seconds=1))
    assert len(provider.sent) == 2


# Persistence ------------------------------------------------------------------------


def test_recovered_in_flight_record_survives_a_failing_store(tmp_path: Path) -> None:
    seed_store(
        tmp_path, pending(1, status=DeliveryStatus.IN_FLIGHT, attempts=1, last_attempt_at=BASE)
    )
    switch = FailSwitch(only="INSERT")
    switch.on = True
    provider = FakeReconcilingProvider()
    provider.lookups.append(ReconcileStatus.DELIVERED)
    engine = make_engine(flaky_store(tmp_path, switch), voipms=provider)
    assert engine.health(BASE).persistence_healthy is False
    assert engine.run_due(BASE).reconciled == 1
    switch.on = False
    assert engine.flush(BASE)
    reopened = make_engine(StateStore(tmp_path))
    record = reopened.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.DELIVERED


def test_direct_notification_to_a_dry_run_recipient(tmp_path: Path) -> None:
    dry = FakeProvider()
    engine = make_engine(StateStore(tmp_path), dry_run=dry)
    engine.accept_cycle(rule_states={}, notifications=[direct_note(1, "audit")], now=BASE)
    engine.run_due(BASE)
    assert [s.recipient.provider for s in dry.sent] == ["log"]

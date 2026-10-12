"""Edge cases of the delivery engine. Every value here is fictitious."""

from __future__ import annotations

import logging
import sqlite3
from contextlib import closing
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest
from delivery_fakes import (
    BASE,
    FailSwitch,
    FakeClock,
    FakeProvider,
    FakeReconcilingProvider,
    direct_note,
    event_id,
    flaky_store,
    make_config,
    make_engine,
    rule_note,
    summaries,
)

from vrm_alert_relay.delivery import (
    DeliveryEngine,
    DeliveryLimits,
    Notification,
    RateLimiter,
    ReconcileStatus,
    RuleTarget,
    SendResult,
    SendStatus,
    SystemTarget,
)
from vrm_alert_relay.delivery import engine as engine_module
from vrm_alert_relay.engine import RuleState
from vrm_alert_relay.state import (
    DB_FILENAME,
    AttemptMark,
    Changes,
    DeliveryKind,
    DeliveryRecord,
    DeliveryStatus,
    StateStore,
    SuppressionState,
)

if TYPE_CHECKING:
    from pathlib import Path


def logged(caplog: pytest.LogCaptureFixture) -> list[Any]:
    return [record.__dict__.get("event") for record in caplog.records]


def seed(path: Path, changes: Changes, at: Any = BASE) -> None:
    store = StateStore(path)
    store.load(at)
    assert store.flush(changes, at)
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
    [{"max_queue": 0}, {"max_queue": 10, "max_records": 5}, {"summary_interval": timedelta(0)}],
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
            clock=FakeClock(),
        )


def test_requires_a_provider_for_every_live_recipient(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="voipms"):
        DeliveryEngine.from_config(
            make_config(),
            providers={},
            dry_run=FakeProvider(),
            store=StateStore(tmp_path),
            clock=FakeClock(),
        )


def test_default_rng_jitters_within_the_backoff(tmp_path: Path) -> None:
    provider = FakeProvider(default=SendResult(SendStatus.FAILED, retryable=True))
    engine = DeliveryEngine.from_config(
        make_config(sending=False),
        providers={},
        dry_run=provider,
        store=StateStore(tmp_path),
        clock=FakeClock(),
    )
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    engine.run_due()
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.next_attempt_at is not None
    assert BASE + timedelta(seconds=15) <= record.next_attempt_at <= BASE + timedelta(seconds=30)


def test_restored_retry_times_within_the_backoff_are_kept(tmp_path: Path) -> None:
    seed(
        tmp_path,
        Changes(
            deliveries=(
                pending(1, next_attempt_at=BASE + timedelta(minutes=2)),
                pending(2, next_attempt_at=None),
            )
        ),
    )
    provider = FakeProvider()
    clock = FakeClock()
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=provider)
    assert engine.run_due().sent == 1
    clock.advance(timedelta(minutes=2))
    assert engine.run_due().sent == 1


def test_old_attempts_kept_after_the_clock_moved_back_do_not_occupy_slots(
    tmp_path: Path,
) -> None:
    clock = FakeClock(now=BASE + timedelta(days=3))
    seed(
        tmp_path,
        Changes(attempts=(AttemptMark("evt_old", "owner_sms", 1, BASE),)),
        at=clock.now,
    )
    clock.jump_wall(timedelta(days=-1))
    engine = make_engine(StateStore(tmp_path), clock=clock, config=make_config(per_hour=1))
    assert engine.health().sent_last_day == 0
    with closing(sqlite3.connect(tmp_path / DB_FILENAME)) as connection:
        assert connection.execute("SELECT count(*) FROM send_attempt").fetchone() == (1,)


# Intake -------------------------------------------------------------------------


def test_malformed_notifications_are_dropped_and_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), clock=FakeClock(), voipms=provider)
    notes: list[Any] = [
        "not a notification",
        Notification(event_id="evt with spaces", text="x", target=RuleTarget("freezer")),
        Notification(event_id="e" * 129, text="x", target=RuleTarget("freezer")),
        Notification(event_id=event_id(1), text=None, target=RuleTarget("freezer")),  # type: ignore[arg-type]
        Notification(event_id=event_id(2), text="x", target="freezer"),  # type: ignore[arg-type]
    ]
    with caplog.at_level(logging.ERROR, logger="vrm_alert_relay.delivery"):
        assert engine.accept_cycle(rule_states={}, notifications=notes) == 0
    assert logged(caplog).count("delivery.notification_invalid") == 4
    assert logged(caplog).count("delivery.unknown_target") == 1
    engine.run_due()
    assert provider.sent == []


def test_system_target_goes_to_system_recipients(tmp_path: Path) -> None:
    provider = FakeProvider()
    engine = make_engine(
        StateStore(tmp_path),
        clock=FakeClock(),
        config=make_config(system=("partner_sms", "owner_sms")),
        voipms=provider,
    )
    note = Notification(event_id=event_id(1), text="Monitoring degraded", target=SystemTarget())
    assert engine.accept_cycle(rule_states={}, notifications=[note]) == 2
    engine.run_due()
    record = engine.record(event_id(1), "partner_sms")
    assert record is not None
    assert record.rule_id is None


def test_message_text_is_sanitized_and_bounded(tmp_path: Path) -> None:
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), clock=FakeClock(), voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1, text="a\tb\r\nc" + "z" * 5000)])
    engine.run_due()
    text = provider.sent[0].message.text
    assert text.startswith("a b \nc")
    assert len(text) == 1000
    assert text.endswith("…")


def test_queue_bound_holds_back_and_counts_overflow(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    provider = FakeProvider()
    limits = DeliveryLimits(max_queue=2, max_records=3)
    engine = make_engine(StateStore(tmp_path), clock=FakeClock(), voipms=provider, limits=limits)
    with caplog.at_level(logging.WARNING, logger="vrm_alert_relay.delivery"):
        queued = engine.accept_cycle(
            rule_states={}, notifications=[rule_note(n) for n in range(10)]
        )
    assert queued == 2
    assert "delivery.queue_full" in logged(caplog)
    assert (engine.health().queued, engine.health().suppressed_pending) == (2, 8)
    engine.run_due()
    # The real alerts first, then the summary of what was held back.
    assert provider.texts()[:2] == ["Freezer warming", "Freezer warming"]
    assert summaries(provider) == [
        "VRM Alert Relay: 8 alerts held back by the global rate limit since 2035-01-01 00:00 UTC."
    ]


def test_memory_keeps_only_the_newest_finished_records(tmp_path: Path) -> None:
    clock = FakeClock()
    limits = DeliveryLimits(max_queue=2, max_records=2)
    engine = make_engine(StateStore(tmp_path), clock=clock, limits=limits)
    for n in range(4):
        engine.accept_cycle(rule_states={}, notifications=[rule_note(n)])
        engine.run_due()
        clock.advance(timedelta(minutes=1))
    assert engine.record(event_id(0), "owner_sms") is None
    assert engine.record(event_id(1), "owner_sms") is None
    assert engine.record(event_id(3), "owner_sms") is not None


def test_rule_states_are_validated_and_bounded(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(engine_module, "MAX_RULE_STATES", 2)
    engine = make_engine(StateStore(tmp_path), clock=FakeClock())
    fresh = RuleState()
    bad: dict[str, Any] = {"bad id": fresh, "freezer": "not a state"}
    with caplog.at_level(logging.ERROR, logger="vrm_alert_relay.delivery"):
        engine.accept_cycle(rule_states=bad, notifications=[])
        engine.accept_cycle(
            rule_states={"a": fresh, "b": fresh, "c": fresh, "d": fresh}, notifications=[]
        )
        engine.accept_cycle(rule_states={"a": fresh}, notifications=[])
    assert logged(caplog).count("delivery.rule_state_invalid") == 2
    assert logged(caplog).count("delivery.rule_state_limit") == 2


# Sending outcomes --------------------------------------------------------------


@pytest.mark.parametrize(
    "result",
    [
        SendResult(SendStatus.FAILED, retryable=False),
        SendResult(SendStatus.FAILED, retryable=1),  # type: ignore[arg-type]
    ],
)
def test_definitive_failure_is_not_retried(tmp_path: Path, result: SendResult) -> None:
    clock = FakeClock()
    provider = FakeProvider(default=result)
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    assert engine.run_due().failed == 1
    clock.advance(timedelta(hours=2))
    engine.run_due()
    assert len(provider.sent) == 1


@pytest.mark.parametrize(
    "outcome",
    [RuntimeError("connection reset"), "delivered", SendResult("delivered")],  # type: ignore[arg-type]
)
def test_provider_errors_and_invalid_results_are_ambiguous(
    tmp_path: Path, outcome: Any, caplog: pytest.LogCaptureFixture
) -> None:
    clock = FakeClock()
    provider = FakeProvider()
    provider.script(outcome)
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    with caplog.at_level(logging.WARNING, logger="vrm_alert_relay.delivery"):
        assert engine.run_due().ambiguous == 1
    assert {"delivery.provider_error", "delivery.provider_invalid_result"} & set(logged(caplog))
    clock.advance(timedelta(minutes=5))
    engine.run_due()
    assert len(provider.sent) == 2


def test_ambiguous_after_the_last_attempt_gives_up_with_unknown_outcome(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    clock = FakeClock()
    provider = FakeProvider(default=SendResult(SendStatus.AMBIGUOUS))
    engine = make_engine(
        StateStore(tmp_path), clock=clock, config=make_config(retries=0), voipms=provider
    )
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    engine.run_due()
    clock.advance(timedelta(minutes=5))
    with caplog.at_level(logging.ERROR, logger="vrm_alert_relay.delivery"):
        assert engine.run_due().failed == 1
    exhausted = [
        r for r in caplog.records if r.__dict__.get("event") == "delivery.attempts_exhausted"
    ]
    assert exhausted[0].__dict__["outcome_unknown"] is True
    assert len(provider.sent) == 1


def test_reconcile_still_runs_after_the_last_attempt(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeReconcilingProvider(default=SendResult(SendStatus.AMBIGUOUS))
    provider.lookups.append(ReconcileStatus.DELIVERED)
    engine = make_engine(
        StateStore(tmp_path), clock=clock, config=make_config(retries=0), voipms=provider
    )
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    engine.run_due()
    clock.advance(timedelta(minutes=5))
    assert engine.run_due().reconciled == 1


def test_provider_message_id_is_kept_when_a_retry_reports_none(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeReconcilingProvider()
    provider.script(
        SendResult(SendStatus.AMBIGUOUS, "provider-id-1"), SendResult(SendStatus.AMBIGUOUS)
    )
    provider.lookups.extend([ReconcileStatus.NOT_DELIVERED, ReconcileStatus.NOT_DELIVERED])
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    for _ in range(3):
        engine.run_due()
        clock.advance(timedelta(minutes=5))
    assert [q.provider_message_id for q in provider.queries] == ["provider-id-1"] * 2
    assert [q.attempted_at for q in provider.queries] == [BASE, BASE + timedelta(minutes=5)]


def test_reconcile_falls_back_to_creation_time_without_an_attempt_time(tmp_path: Path) -> None:
    seed(tmp_path, Changes(deliveries=(pending(1, status=DeliveryStatus.AMBIGUOUS, attempts=1),)))
    provider = FakeReconcilingProvider()
    provider.lookups.append(ReconcileStatus.DELIVERED)
    engine = make_engine(StateStore(tmp_path), clock=FakeClock(), voipms=provider)
    engine.run_due()
    assert provider.queries[0].attempted_at == BASE


def test_delivery_to_a_recipient_removed_from_config_is_dropped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    seed(tmp_path, Changes(deliveries=(pending(1, recipient="r2025550999"),)))
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), clock=FakeClock(), voipms=provider)
    with caplog.at_level(logging.ERROR, logger="vrm_alert_relay.delivery"):
        assert engine.run_due().failed == 1
    removed = [r for r in caplog.records if r.__dict__.get("event") == "delivery.recipient_removed"]
    assert removed[0].__dict__["recipient"] == "[#?]"
    assert provider.sent == []


# Summaries ------------------------------------------------------------------------


def test_summary_deliveries_beyond_the_cap_are_suppressed_not_counted(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeProvider()
    engine = make_engine(
        StateStore(tmp_path),
        clock=clock,
        config=make_config(per_hour=1, system=("owner_sms", "partner_sms")),
        voipms=provider,
    )
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1), rule_note(2)])
    engine.run_due()
    clock.advance(timedelta(hours=1, seconds=1))
    report = engine.run_due()
    assert (report.sent, report.suppressed) == (1, 1)
    assert engine.health().suppressed_pending == 0  # one summary was delivered


def test_summary_waits_without_system_recipients(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeProvider()
    config = make_config(per_hour=1, system=None)
    config = config.model_copy(update={"rules": ()})
    seed(tmp_path, Changes(suppression=SuppressionState(count=3, since=BASE)))
    engine = make_engine(StateStore(tmp_path), clock=clock, config=config, voipms=provider)
    engine.run_due()
    assert provider.sent == []
    assert engine.health().suppressed_pending == 3


def test_a_stale_summary_record_does_not_settle_the_current_count(tmp_path: Path) -> None:
    stale = pending(1, kind=DeliveryKind.SUMMARY, text="VRM Alert Relay: 9 alerts held back")
    seed(
        tmp_path,
        Changes(deliveries=(stale,), suppression=SuppressionState(count=2, since=BASE)),
    )
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), clock=FakeClock(), voipms=provider)
    engine.run_due()
    assert summaries(provider)[0] == "VRM Alert Relay: 9 alerts held back"
    assert engine.health().suppressed_pending == 0  # settled by the new summary


# Storage --------------------------------------------------------------------------


def test_durable_accounting_recovers_at_the_next_run(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    clock = FakeClock()
    switch = FailSwitch()
    provider = FakeProvider()
    engine = make_engine(flaky_store(tmp_path, switch), clock=clock, voipms=provider)
    switch.on = True
    (tmp_path / "relay-state.journal").mkdir()  # the journal is unusable too
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    report = engine.run_due()
    assert (report.sent, report.sent_unrecorded) == (2, 2)  # alert and notice, sent anyway (R1)
    assert engine.health().durable_accounting is False
    (tmp_path / "relay-state.journal").rmdir()
    switch.on = False
    with caplog.at_level(logging.WARNING, logger="vrm_alert_relay.delivery"):
        engine.run_due()
    assert "delivery.durable_accounting_restored" in logged(caplog)
    assert engine.health().durable_accounting is True
    assert provider.texts() == ["Freezer warming", engine_module.STORAGE_NOTICE_TEXT]


def test_journal_recovers_durability_after_a_failure(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    clock = FakeClock()
    switch = FailSwitch()
    provider = FakeProvider()
    engine = make_engine(flaky_store(tmp_path, switch), clock=clock, voipms=provider)
    switch.on = True
    (tmp_path / "relay-state.journal").mkdir()
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    engine.run_due()
    (tmp_path / "relay-state.journal").rmdir()
    engine.accept_cycle(rule_states={}, notifications=[rule_note(2)])
    with caplog.at_level(logging.WARNING, logger="vrm_alert_relay.delivery"):
        report = engine.run_due()
    assert (report.sent, report.sent_unrecorded) == (1, 0)
    assert "delivery.durable_accounting_restored" in logged(caplog)
    assert provider.texts()[-1] == "Freezer warming"


def test_storage_notice_needs_a_system_recipient(tmp_path: Path) -> None:
    clock = FakeClock()
    switch = FailSwitch()
    provider = FakeProvider()
    config = make_config(system=None).model_copy(update={"rules": ()})
    engine = make_engine(flaky_store(tmp_path, switch), clock=clock, config=config, voipms=provider)
    switch.on = True
    (tmp_path / "relay-state.journal").mkdir()
    engine.accept_cycle(rule_states={}, notifications=[direct_note(1, "owner_sms")])
    assert engine.run_due().storage_notice is None
    assert provider.texts() == ["Test notification"]  # the alert itself still goes out


def test_storage_notice_waits_for_capacity(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeProvider()
    engine = make_engine(
        StateStore(tmp_path), clock=clock, config=make_config(per_hour=1), voipms=provider
    )
    # White box: durability was lost while every slot of the cap is taken.
    engine._durable = False
    engine._live = RateLimiter(1, 10, [(clock.mono, ("evt_x", "owner_sms", 1))])
    engine._store.flush = lambda changes, now: False  # type: ignore[method-assign]
    assert engine.run_due().storage_notice is None
    clock.advance(timedelta(hours=1, seconds=1))
    assert engine.run_due().storage_notice is SendStatus.DELIVERED
    assert provider.texts() == [engine_module.STORAGE_NOTICE_TEXT]


def test_storage_notice_to_a_dry_run_system_recipient(tmp_path: Path) -> None:
    clock = FakeClock()
    switch = FailSwitch()
    dry = FakeProvider()
    engine = make_engine(
        flaky_store(tmp_path, switch),
        clock=clock,
        config=make_config(system=("audit",)),
        dry_run=dry,
    )
    switch.on = True
    (tmp_path / "relay-state.journal").mkdir()
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    assert engine.run_due().storage_notice is SendStatus.DELIVERED
    assert dry.texts() == [engine_module.STORAGE_NOTICE_TEXT]
    assert engine.health().dry_run_sent_last_hour == 1


def test_reconciled_outcome_goes_to_the_journal_when_sqlite_fails(tmp_path: Path) -> None:
    seed(tmp_path, Changes(deliveries=(pending(1, status=DeliveryStatus.AMBIGUOUS, attempts=1),)))
    switch = FailSwitch(only="INSERT")
    switch.on = True
    provider = FakeReconcilingProvider()
    provider.lookups.append(ReconcileStatus.DELIVERED)
    store = flaky_store(tmp_path, switch)
    engine = make_engine(store, clock=FakeClock(), voipms=provider)
    engine.run_due()
    store.close()
    reopened = make_engine(StateStore(tmp_path), clock=FakeClock())
    record = reopened.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.DELIVERED


def test_health_reports_suppression_and_dry_run_counters(tmp_path: Path) -> None:
    seed(
        tmp_path,
        Changes(suppression=SuppressionState(count=4, since=BASE)),
    )
    engine = make_engine(StateStore(tmp_path), clock=FakeClock(), config=make_config(sending=False))
    health = engine.health()
    assert health.suppressed_pending == 4
    assert health.suppressed_total == 0
    assert health.dry_run_over_cap_total == 0

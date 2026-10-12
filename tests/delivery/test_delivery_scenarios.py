"""Named failure scenarios for the delivery engine (R13-R18, R22, R24, R32, ADR 0002).

Every identifier, number, and message here is fictitious.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import closing
from datetime import timedelta
from typing import TYPE_CHECKING

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
    STORAGE_NOTICE_TEXT,
    DeliveryLimits,
    Notification,
    RecipientTarget,
    ReconcileStatus,
    Routing,
    RuleTarget,
    SendResult,
    SendStatus,
)
from vrm_alert_relay.engine import Direction, LevelSpec, RuleSpec, RuleState, Sample, evaluate
from vrm_alert_relay.state import (
    DB_FILENAME,
    JOURNAL_FILENAME,
    DeliveryStatus,
    StateLockedError,
    StateStore,
)

if TYPE_CHECKING:
    from pathlib import Path

FREEZER = RuleSpec(
    "freezer",
    Direction.RISING,
    (LevelSpec("warning", -12.0), LevelSpec("critical", -4.5)),
)


class Crash(BaseException):
    """Stands in for the process dying in the middle of a provider call."""


# Restart ------------------------------------------------------------------


def test_restart_sends_no_duplicates(tmp_path: Path) -> None:
    clock = FakeClock()
    voipms = FakeProvider()
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, voipms=voipms)
    state, events = evaluate(FREEZER, engine.rule_state("freezer"), Sample(-3.0, BASE), BASE)
    assert len(events) == 1
    notes = [Notification.for_event(event, "Freezer is critical") for event in events]
    engine.accept_cycle(rule_states={"freezer": state}, notifications=notes)
    engine.run_due()
    assert len(voipms.sent) == 1
    store.close()

    clock.advance(timedelta(minutes=2))
    restarted = FakeProvider()
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=restarted)
    assert engine.rule_state("freezer") == state
    state, events = evaluate(FREEZER, state, Sample(-3.0, clock.now), clock.now)
    assert events == []
    engine.accept_cycle(rule_states={"freezer": state}, notifications=notes)
    assert engine.run_due().sent == 0
    assert restarted.sent == []
    assert engine.health().sent_last_hour == 1


def test_second_instance_on_the_same_state_directory_fails_loudly(tmp_path: Path) -> None:
    clock = FakeClock()
    first = make_engine(StateStore(tmp_path), clock=clock)
    with pytest.raises(StateLockedError):
        make_engine(StateStore(tmp_path), clock=clock)
    first.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    assert first.run_due().sent == 1


# Ambiguous sends ------------------------------------------------------------


def _ambiguous_first(provider: FakeProvider, store: StateStore, clock: FakeClock) -> None:
    provider.script(SendResult(SendStatus.AMBIGUOUS, "provider-id-17"))
    engine = make_engine(store, clock=clock, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    assert engine.run_due().ambiguous == 1
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.AMBIGUOUS
    clock.advance(timedelta(seconds=1))
    assert engine.run_due().sent == 0  # not due before the backoff
    clock.advance(timedelta(minutes=5))
    engine.run_due()


def test_ambiguous_send_reconciled_as_delivered_is_not_retried(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeReconcilingProvider()
    provider.lookups.append(ReconcileStatus.DELIVERED)
    _ambiguous_first(provider, StateStore(tmp_path), clock)
    assert len(provider.sent) == 1
    query = provider.queries[0]
    assert query.provider_message_id == "provider-id-17"
    assert query.attempted_at == BASE
    assert query.message == provider.sent[0].message
    assert query.recipient is provider.sent[0].recipient


@pytest.mark.parametrize(
    "lookup",
    [ReconcileStatus.NOT_DELIVERED, ReconcileStatus.UNKNOWN, RuntimeError("lookup failed"), "?"],
)
def test_ambiguous_send_not_confirmed_is_retried_after_reconcile(
    tmp_path: Path, lookup: object
) -> None:
    provider = FakeReconcilingProvider()
    provider.lookups.append(lookup)
    _ambiguous_first(provider, StateStore(tmp_path), FakeClock())
    assert len(provider.queries) == 1
    assert len(provider.sent) == 2


def test_ambiguous_send_without_lookup_support_is_retried(tmp_path: Path) -> None:
    provider = FakeProvider()
    _ambiguous_first(provider, StateStore(tmp_path), FakeClock())
    assert len(provider.sent) == 2


def test_crash_between_in_flight_and_outcome_is_reconciled_on_startup(tmp_path: Path) -> None:
    clock = FakeClock()
    crashing = FakeProvider()
    crashing.script(Crash())
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, voipms=crashing)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    with pytest.raises(Crash):
        engine.run_due()
    store.close()

    clock.advance(timedelta(minutes=1))
    provider = FakeReconcilingProvider()
    provider.lookups.append(ReconcileStatus.DELIVERED)
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=provider)
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.AMBIGUOUS
    assert engine.run_due().reconciled == 1
    assert provider.sent == []
    assert provider.queries[0].attempted_at == BASE
    assert engine.health().sent_last_hour == 1


def test_crash_between_in_flight_and_outcome_without_lookup_resends_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    clock = FakeClock()
    crashing = FakeProvider()
    crashing.script(Crash())
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, voipms=crashing)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    with pytest.raises(Crash):
        engine.run_due()
    store.close()

    clock.advance(timedelta(minutes=1))
    provider = FakeProvider()
    with caplog.at_level(logging.WARNING, logger="vrm_alert_relay.delivery"):
        engine = make_engine(StateStore(tmp_path), clock=clock, voipms=provider)
    assert any(r.__dict__.get("event") == "delivery.recovered_in_flight" for r in caplog.records)
    engine.run_due()
    assert len(provider.sent) == 1  # one accepted duplicate, counted against the cap
    assert engine.health().sent_last_hour == 2
    clock.advance(timedelta(hours=1))
    engine.run_due()
    assert len(provider.sent) == 1


# Global cap and summaries -------------------------------------------------------


def test_global_cap_holds_under_a_flood_of_1000_events(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeProvider()
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, voipms=provider)
    notes = [rule_note(n) for n in range(1000)]
    assert engine.accept_cycle(rule_states={}, notifications=notes) == 1000
    report = engine.run_due()
    assert (report.sent, report.suppressed) == (20, 980)
    assert engine.health().suppressed_pending == 980

    for minutes in (1, 30, 59):
        clock.set(BASE + timedelta(minutes=minutes))
        assert engine.run_due().sent == 0
    assert len(provider.sent) == 20

    clock.set(BASE + timedelta(hours=1, seconds=1))
    assert engine.run_due().sent == 1
    assert summaries(provider) == [
        "VRM Alert Relay: 980 alerts held back by the global rate limit since 2035-01-01 00:00 UTC."
    ]
    assert engine.health().suppressed_pending == 0
    for minutes in (2, 30, 120):
        clock.advance(timedelta(minutes=minutes))
        assert engine.run_due().sent == 0
    assert len(provider.sent) == 21

    store.close()
    restarted = FakeProvider()
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=restarted)
    engine.accept_cycle(rule_states={}, notifications=notes)
    clock.advance(timedelta(days=2))
    engine.run_due()
    assert restarted.sent == []


def test_real_alerts_get_capacity_before_the_summary(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeProvider()
    engine = make_engine(
        StateStore(tmp_path),
        clock=clock,
        config=make_config(per_hour=2),
        voipms=provider,
        limits=DeliveryLimits(summary_max_wait=timedelta(hours=3)),
    )
    engine.accept_cycle(rule_states={}, notifications=[rule_note(n) for n in range(5)])
    engine.run_due()
    clock.advance(timedelta(hours=1, seconds=1))
    engine.accept_cycle(rule_states={}, notifications=[rule_note(10), rule_note(11)])
    engine.run_due()
    # Both slots went to the real alerts; the summary waits.
    assert provider.texts()[-2:] == ["Freezer warming", "Freezer warming"]
    assert summaries(provider) == []
    clock.advance(timedelta(hours=1, seconds=1))
    engine.run_due()
    assert summaries(provider) == [
        "VRM Alert Relay: 3 alerts held back by the global rate limit since 2035-01-01 00:00 UTC."
    ]


def test_a_summary_waits_at_most_an_hour_for_real_alerts(tmp_path: Path) -> None:
    """M7: under a steady stream of real alerts, the summary still goes out within an hour."""
    clock = FakeClock()
    provider = FakeProvider()
    engine = make_engine(
        StateStore(tmp_path), clock=clock, config=make_config(per_hour=2), voipms=provider
    )
    n = 0
    for _ in range(13):  # two new alerts every 10 minutes for two hours
        engine.accept_cycle(rule_states={}, notifications=[rule_note(n), rule_note(n + 1)])
        n += 2
        engine.run_due()
        clock.advance(timedelta(minutes=10))
    # Slots free up at 0:00, 1:00 and 2:00. At 1:00 the first held alert has
    # waited only 50 minutes, so real alerts take both slots; at 2:00 the
    # summary has waited over an hour and takes the first free slot.
    texts = provider.texts()
    assert len(summaries(provider)) == 1
    assert texts.index(summaries(provider)[0]) == 4
    assert summaries(provider)[0].startswith("VRM Alert Relay: 20 alerts held back")


def test_at_most_one_summary_per_hour_while_a_flood_continues(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(n) for n in range(30)])
    engine.run_due()
    clock.advance(timedelta(hours=1, seconds=1))
    engine.run_due()  # summary 1
    clock.advance(timedelta(minutes=10))
    engine.accept_cycle(rule_states={}, notifications=[rule_note(n) for n in range(100, 200)])
    assert engine.run_due().sent == 19
    for minutes in (20, 40, 59):
        clock.set(BASE + timedelta(hours=1, minutes=minutes))
        engine.run_due()
    assert len(summaries(provider)) == 1
    clock.set(BASE + timedelta(hours=2, seconds=2))
    engine.run_due()
    assert summaries(provider)[-1].startswith("VRM Alert Relay: 81 alerts")
    assert len(summaries(provider)) == 2


def test_summary_count_is_kept_until_a_summary_is_delivered(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeProvider()
    engine = make_engine(
        StateStore(tmp_path), clock=clock, config=make_config(per_hour=1), voipms=provider
    )
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1), rule_note(2)])
    engine.run_due()
    provider.script(SendResult(SendStatus.FAILED, retryable=False))
    clock.advance(timedelta(hours=1, seconds=1))
    engine.run_due()  # the summary fails definitively
    assert engine.health().suppressed_pending == 1
    engine.accept_cycle(rule_states={}, notifications=[rule_note(3)])
    clock.advance(timedelta(minutes=1))
    engine.run_due()  # held back: the count keeps growing
    assert engine.health().suppressed_pending == 2
    clock.advance(timedelta(hours=1, seconds=1))
    engine.run_due()
    assert summaries(provider)[-1].startswith("VRM Alert Relay: 2 alerts")
    assert engine.health().suppressed_pending == 0


def test_retries_consume_the_global_cap(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeProvider()
    retryable = SendResult(SendStatus.FAILED, retryable=True)
    provider.script(retryable, retryable)
    engine = make_engine(
        StateStore(tmp_path),
        clock=clock,
        config=make_config(per_hour=3, per_day=10),
        voipms=provider,
    )
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    for _ in range(3):
        engine.run_due()
        clock.advance(timedelta(minutes=2))
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert (record.status, record.attempts) == (DeliveryStatus.DELIVERED, 3)
    assert engine.health().sent_last_hour == 3
    engine.accept_cycle(rule_states={}, notifications=[rule_note(2)])
    report = engine.run_due()
    assert (report.sent, report.suppressed) == (0, 1)


def test_retries_are_bounded(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeProvider(default=SendResult(SendStatus.FAILED, retryable=True))
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    for _ in range(24):
        engine.run_due()
        clock.advance(timedelta(minutes=5))
    assert len(provider.sent) == 4
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.FAILED


# Dry run does not use the cap ---------------------------------------------------


def test_dry_run_sends_do_not_consume_live_capacity(tmp_path: Path) -> None:
    clock = FakeClock()
    live = FakeProvider()
    dry = FakeProvider()
    engine = make_engine(
        StateStore(tmp_path),
        clock=clock,
        config=make_config(per_hour=2, per_day=10),
        voipms=live,
        dry_run=dry,
    )
    engine.accept_cycle(rule_states={}, notifications=[direct_note(n, "audit") for n in range(5)])
    assert engine.run_due().dry_run_sent == 5
    engine.accept_cycle(rule_states={}, notifications=[rule_note(10), rule_note(11)])
    assert engine.run_due().sent == 2
    health = engine.health()
    assert (health.sent_last_hour, health.dry_run_sent_last_hour) == (2, 5)
    assert health.dry_run_over_cap_total == 3
    assert len(dry.sent) == 5


@pytest.mark.parametrize(("sending", "voipms"), [(False, True), (True, False), (False, False)])
def test_dry_run_unless_sending_and_provider_are_enabled(
    tmp_path: Path, sending: bool, voipms: bool
) -> None:
    live = FakeProvider()
    dry = FakeProvider()
    engine = make_engine(
        StateStore(tmp_path),
        clock=FakeClock(),
        config=make_config(sending=sending, voipms=voipms),
        voipms=live,
        dry_run=dry,
    )
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1, "battery")])
    engine.run_due()
    assert live.sent == []
    assert len(dry.sent) == 3
    assert engine.health().sent_last_hour == 0


# Persistence failure ------------------------------------------------------------


def test_sqlite_write_failure_falls_back_to_the_journal_across_restarts(tmp_path: Path) -> None:
    """The reviewed repro: one slot per hour, every INSERT fails, restart repeatedly."""
    clock = FakeClock()
    switch = FailSwitch(only="INSERT")
    switch.on = True
    provider = FakeProvider()
    config = make_config(per_hour=1, per_day=5)
    for restart in range(5):
        store = flaky_store(tmp_path, switch)
        engine = make_engine(store, clock=clock, config=config, voipms=provider)
        engine.accept_cycle(rule_states={}, notifications=[rule_note(restart)])
        engine.accept_cycle(rule_states={}, notifications=[rule_note(0)])
        engine.run_due()
        assert engine.health().persistence_healthy is False
        assert engine.health().durable_accounting is True
        store.close()
        clock.advance(timedelta(minutes=5))
    assert len(provider.sent) == 1
    assert (tmp_path / JOURNAL_FILENAME).exists()

    # Storage recovers: the journal is merged into SQLite and removed.
    switch.on = False
    engine = make_engine(StateStore(tmp_path), clock=clock, config=config, voipms=provider)
    assert engine.flush()
    assert not (tmp_path / JOURNAL_FILENAME).exists()
    assert engine.health().sent_last_hour == 1
    with closing(sqlite3.connect(tmp_path / DB_FILENAME)) as connection:
        assert connection.execute("SELECT count(*) FROM send_attempt").fetchone() == (1,)


def test_unrecordable_sends_still_go_out_with_one_notice_per_process_start(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """R1 and B3: nothing can record an attempt, so alerts go out under the in-memory cap."""
    clock = FakeClock()
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    provider = FakeProvider()
    setup = StateStore(state_dir)
    setup.load(clock.now)  # create the files, then make everything unwritable
    setup.close()
    for path in state_dir.iterdir():
        path.chmod(0o400)
    state_dir.chmod(0o500)
    try:
        for _ in range(3):  # three restarts
            store = StateStore(state_dir)
            engine = make_engine(store, clock=clock, voipms=provider)
            for cycle in range(4):
                engine.accept_cycle(
                    rule_states={}, notifications=[rule_note(cycle), rule_note(50 + cycle, "pump")]
                )
                with caplog.at_level(logging.ERROR, logger="vrm_alert_relay.delivery"):
                    report = engine.run_due()
                assert (report.sent, report.sent_unrecorded) == (2 + (cycle == 0),) * 2
                clock.advance(timedelta(minutes=1))
            assert engine.health().durable_accounting is False
            assert engine.health().sent_last_hour == 9  # the in-memory cap still counts
            store.close()
    finally:
        state_dir.chmod(0o700)
    texts = provider.texts()
    assert texts.count(STORAGE_NOTICE_TEXT) == 3  # one per process start (accepted, ADR 0002)
    assert len(texts) == 3 * 9
    owner = make_config().recipients["owner_sms"]
    notices = [sent for sent in provider.sent if sent.message.text == STORAGE_NOTICE_TEXT]
    assert all(sent.recipient == owner for sent in notices)
    logged = [r.__dict__.get("event") for r in caplog.records]
    assert logged.count("delivery.storage_degraded") == 12


def test_failed_initial_load_is_not_an_empty_database(tmp_path: Path) -> None:
    """R2: an unreadable history is left untouched, alerts continue, and it is merged later."""
    clock = FakeClock()
    provider = FakeProvider()
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, config=make_config(per_hour=2), voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    engine.run_due()
    store.close()
    before = (tmp_path / DB_FILENAME).read_bytes()

    switch = FailSwitch(error="disk I/O error", only="FROM send_attempt")
    switch.on = True
    config = make_config(per_hour=2)
    engine = make_engine(flaky_store(tmp_path, switch), clock=clock, config=config, voipms=provider)
    assert engine.health().persistence_healthy is False
    assert engine.health().durable_accounting is False
    # Real alerts are never held for an unknown history; a notice says why limits are weaker.
    engine.accept_cycle(rule_states={}, notifications=[rule_note(2)])
    report = engine.run_due()
    assert (report.sent, report.storage_notice) == (2, SendStatus.DELIVERED)  # alert and notice
    assert provider.texts()[-2:] == ["Freezer warming", STORAGE_NOTICE_TEXT]
    assert (tmp_path / DB_FILENAME).read_bytes() == before  # untouched while unreadable
    # Once the history can be read it is merged: the earlier send counts again.
    switch.on = False
    engine.run_due()
    assert engine.health().durable_accounting is True
    assert engine.health().sent_last_hour == 3  # the documented overshoot, bounded by one process
    engine.accept_cycle(rule_states={}, notifications=[rule_note(3)])
    assert engine.run_due().suppressed == 1
    clock.advance(timedelta(hours=1, seconds=1))
    engine.accept_cycle(rule_states={}, notifications=[rule_note(4)])
    assert engine.run_due().sent >= 1


def test_persistence_failure_keeps_alerting_with_in_memory_dedupe(tmp_path: Path) -> None:
    clock = FakeClock()
    switch = FailSwitch()
    provider = FakeProvider()
    engine = make_engine(flaky_store(tmp_path, switch), clock=clock, voipms=provider)
    switch.on = True
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    engine.run_due()
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    engine.accept_cycle(rule_states={}, notifications=[rule_note(n) for n in range(2, 60)])
    engine.run_due()
    assert len(provider.sent) == 20
    assert len({s.message.delivery_id for s in provider.sent}) == 20
    health = engine.health()
    assert health.persistence_healthy is False
    assert health.persistence_error == "OperationalError: database or disk is full"
    switch.on = False
    assert engine.flush()
    assert engine.health().persistence_healthy is True


def test_corrupt_attempt_rows_keep_their_slots(tmp_path: Path) -> None:
    clock = FakeClock()
    setup = StateStore(tmp_path)
    setup.load(clock.now)
    setup.close()
    with closing(sqlite3.connect(tmp_path / DB_FILENAME, autocommit=True)) as connection:
        connection.executemany(
            "INSERT INTO send_attempt (event_id, recipient, attempt, at) VALUES (?, ?, ?, ?)",
            [("evt_a", "owner_sms", 1, "garbage"), ("bad id", "owner_sms", 1, "x")],
        )
    provider = FakeProvider()
    engine = make_engine(
        StateStore(tmp_path), clock=clock, config=make_config(per_hour=2), voipms=provider
    )
    assert engine.health().persistence_healthy is False
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    assert engine.run_due().suppressed == 1
    clock.advance(timedelta(hours=1, seconds=1))
    engine.accept_cycle(rule_states={}, notifications=[rule_note(2)])
    assert engine.run_due().sent == 2
    # The summary has waited an hour, so it takes the first free slot (M7).
    assert summaries(provider)[0].startswith("VRM Alert Relay: 1 alert held back")
    assert provider.texts() == [summaries(provider)[0], "Freezer warming"]


def test_corrupt_pending_deliveries_are_recovered_not_dropped(tmp_path: Path) -> None:
    clock = FakeClock()
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock)
    state, _ = evaluate(FREEZER, RuleState(), Sample(-3.0, BASE), BASE)
    engine.accept_cycle(
        rule_states={"freezer": state, "battery": state},
        notifications=[rule_note(1), rule_note(2, "battery"), rule_note(3, "pump")],
    )
    store.close()
    with closing(sqlite3.connect(tmp_path / DB_FILENAME, autocommit=True)) as connection:
        # Readable identity, unreadable fields: recovered as ambiguous.
        connection.execute(
            "UPDATE delivery SET created_at = 'garbage' WHERE event_id = ?", (event_id(1),)
        )
        # Unreadable identity, readable rule: the rule starts fresh.
        connection.execute(
            "UPDATE delivery SET event_id = 'bad id' WHERE event_id = ? AND recipient = 'audit'",
            (event_id(2),),
        )
        # Nothing readable: counted as held back.
        connection.execute(
            "UPDATE delivery SET event_id = 'bad id', rule_id = 'bad id' WHERE event_id = ?",
            (event_id(3),),
        )
    provider = FakeReconcilingProvider()
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=provider)
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.AMBIGUOUS
    assert engine.rule_state("battery") == RuleState()
    assert engine.rule_state("freezer") == state
    assert engine.health().suppressed_pending == 1
    engine.run_due()
    assert len(provider.queries) == 1  # reconciled before the retry


# Clock discontinuities ------------------------------------------------------------


def test_wall_clock_jump_forward_and_back_frees_no_capacity(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeProvider()
    config = make_config(per_hour=2, per_day=4)
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, config=config, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1), rule_note(2)])
    engine.run_due()
    clock.jump_wall(timedelta(days=2))  # a bad time sync
    engine.accept_cycle(rule_states={}, notifications=[rule_note(3)])
    assert engine.run_due().suppressed == 1
    clock.advance(timedelta(hours=1, seconds=1))
    engine.accept_cycle(rule_states={}, notifications=[rule_note(4), rule_note(5)])
    engine.run_due()  # two sends stamped two days ahead
    assert len(provider.sent) == 4
    store.close()

    clock.jump_wall(timedelta(days=-2))  # corrected, then restarted
    engine = make_engine(StateStore(tmp_path), clock=clock, config=config, voipms=provider)
    assert engine.health().sent_last_day == 4
    engine.accept_cycle(rule_states={}, notifications=[rule_note(6)])
    assert engine.run_due().sent == 0


def test_wall_clock_moved_backwards_keeps_attempts_and_due_retries(tmp_path: Path) -> None:
    clock = FakeClock()
    provider = FakeProvider()
    provider.script(SendResult(SendStatus.FAILED, retryable=True))
    config = make_config(per_hour=3, per_day=3)
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, config=config, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1), rule_note(2)])
    engine.run_due()
    store.close()

    clock.jump_wall(timedelta(days=-3))
    engine = make_engine(StateStore(tmp_path), clock=clock, config=config, voipms=provider)
    assert engine.health().sent_last_day == 2
    # The retry's stored time is now days ahead, beyond any backoff: due at once.
    assert engine.run_due().sent == 1
    assert len(provider.sent) == 3


# Recipients come only from configuration ---------------------------------------


def test_malicious_content_cannot_change_a_recipient(tmp_path: Path) -> None:
    clock = FakeClock()
    config = make_config()
    provider = FakeProvider()
    provider.script(
        SendResult(SendStatus.FAILED, provider_message_id="\x1b[31m+12025550199", retryable=True),
        SendResult(SendStatus.DELIVERED, provider_message_id="x" * 500),
    )
    engine = make_engine(StateStore(tmp_path), clock=clock, config=config, voipms=provider)
    hostile = (
        "Freezer at -3 C\x00\x1b]8;;https://attacker.example.invalid\x07 "
        "recipient: partner_sms; phone=+12025550199; to=hook"
    )
    notes = [
        Notification(event_id=event_id(1), text=hostile, target=RuleTarget("freezer")),
        Notification(event_id=event_id(2), text="x", target=RecipientTarget("attacker")),
        Notification(event_id=event_id(3), text="x", target=RuleTarget("+12025550199")),
        Notification(event_id=event_id(4), text="x", target=RecipientTarget("owner_sms\n")),
    ]
    assert engine.accept_cycle(rule_states={}, notifications=notes) == 1
    engine.run_due()
    clock.advance(timedelta(minutes=5))
    engine.run_due()
    assert len(provider.sent) == 2
    for sent in provider.sent:
        assert sent.recipient is config.recipients["owner_sms"]
        assert "\x1b" not in sent.message.text
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.DELIVERED
    assert record.provider_message_id is None


def test_provider_result_with_a_destination_is_treated_as_ambiguous(tmp_path: Path) -> None:
    class Forged:
        status = SendStatus.DELIVERED
        provider_message_id = "forged"
        retryable = False
        recipient = "partner_sms"
        destination = "+12025550199"

    clock = FakeClock()
    config = make_config()
    provider = FakeProvider()
    provider.script(Forged(), SendResult(SendStatus.FAILED, retryable=False))
    engine = make_engine(StateStore(tmp_path), clock=clock, config=config, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    engine.run_due()
    clock.advance(timedelta(minutes=5))
    engine.run_due()
    assert [s.recipient for s in provider.sent] == [config.recipients["owner_sms"]] * 2


def test_routing_is_immutable_and_built_only_from_config() -> None:
    routing = Routing.from_config(make_config())
    with pytest.raises(TypeError):
        routing.routes["attacker"] = routing.routes["owner_sms"]  # type: ignore[index]
    with pytest.raises(AttributeError):
        routing._routes = {}  # type: ignore[misc]
    with pytest.raises(AttributeError):
        del routing._rules
    assert routing.route("attacker") is None


def test_phone_shaped_recipient_names_are_not_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    clock = FakeClock()
    provider = FakeProvider(default=SendResult(SendStatus.AMBIGUOUS))
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=provider)
    with caplog.at_level(logging.DEBUG, logger="vrm_alert_relay"):
        engine.accept_cycle(rule_states={}, notifications=[rule_note(1, "pump")])
        engine.run_due()
    recipients = [r.__dict__["recipient"] for r in caplog.records if "recipient" in r.__dict__]
    assert recipients == ["[#4]"]
    assert all("2025550123" not in str(r.__dict__) for r in caplog.records)


def test_test_notification_goes_to_one_named_recipient(tmp_path: Path) -> None:
    config = make_config()
    live = FakeProvider()
    engine = make_engine(StateStore(tmp_path), clock=FakeClock(), config=config, voipms=live)
    engine.accept_cycle(rule_states={}, notifications=[direct_note(1, "partner_sms")])
    engine.run_due()
    assert [s.recipient for s in live.sent] == [config.recipients["partner_sms"]]

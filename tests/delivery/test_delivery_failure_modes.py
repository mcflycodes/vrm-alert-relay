"""Delivery under storage failure modes: alerting comes first (ADR 0002).

Each test names the review finding it covers. Every identifier, number, and
message here is fictitious.
"""

from __future__ import annotations

import errno
import os
import sqlite3
from contextlib import closing
from datetime import timedelta
from pathlib import Path

import pytest
from delivery_fakes import (
    FailSwitch,
    FakeClock,
    FakeProvider,
    FakeReconcilingProvider,
    flaky_store,
    make_config,
    make_engine,
    rule_note,
    summaries,
)

from vrm_alert_relay.delivery import STORAGE_NOTICE_TEXT, SendResult, SendStatus
from vrm_alert_relay.delivery import engine as engine_module
from vrm_alert_relay.engine import RuleState
from vrm_alert_relay.state import (
    DB_FILENAME,
    JOURNAL_FILENAME,
    Changes,
    DeliveryKind,
    DeliveryStatus,
    JournalEntry,
    StateStore,
    SuppressionState,
)


def test_journal_keeps_a_full_day_of_sends_while_sqlite_is_down(tmp_path: Path) -> None:
    """B2: a small journal is compacted, never rotated, so no send is forgotten at restart."""
    clock = FakeClock()
    switch = FailSwitch(only="INSERT")
    switch.on = True
    provider = FakeProvider()
    config = make_config(per_hour=20, per_day=60)
    store = flaky_store(tmp_path, switch, journal_max_bytes=4096)
    engine = make_engine(store, clock=clock, config=config, voipms=provider)
    for n in range(60):
        engine.accept_cycle(rule_states={}, notifications=[rule_note(n)])
        engine.run_due()
        clock.advance(timedelta(minutes=20))
    assert len(provider.sent) == 60
    store.close()
    switch.on = False
    engine = make_engine(StateStore(tmp_path), clock=clock, config=config, voipms=provider)
    assert engine.health().sent_last_day == 60
    engine.accept_cycle(rule_states={}, notifications=[rule_note(100)])
    assert engine.run_due().sent == 0  # the daily cap is still full after the restart


def test_a_recorded_notice_is_not_repeated_after_a_restart(tmp_path: Path) -> None:
    """B3: when the journal can record the notice, a restart does not send another."""
    clock = FakeClock()
    switch = FailSwitch(error="disk I/O error", only="FROM send_attempt")
    switch.on = True
    provider = FakeProvider()
    for _ in range(3):
        store = flaky_store(tmp_path, switch)
        engine = make_engine(store, clock=clock, voipms=provider)
        engine.run_due()
        store.close()
        clock.advance(timedelta(minutes=5))
    assert provider.texts() == [STORAGE_NOTICE_TEXT]
    clock.advance(timedelta(days=1))
    engine = make_engine(flaky_store(tmp_path, switch), clock=clock, voipms=provider)
    engine.run_due()
    assert provider.texts() == [STORAGE_NOTICE_TEXT] * 2  # a day later it is repeated


def test_held_back_alerts_survive_a_restart_while_sqlite_is_down(tmp_path: Path) -> None:
    """H4: suppression goes to the journal by delivery identity; a restart neither loses
    nor double counts it, and a summary delivered while SQLite is down settles it."""
    clock = FakeClock()
    switch = FailSwitch(only="INSERT")
    provider = FakeProvider()
    config = make_config(per_hour=1)
    store = flaky_store(tmp_path, switch)
    engine = make_engine(store, clock=clock, config=config, voipms=provider)
    switch.on = True
    engine.accept_cycle(rule_states={}, notifications=[rule_note(n) for n in range(4)])
    engine.run_due()
    assert engine.health().suppressed_pending == 3
    store.close()
    for _ in range(2):  # restarting twice must not count anything twice
        store = flaky_store(tmp_path, switch)
        engine = make_engine(store, clock=clock, config=config, voipms=provider)
        assert engine.health().suppressed_pending == 3
        store.close()
    clock.advance(timedelta(hours=1, seconds=1))
    store = flaky_store(tmp_path, switch)
    engine = make_engine(store, clock=clock, config=config, voipms=provider)
    engine.run_due()
    assert summaries(provider) == [
        "VRM Alert Relay: 3 alert(s) held back by the global rate limit since 2035-01-01 00:00 UTC"
    ]
    store.close()
    switch.on = False
    engine = make_engine(StateStore(tmp_path), clock=clock, config=config, voipms=provider)
    assert engine.health().suppressed_pending == 0


def test_storage_notice_fails_over_in_order_and_reports_the_real_outcome(tmp_path: Path) -> None:
    """H6: a definite failure moves on to the next system recipient; the outcome is reported."""
    clock = FakeClock()
    switch = FailSwitch(error="disk I/O error", only="FROM send_attempt")
    switch.on = True
    provider = FakeProvider()
    provider.script(SendResult(SendStatus.FAILED), SendResult(SendStatus.FAILED))
    config = make_config(system=("owner_sms", "partner_sms"))
    engine = make_engine(flaky_store(tmp_path, switch), clock=clock, config=config, voipms=provider)
    report = engine.run_due()
    assert report.storage_notice is SendStatus.FAILED
    recipients = [sent.recipient for sent in provider.sent]
    assert recipients == [config.recipients["owner_sms"], config.recipients["partner_sms"]]


def test_storage_notice_stops_at_an_unknown_outcome(tmp_path: Path) -> None:
    """H6: an ambiguous notice may have arrived, so the next recipient is not tried."""
    clock = FakeClock()
    switch = FailSwitch(error="disk I/O error", only="FROM send_attempt")
    switch.on = True
    provider = FakeProvider()
    provider.script(SendResult(SendStatus.AMBIGUOUS))
    config = make_config(system=("owner_sms", "partner_sms"))
    engine = make_engine(flaky_store(tmp_path, switch), clock=clock, config=config, voipms=provider)
    assert engine.run_due().storage_notice is SendStatus.AMBIGUOUS
    assert len(provider.sent) == 1
    clock.advance(timedelta(hours=2))
    assert engine.run_due().storage_notice is None  # not retried, not repeated


def test_a_corrupt_database_is_replaced_and_alerting_continues(tmp_path: Path) -> None:
    """R2: quarantine, start afresh with what was salvaged, notify once, keep alerting."""
    clock = FakeClock()
    provider = FakeProvider()
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, config=make_config(per_hour=3), voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    engine.run_due()
    store.close()
    with closing(sqlite3.connect(tmp_path / DB_FILENAME, autocommit=True)) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        root = connection.execute(
            "SELECT rootpage FROM sqlite_master WHERE name = 'delivery'"
        ).fetchone()[0]
        size = connection.execute("PRAGMA page_size").fetchone()[0]
    with (tmp_path / DB_FILENAME).open("r+b") as handle:
        handle.seek((root - 1) * size)
        handle.write(b"\xa5" * size)

    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, config=make_config(per_hour=3), voipms=provider)
    assert engine.health().persistence_healthy is False
    assert engine.health().sent_last_hour == 1  # salvaged send history, not a full window
    engine.accept_cycle(rule_states={}, notifications=[rule_note(2)])
    report = engine.run_due()
    assert report.storage_notice is SendStatus.DELIVERED
    assert provider.texts()[-2:] == ["Freezer warming", STORAGE_NOTICE_TEXT]
    assert len(list(tmp_path.glob(f"{DB_FILENAME}.corrupt-*"))) == 1
    store.close()
    engine = make_engine(StateStore(tmp_path), clock=clock, config=make_config(per_hour=3))
    assert engine.health().persistence_healthy is True
    assert engine.health().sent_last_hour == 3  # everything was rewritten into the new file


def test_a_newer_schema_keeps_alerting_from_memory_and_the_journal(tmp_path: Path) -> None:
    """R2: a newer schema is left alone, alerts continue, and the journal records them."""
    clock = FakeClock()
    setup = StateStore(tmp_path)
    setup.load(clock.now)
    setup.close()
    with closing(sqlite3.connect(tmp_path / DB_FILENAME, autocommit=True)) as connection:
        connection.execute("PRAGMA user_version = 99")
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    report = engine.run_due()
    assert (report.sent, report.sent_unrecorded) == (2, 0)  # the alert and the notice
    assert (tmp_path / JOURNAL_FILENAME).exists()


def test_wall_clock_jump_while_the_history_is_unread_frees_no_capacity(tmp_path: Path) -> None:
    """The C6 regression: merging the history mid-process keeps the slots already held."""
    clock = FakeClock()
    provider = FakeProvider()
    config = make_config(per_hour=2)
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, config=config, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(n) for n in range(3)])
    engine.run_due()
    assert len(provider.sent) == 2
    journal = tmp_path / JOURNAL_FILENAME
    journal.touch()
    journal.chmod(0o000)
    store.close()
    try:
        store = StateStore(tmp_path)
        engine = make_engine(store, clock=clock, config=config, voipms=provider)
        clock.jump_wall(timedelta(hours=3))
    finally:
        journal.chmod(0o600)
    engine.run_due()
    assert len(provider.sent) == 2
    store.close()


def _held_back_then_summary_attempted(
    tmp_path: Path, switch: FailSwitch, provider: FakeProvider
) -> FakeClock:
    """Fill a 1/hour cap, hold back two alerts, then try a summary that fails retryably."""
    clock = FakeClock()
    config = make_config(per_hour=1)
    store = flaky_store(tmp_path, switch)
    engine = make_engine(store, clock=clock, config=config, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(n) for n in range(3)])
    engine.run_due()
    clock.advance(timedelta(hours=1, seconds=1))
    provider.script(SendResult(SendStatus.FAILED, retryable=True))
    engine.run_due()
    assert len(summaries(provider)) == 1
    store.close()
    return clock


def test_a_summary_in_progress_resumes_after_a_restart(tmp_path: Path) -> None:
    provider = FakeProvider()
    clock = _held_back_then_summary_attempted(tmp_path, FailSwitch(), provider)
    clock.advance(timedelta(hours=1, seconds=1))
    engine = make_engine(
        StateStore(tmp_path), clock=clock, config=make_config(per_hour=1), voipms=provider
    )
    engine.run_due()
    assert len(summaries(provider)) == 2
    assert engine.health().suppressed_pending == 0


def test_a_summary_only_the_journal_knows_resumes_after_a_restart(tmp_path: Path) -> None:
    """H4: the summary's start reached only the journal; it is resumed, and its delivery
    settles the count instead of leaving it to be reported twice."""
    switch = FailSwitch(only="INSERT")
    provider = FakeProvider()
    switch.on = False
    clock = FakeClock()
    config = make_config(per_hour=1)
    store = flaky_store(tmp_path, switch)
    engine = make_engine(store, clock=clock, config=config, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(n) for n in range(3)])
    engine.run_due()
    switch.on = True  # from here on only the journal records anything
    clock.advance(timedelta(hours=1, seconds=1))
    provider.script(SendResult(SendStatus.FAILED, retryable=True))
    engine.run_due()
    store.close()
    clock.advance(timedelta(hours=1, seconds=1))
    store = flaky_store(tmp_path, switch)
    engine = make_engine(store, clock=clock, config=config, voipms=provider)
    engine.run_due()
    assert len(summaries(provider)) == 2
    assert summaries(provider)[0] == summaries(provider)[1]  # the same summary, retried
    assert engine.health().suppressed_pending == 0
    store.close()


@pytest.mark.parametrize("held_here", [True, False])
def test_state_unreadable_at_startup_is_merged_once_it_can_be_read(
    tmp_path: Path, held_here: bool
) -> None:
    """R2: a transient read failure is retried each cycle; what was stored is then merged."""
    clock = FakeClock()
    seed = make_engine(StateStore(tmp_path), clock=clock, config=make_config(per_hour=1))
    seed.accept_cycle(
        rule_states={"battery": RuleState()}, notifications=[rule_note(n) for n in range(3)]
    )
    seed.run_due()  # one sent, two held back
    seed._store.close()
    switch = FailSwitch(error="disk I/O error", only="FROM meta ")
    switch.on = True
    provider = FakeProvider()
    store = flaky_store(tmp_path, switch)
    engine = make_engine(store, clock=clock, config=make_config(per_hour=1), voipms=provider)
    assert engine.health().suppressed_pending == 0  # not known yet
    if held_here:
        engine.accept_cycle(rule_states={}, notifications=[rule_note(10)])
        engine.run_due()  # the stored send still fills the 1/hour cap, so this is held
        assert engine.health().suppressed_pending == 1
    switch.on = False
    engine.run_due()
    # The stored two, plus any this process held back itself.
    assert engine.health().suppressed_pending == 2 + held_here
    assert engine.rule_state("battery") == RuleState()
    store.close()


def test_a_database_found_corrupt_after_a_transient_failure_is_replaced(tmp_path: Path) -> None:
    clock = FakeClock()
    failing = {"on": True}

    def connect(path: Path) -> sqlite3.Connection:
        if failing["on"]:
            raise sqlite3.OperationalError("database is locked")
        return sqlite3.connect(path, autocommit=True)

    setup = StateStore(tmp_path)
    setup.load(clock.now)
    setup.close()
    provider = FakeProvider()
    store = StateStore(tmp_path, connect=connect)
    engine = make_engine(store, clock=clock, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    engine.run_due()
    (tmp_path / DB_FILENAME).write_bytes(b"not a database" * 64)
    failing["on"] = False
    engine.run_due()
    assert len(list(tmp_path.glob(f"{DB_FILENAME}.corrupt-*"))) == 1
    store.close()
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=provider)
    assert engine.record(rule_note(1).event_id, "owner_sms") is not None  # rewritten afresh


def _seed_pending_with_corrupt_attempts(tmp_path: Path, clock: FakeClock, *, marks: int) -> None:
    """A pending delivery whose stored attempt count is out of bounds, after ``marks`` sends."""
    seed = make_engine(StateStore(tmp_path), clock=clock)
    seed.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    seed._store.close()
    with closing(sqlite3.connect(tmp_path / DB_FILENAME, autocommit=True)) as connection:
        connection.executemany(
            "INSERT INTO send_attempt (event_id, recipient, attempt, at) VALUES (?, ?, ?, ?)",
            [
                (rule_note(1).event_id, "owner_sms", n, "2035-01-01T00:00:00.000000+00:00")
                for n in range(1, marks + 1)
            ],
        )
        connection.execute("UPDATE delivery SET attempts = 500")


@pytest.mark.parametrize("reconciling", [False, True])
def test_a_corrupt_unfinished_delivery_is_reconciled_then_retried(
    tmp_path: Path, reconciling: bool
) -> None:
    """H1: an out-of-bounds attempt count never fails a delivery without a provider call."""
    clock = FakeClock()
    _seed_pending_with_corrupt_attempts(tmp_path, clock, marks=0)
    provider = FakeReconcilingProvider() if reconciling else FakeProvider()
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=provider)
    report = engine.run_due()
    assert provider.texts()[0] == "Freezer warming"
    assert report.delivered >= 1
    if reconciling:
        assert len(provider.queries) == 1  # reconciled before the retry


def test_a_recovered_delivery_keeps_its_retry_across_a_restart(tmp_path: Path) -> None:
    """H1: the recovered mark is stored, and the retry is numbered past every stored attempt."""
    clock = FakeClock()
    _seed_pending_with_corrupt_attempts(tmp_path, clock, marks=3)
    salvage = StateStore(tmp_path)
    salvage.load(clock.now)  # salvages and writes the repair back, then stops
    salvage.close()
    provider = FakeProvider()
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, config=make_config(per_hour=5), voipms=provider)
    engine.run_due()
    assert provider.texts() == ["Freezer warming"]
    store.close()
    engine = make_engine(StateStore(tmp_path), clock=clock, config=make_config(per_hour=5))
    assert engine.health().sent_last_hour == 4  # three stored sends and the retry, all kept


def test_a_recovered_retry_is_bounded(tmp_path: Path) -> None:
    """H1: the guaranteed retry is one attempt; past the ceiling it then fails."""
    clock = FakeClock()
    _seed_pending_with_corrupt_attempts(tmp_path, clock, marks=4)
    provider = FakeProvider()
    provider.script(SendResult(SendStatus.FAILED, retryable=True))
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=provider)
    engine.run_due()
    clock.advance(timedelta(hours=1))
    report = engine.run_due()
    assert len(provider.sent) == 1
    assert report.failed == 0  # it already failed at the end of the retry
    record = engine.record(rule_note(1).event_id, "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.FAILED


@pytest.mark.parametrize("with_summary", [False, True])
def test_suppression_unread_at_startup_is_merged_by_identity(
    tmp_path: Path, with_summary: bool
) -> None:
    """M2: a held-back delivery stored in SQLite and repeated in the journal counts once,
    and a summary stored as delivered is not subtracted again."""
    clock = FakeClock()
    config = make_config(per_hour=1)
    store = StateStore(tmp_path)
    seed = make_engine(store, clock=clock, config=config)
    seed.accept_cycle(rule_states={}, notifications=[rule_note(n) for n in range(3)])
    seed.run_due()  # one sent, two held back
    held = [rule_note(n).event_id for n in (1, 2)]
    if with_summary:
        clock.advance(timedelta(hours=1, seconds=1))
        seed.run_due()  # the summary reports both
        seed.accept_cycle(rule_states={}, notifications=[rule_note(3)])
        seed.run_due()  # held back: the summary took the slot
        held.append(rule_note(3).event_id)
    expected = 1 if with_summary else 2
    assert seed.health().suppressed_pending == expected
    # Everything reached SQLite, and the same changes were also journaled.
    repeated = [seed.record(event, "owner_sms") for event in held]
    repeated += [r for r in seed._records.values() if r.kind is DeliveryKind.SUMMARY]
    assert store.journal(
        tuple(JournalEntry(r, attempt=False) for r in repeated if r is not None), clock.now
    )
    store.close()

    failing = {"on": True}

    def connect(path: Path) -> sqlite3.Connection:
        if failing["on"]:
            raise sqlite3.OperationalError("database is locked")
        return sqlite3.connect(path, autocommit=True)

    store = StateStore(tmp_path, connect=connect)
    engine = make_engine(store, clock=clock, config=config)
    failing["on"] = False
    engine.run_due()
    assert engine.health().suppressed_pending == expected
    store.close()


def test_a_summary_lost_with_a_corrupt_database_is_opened_again(tmp_path: Path) -> None:
    """M4: the stored summary id outlived its deliveries; the count is still summarised."""
    provider = FakeProvider()
    clock = _held_back_then_summary_attempted(tmp_path, FailSwitch(), provider)
    with closing(sqlite3.connect(tmp_path / DB_FILENAME, autocommit=True)) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        root = connection.execute(
            "SELECT rootpage FROM sqlite_master WHERE name = 'delivery'"
        ).fetchone()[0]
        size = connection.execute("PRAGMA page_size").fetchone()[0]
    with (tmp_path / DB_FILENAME).open("r+b") as handle:
        handle.seek((root - 1) * size)
        handle.write(b"\xa5" * size)
    config = make_config(per_hour=1)
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, config=config, voipms=provider)
    assert engine.health().suppressed_pending == 2
    for _ in range(4):
        clock.advance(timedelta(hours=1, seconds=1))
        engine.run_due()
    held_back = [text for text in summaries(provider) if text != STORAGE_NOTICE_TEXT]
    assert held_back[-1] == (
        "VRM Alert Relay: 2 alert(s) held back by the global rate limit since 2035-01-01 00:00 UTC"
    )
    assert len(held_back) == 2
    assert engine.health().suppressed_pending == 0
    store.close()


def test_a_delayed_storage_notice_waits_a_day_from_when_it_was_sent(tmp_path: Path) -> None:
    """L5: the notice interval starts at the first provider call, not when it was due."""
    clock = FakeClock()
    switch = FailSwitch(error="disk I/O error", only="FROM send_attempt")
    switch.on = True
    provider = FakeProvider()
    config = make_config(per_hour=2, per_day=2)
    engine = make_engine(flaky_store(tmp_path, switch), clock=clock, config=config, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1), rule_note(2)])
    engine.run_due()  # both alerts fill the day; the notice waits
    assert STORAGE_NOTICE_TEXT not in provider.texts()
    clock.advance(timedelta(days=1, seconds=1))
    engine.run_due()
    assert provider.texts().count(STORAGE_NOTICE_TEXT) == 1
    clock.advance(timedelta(minutes=1))
    engine.run_due()
    assert provider.texts().count(STORAGE_NOTICE_TEXT) == 1
    clock.advance(timedelta(days=1))
    engine.run_due()
    assert provider.texts().count(STORAGE_NOTICE_TEXT) == 2


def test_sent_counts_every_real_call_and_unrecorded_is_a_subset(tmp_path: Path) -> None:
    """L6: ``sent`` is every real provider call; ``sent_unrecorded`` those not recorded."""
    clock = FakeClock()
    switch = FailSwitch()
    store = flaky_store(tmp_path, switch)
    engine = make_engine(store, clock=clock)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)])
    journal = tmp_path / JOURNAL_FILENAME
    journal.mkdir()  # the journal cannot be written either
    switch.on = True
    report = engine.run_due()
    assert (report.sent, report.sent_unrecorded) == (2, 2)  # the alert and the notice
    journal.rmdir()
    engine.accept_cycle(rule_states={}, notifications=[rule_note(2)])
    report = engine.run_due()
    assert (report.sent, report.sent_unrecorded) == (1, 0)  # journaled, so recorded


def _unreadable_until_switched(tmp_path: Path) -> tuple[StateStore, dict[str, bool]]:
    failing = {"on": True}

    def connect(path: Path) -> sqlite3.Connection:
        if failing["on"]:
            raise sqlite3.OperationalError("database is locked")
        return sqlite3.connect(path, autocommit=True)

    return StateStore(tmp_path, connect=connect), failing


def test_a_summary_opened_while_the_counts_were_unread_settles_them(tmp_path: Path) -> None:
    """M2: a summary this process started is kept through the merge, and the delivery it
    reports, stored in SQLite and repeated in the journal, is not left over afterwards."""
    clock = FakeClock()
    config = make_config(per_hour=1)
    store = StateStore(tmp_path)
    seed = make_engine(store, clock=clock, config=config)
    seed.accept_cycle(rule_states={}, notifications=[rule_note(0), rule_note(1)])
    seed.run_due()  # one sent, one held back
    held = seed.record(rule_note(1).event_id, "owner_sms")
    assert held is not None
    assert store.journal((JournalEntry(held, attempt=False),), clock.now)
    store.close()
    clock.advance(timedelta(hours=1, seconds=1))
    provider = FakeProvider()
    store, failing = _unreadable_until_switched(tmp_path)
    engine = make_engine(store, clock=clock, config=config, voipms=provider)
    provider.script(SendResult(SendStatus.FAILED, retryable=True))
    engine.run_due()  # the summary starts while SQLite is unreadable, and stays open
    failing["on"] = False
    clock.advance(timedelta(hours=1, seconds=1))
    engine.run_due()
    held_back = [text for text in summaries(provider) if text != STORAGE_NOTICE_TEXT]
    assert held_back == [held_back[0]] * 2  # the same summary, retried
    assert engine.health().suppressed_pending == 0
    store.close()


def test_a_stored_summary_delivered_while_the_counts_were_unread_settles_them(
    tmp_path: Path,
) -> None:
    """M2: the journal resumed the stored summary; delivering it settles the stored count."""
    provider = FakeProvider()
    switch = FailSwitch(only="INSERT")
    clock = _held_back_then_summary_attempted(tmp_path, switch, provider)
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, config=make_config(per_hour=1))
    [summary] = [r for r in engine._records.values() if r.kind is DeliveryKind.SUMMARY]
    assert store.journal((JournalEntry(summary, attempt=False),), clock.now)
    store.close()
    store, failing = _unreadable_until_switched(tmp_path)
    engine = make_engine(store, clock=clock, config=make_config(per_hour=1), voipms=provider)
    clock.advance(timedelta(hours=1, seconds=1))
    engine.run_due()  # the summary is delivered while SQLite is still unreadable
    failing["on"] = False
    clock.advance(timedelta(hours=1, seconds=1))
    engine.run_due()
    assert engine.health().suppressed_pending == 0
    held_back = [text for text in summaries(provider) if text != STORAGE_NOTICE_TEXT]
    assert len(held_back) == 2  # the failed attempt and its retry; nothing reported again
    store.close()


def test_held_back_deliveries_past_the_ledger_bound_are_still_counted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M2: beyond its bound the ledger counts without identities, erring towards more."""
    monkeypatch.setattr(engine_module, "MAX_UNREAD_LEDGER", 1)
    clock = FakeClock()
    setup = StateStore(tmp_path)
    setup.load(clock.now)
    setup.close()
    store, failing = _unreadable_until_switched(tmp_path)
    engine = make_engine(store, clock=clock, config=make_config(per_hour=1))
    engine.accept_cycle(rule_states={}, notifications=[rule_note(n) for n in range(4)])
    engine.run_due()
    assert engine.health().suppressed_pending == 3
    failing["on"] = False
    engine.run_due()
    assert engine.health().suppressed_pending == 3
    store.close()


def test_a_lost_summary_with_nothing_held_back_is_simply_forgotten(tmp_path: Path) -> None:
    """M4: a stored summary id with no deliveries and no count blocks nothing."""
    clock = FakeClock()
    store = StateStore(tmp_path)
    store.load(clock.now)
    assert store.flush(
        Changes(suppression=SuppressionState(summary_event_id="sum_lost")), clock.now
    )
    store.close()
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, config=make_config(per_hour=1))
    engine.accept_cycle(rule_states={}, notifications=[rule_note(n) for n in range(2)])
    engine.run_due()
    clock.advance(timedelta(hours=1, seconds=1))
    engine.run_due()
    assert engine.health().suppressed_pending == 0
    store.close()


def test_a_journal_unreadable_at_startup_keeps_its_held_back_count(tmp_path: Path) -> None:
    """Round 4, item 1: SQLite was readable and only the journal was not; once the
    journal can be read, the alerts it held back are counted."""
    clock = FakeClock()
    config = make_config(per_hour=1)
    switch = FailSwitch(only="INSERT")
    store = flaky_store(tmp_path, switch)
    engine = make_engine(store, clock=clock, config=config)
    switch.on = True  # from here on only the journal records anything
    engine.accept_cycle(rule_states={}, notifications=[rule_note(n) for n in range(3)])
    engine.run_due()  # one sent, two held back
    assert engine.health().suppressed_pending == 2
    store.close()
    switch.on = False
    journal = tmp_path / JOURNAL_FILENAME
    journal.chmod(0o000)
    try:
        store = StateStore(tmp_path)
        engine = make_engine(store, clock=clock, config=config)
    finally:
        journal.chmod(0o600)
    engine.run_due()
    assert engine.health().suppressed_pending == 2
    store.close()


def test_a_stale_delivered_summary_line_never_subtracts_a_newer_alert(tmp_path: Path) -> None:
    """Round 4, item 2: a summary line left in the journal after SQLite recorded it, and
    after SQLite pruned it, does not settle an alert held back later."""
    clock = FakeClock()
    config = make_config(per_hour=1)
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, config=config)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(0), rule_note(1)])
    engine.run_due()  # one sent, one held back
    clock.advance(timedelta(hours=1, seconds=1))
    engine.run_due()  # the summary reports it
    [summary] = [r for r in engine._records.values() if r.kind is DeliveryKind.SUMMARY]
    assert summary.status is DeliveryStatus.DELIVERED
    clock.advance(timedelta(days=8))
    engine.run_due()  # retention prunes the summary's row
    engine.accept_cycle(rule_states={}, notifications=[rule_note(2), rule_note(3)])
    engine.run_due()  # one sent, one held back
    assert engine.health().suppressed_pending == 1
    # The summary's line outlived it in the journal, as when clearing the journal failed.
    assert store.journal((JournalEntry(summary, attempt=False),), clock.now)
    store.close()
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, config=config)
    assert engine.health().suppressed_pending == 1
    store.close()


def test_a_partial_quarantine_during_reload_is_retried(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round 4, item 3: while the database is still unread, every cycle reads it again."""
    clock = FakeClock()
    setup = StateStore(tmp_path)
    setup.load(clock.now)
    setup.close()
    store, failing = _unreadable_until_switched(tmp_path)
    engine = make_engine(store, clock=clock)
    (tmp_path / DB_FILENAME).write_bytes(b"not a database" * 64)
    link = os.link

    def refuse_the_database(source: Path, destination: Path, **kwargs: bool) -> None:
        if Path(source).name == DB_FILENAME:
            raise PermissionError(errno.EACCES, "Permission denied")
        link(source, destination, **kwargs)

    monkeypatch.setattr(os, "link", refuse_the_database)
    failing["on"] = False
    engine.run_due()  # found corrupt, but it cannot be moved aside
    assert list(tmp_path.glob(f"{DB_FILENAME}.corrupt-*")) == []
    engine.run_due()
    monkeypatch.setattr(os, "link", link)
    clock.advance(timedelta(minutes=1))
    engine.run_due()
    assert len(list(tmp_path.glob(f"{DB_FILENAME}.corrupt-*"))) == 1
    assert engine.health().durable_accounting is False  # unhealthy for the rest of the run
    store.close()

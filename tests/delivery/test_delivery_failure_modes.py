"""Delivery under storage failure modes: alerting comes first (ADR 0002).

Each test names the review finding it covers. Every identifier, number, and
message here is fictitious.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from delivery_fakes import (
    FailSwitch,
    FakeClock,
    FakeProvider,
    flaky_store,
    make_config,
    make_engine,
    rule_note,
    summaries,
)

from vrm_alert_relay.delivery import STORAGE_NOTICE_TEXT, SendResult, SendStatus
from vrm_alert_relay.engine import RuleState
from vrm_alert_relay.state import DB_FILENAME, JOURNAL_FILENAME, StateStore

if TYPE_CHECKING:
    from pathlib import Path


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
        "VRM Alert Relay: 3 alerts held back by the global rate limit since 2035-01-01 00:00 UTC."
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

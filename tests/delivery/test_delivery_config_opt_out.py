"""Opt-outs from configuration hold for deliveries queued before a restart.

A delivery queued under a configuration that sent it, then restored after a
restart under ``stale_notify: false`` or ``system_recipients: []``, is logged
instead of sent, whether it is read from SQLite, from the journal, or merged
once unreadable state becomes readable. Alarms, reminders, recoveries and
records of unknown origin are always sent. Every value here is fictitious.
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
    event_id,
    flaky_store,
    make_config,
    make_engine,
)

from vrm_alert_relay.delivery import Notification, Routing, RuleTarget, SystemTarget
from vrm_alert_relay.state import (
    DB_FILENAME,
    DeliveryOrigin,
    DeliveryStatus,
    StateStore,
)
from vrm_alert_relay.state.schema import MIGRATIONS, migrate

if TYPE_CHECKING:
    from pathlib import Path

    from vrm_alert_relay.config import RelayConfig
    from vrm_alert_relay.delivery import DeliveryEngine

# (event number, origin or None, rule or system target, text)
QUEUED: tuple[tuple[int, DeliveryOrigin | None, str | None, str], ...] = (
    (1, DeliveryOrigin.ALARM, "freezer", "alarm"),
    (2, DeliveryOrigin.REMINDER, "freezer", "reminder"),
    (3, DeliveryOrigin.RECOVERY, "freezer", "recovery"),
    (4, DeliveryOrigin.STALE, "freezer", "stale"),
    (5, DeliveryOrigin.RESTORED, "freezer", "restored"),
    (6, None, "freezer", "legacy"),
    (7, DeliveryOrigin.STALE, "pump", "pump stale"),
    (8, None, None, "system"),
)
ALWAYS_SENT = ["alarm", "reminder", "recovery", "legacy", "pump stale"]


def notes() -> list[Notification]:
    return [
        Notification(
            event_id=event_id(n),
            text=text,
            target=SystemTarget() if rule is None else RuleTarget(rule),
            origin=origin,
        )
        for n, origin, rule, text in QUEUED
    ]


def quiet() -> RelayConfig:
    return make_config(system=(), stale_notify=False)


def suppressed(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r for r in caplog.records if getattr(r, "event", None) == "delivery.suppressed_by_config"
    ]


def restart_quiet(store: StateStore, clock: FakeClock) -> tuple[DeliveryEngine, FakeProvider]:
    provider = FakeProvider()
    engine = make_engine(store, clock=clock, config=quiet(), voipms=provider)
    engine.run_due()
    return engine, provider


def queue_without_sending(store: StateStore, clock: FakeClock) -> None:
    engine = make_engine(store, clock=clock)
    assert engine.accept_cycle(rule_states={}, notifications=notes()) == len(QUEUED)
    store.close()


def assert_quiet_outcome(
    engine: DeliveryEngine, provider: FakeProvider, caplog: pytest.LogCaptureFixture
) -> None:
    assert sorted(provider.texts()) == sorted(ALWAYS_SENT)
    dropped = {r.event_id: r for r in suppressed(caplog)}  # type: ignore[attr-defined]
    assert set(dropped) == {event_id(4), event_id(5), event_id(8)}
    assert getattr(dropped[event_id(4)], "origin", None) == "stale"
    assert getattr(dropped[event_id(4)], "rule_id", None) == "freezer"
    assert getattr(dropped[event_id(8)], "origin", None) == "system"
    for n in (4, 5, 8):
        record = engine.record(event_id(n), "owner_sms")
        assert record is not None
        assert record.status is DeliveryStatus.FAILED
        assert record.attempts == 0
    assert engine.health().queued == 0


def test_queued_under_the_old_config_and_restored_from_sqlite(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    clock = FakeClock()
    queue_without_sending(StateStore(tmp_path), clock)

    with caplog.at_level(logging.INFO):
        engine, provider = restart_quiet(StateStore(tmp_path), clock)

    assert_quiet_outcome(engine, provider, caplog)
    engine._store.close()


def test_the_same_restart_without_opt_outs_sends_everything(tmp_path: Path) -> None:
    clock = FakeClock()
    queue_without_sending(StateStore(tmp_path), clock)
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), clock=clock, voipms=provider)
    engine.run_due()

    assert sorted(provider.texts()) == sorted(text for *_, text in QUEUED)
    engine._store.close()


def test_queued_only_in_the_journal(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    switch = FailSwitch(only="INSERT")
    switch.on = True  # SQLite records nothing; the journal records the deliveries
    clock = FakeClock()
    queue_without_sending(flaky_store(tmp_path, switch), clock)
    with closing(sqlite3.connect(tmp_path / DB_FILENAME)) as connection:
        assert connection.execute("SELECT count(*) FROM delivery").fetchone() == (0,)

    with caplog.at_level(logging.INFO):
        engine, provider = restart_quiet(flaky_store(tmp_path, switch), clock)

    assert_quiet_outcome(engine, provider, caplog)
    engine._store.close()


def test_queued_records_merged_once_state_is_readable_again(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    clock = FakeClock()
    queue_without_sending(StateStore(tmp_path), clock)
    switch = FailSwitch(error="disk I/O error", only="FROM delivery")
    switch.on = True
    store = flaky_store(tmp_path, switch)
    provider = FakeProvider()
    engine = make_engine(store, clock=clock, config=quiet(), voipms=provider)
    engine.run_due()
    assert provider.texts() == []  # nothing could be read yet
    switch.on = False

    with caplog.at_level(logging.INFO):
        engine.run_due()  # merges the stored deliveries, then processes them

    assert_quiet_outcome(engine, provider, caplog)
    store.close()


def test_a_legacy_database_is_migrated_and_only_its_system_deliveries_follow_opt_outs(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """0.1.0 stored no origin: its summaries are system notifications, but a rule
    event could be an alarm and is delivered once, whatever its text says."""
    with closing(sqlite3.connect(tmp_path / DB_FILENAME, autocommit=True)) as connection:
        assert migrate(connection, MIGRATIONS[:1]) == 1
        connection.executemany(
            "INSERT INTO delivery (event_id, recipient, rule_id, kind, status, text, attempts, "
            "created_at, updated_at, next_attempt_at) "
            "VALUES (?, 'owner_sms', ?, ?, 'pending', ?, 0, ?, ?, ?)",
            [
                (event_id(1), "freezer", "event", "Stale data: old", *[BASE.isoformat()] * 3),
                (event_id(2), None, "summary", "old summary", *[BASE.isoformat()] * 3),
                (event_id(3), None, "event", "old monitoring", *[BASE.isoformat()] * 3),
            ],
        )
    clock = FakeClock()

    with caplog.at_level(logging.INFO):
        engine, provider = restart_quiet(StateStore(tmp_path), clock)

    assert sorted(provider.texts()) == ["Stale data: old", "old monitoring"]
    (dropped,) = suppressed(caplog)
    assert getattr(dropped, "event_id", None) == event_id(2)
    assert getattr(dropped, "origin", None) == "system"
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.origin is None
    assert record.status is DeliveryStatus.DELIVERED
    engine._store.close()
    with closing(sqlite3.connect(tmp_path / DB_FILENAME)) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (len(MIGRATIONS),)
        assert connection.execute("SELECT DISTINCT origin FROM delivery").fetchall() == [(None,)]


def test_a_legacy_summary_is_still_sent_without_opt_outs(tmp_path: Path) -> None:
    with closing(sqlite3.connect(tmp_path / DB_FILENAME, autocommit=True)) as connection:
        assert migrate(connection, MIGRATIONS[:1]) == 1
        connection.execute(
            "INSERT INTO delivery (event_id, recipient, rule_id, kind, status, text, attempts, "
            "created_at, updated_at, next_attempt_at) "
            "VALUES (?, 'owner_sms', NULL, 'summary', 'pending', 'old summary', 0, ?, ?, ?)",
            (event_id(2), *[BASE.isoformat()] * 3),
        )
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), clock=FakeClock(), voipms=provider)
    engine.run_due()
    assert provider.texts() == ["old summary"]
    engine._store.close()


class _BrokenHandler(logging.Handler):
    """Fails on the opt-out record, past logging's own error handling."""

    def emit(self, record: logging.LogRecord) -> None:
        if getattr(record, "event", None) == "delivery.suppressed_by_config":
            raise RuntimeError

    def handleError(self, record: logging.LogRecord) -> None:  # noqa: N802  # logging API
        raise RuntimeError


def test_a_failing_log_handler_does_not_stop_a_later_alarm(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    clock = FakeClock()
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock)
    engine.accept_cycle(rule_states={}, notifications=[notes()[3]])  # stale, due first
    clock.advance(timedelta(seconds=1))
    engine.accept_cycle(rule_states={}, notifications=[notes()[0]])  # the alarm, due after
    store.close()
    handler = _BrokenHandler()
    engine_logger = logging.getLogger("vrm_alert_relay.delivery.engine")
    provider = FakeProvider()
    store = StateStore(tmp_path)
    engine = make_engine(store, clock=clock, config=quiet(), voipms=provider)
    engine_logger.addHandler(handler)
    try:
        with caplog.at_level(logging.INFO, logger=engine_logger.name):
            engine.run_due()
    finally:
        engine_logger.removeHandler(handler)

    assert provider.texts() == ["alarm"]
    stale = engine.record(event_id(4), "owner_sms")
    assert stale is not None
    assert stale.status is DeliveryStatus.FAILED
    store.close()


def test_a_failing_opt_out_check_sends_the_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = FakeClock()
    queue_without_sending(StateStore(tmp_path), clock)

    def broken(*_args: object) -> bool:
        raise RuntimeError

    monkeypatch.setattr(Routing, "opted_out", broken)
    engine, provider = restart_quiet(StateStore(tmp_path), clock)

    assert "stale" in provider.texts()
    assert "alarm" in provider.texts()
    engine._store.close()


def test_new_deliveries_are_stored_with_their_origin(tmp_path: Path) -> None:
    clock = FakeClock()
    queue_without_sending(StateStore(tmp_path), clock)
    with closing(sqlite3.connect(tmp_path / DB_FILENAME)) as connection:
        stored = dict(connection.execute("SELECT text, origin FROM delivery").fetchall())
    assert stored == {
        "alarm": "alarm",
        "reminder": "reminder",
        "recovery": "recovery",
        "stale": "stale",
        "restored": "restored",
        "legacy": None,
        "pump stale": "stale",
        "system": "system",
    }


def test_rate_limit_summary_is_stored_as_a_system_delivery(tmp_path: Path) -> None:
    clock = FakeClock()
    store = StateStore(tmp_path)
    provider = FakeProvider()
    engine = make_engine(store, clock=clock, config=make_config(per_hour=1), voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=notes()[:2])
    engine.run_due()  # one sent, one held back
    clock.advance(timedelta(hours=1, seconds=1))
    engine.run_due()  # the summary takes the next free slot
    store.close()

    assert any(text.startswith("VRM Alert Relay: 1 alert(s)") for text in provider.texts())
    with closing(sqlite3.connect(tmp_path / DB_FILENAME)) as connection:
        rows = connection.execute("SELECT origin FROM delivery WHERE kind = 'summary'").fetchall()
    assert rows == [("system",)]


@pytest.mark.parametrize(
    ("origin", "rule_id", "expected"),
    [
        (DeliveryOrigin.STALE, "freezer", True),
        (DeliveryOrigin.RESTORED, "freezer", True),
        (DeliveryOrigin.STALE, "pump", False),
        (DeliveryOrigin.STALE, "removed-rule", True),
        (DeliveryOrigin.RESTORED, None, True),
        (DeliveryOrigin.SYSTEM, None, True),
        (DeliveryOrigin.ALARM, "removed-rule", False),
        (DeliveryOrigin.REMINDER, "freezer", False),
        (DeliveryOrigin.RECOVERY, "freezer", False),
        (None, "freezer", False),
        (None, None, False),
    ],
)
def test_routing_opt_outs(
    origin: DeliveryOrigin | None, rule_id: str | None, expected: bool
) -> None:
    assert Routing.from_config(quiet()).opted_out(origin, rule_id) is expected


@pytest.mark.parametrize("origin", [DeliveryOrigin.STALE, DeliveryOrigin.SYSTEM])
def test_without_opt_outs_nothing_is_opted_out(origin: DeliveryOrigin) -> None:
    assert Routing.from_config(make_config()).opted_out(origin, "freezer") is False

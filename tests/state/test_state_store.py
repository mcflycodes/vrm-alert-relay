"""SQLite state store: schema, locking, paths, corruption, clocks, pruning, failures.

Every identifier here is fictitious.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import stat
from contextlib import closing
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

import pytest

from vrm_alert_relay.engine import Direction, LevelSpec, RuleSpec, RuleState, Sample, evaluate
from vrm_alert_relay.state import (
    DB_FILENAME,
    JOURNAL_FILENAME,
    LOCK_FILENAME,
    SCHEMA_VERSION,
    AttemptMark,
    Changes,
    DeliveryKind,
    DeliveryRecord,
    DeliveryStatus,
    JournalEntry,
    SchemaTooNewError,
    Snapshot,
    StateLockedError,
    StateStore,
    SuppressionState,
    migrate,
)
from vrm_alert_relay.state import store as store_module
from vrm_alert_relay.state.schema import MIGRATIONS, schema_version

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

BASE = datetime(2035, 1, 1, tzinfo=UTC)
RULE = RuleSpec("freezer", Direction.RISING, (LevelSpec("warning", -12.0),))


def record(
    n: int, status: DeliveryStatus = DeliveryStatus.DELIVERED, **changes: Any
) -> DeliveryRecord:
    fields: dict[str, Any] = {
        "event_id": f"evt_{n:04d}",
        "recipient": "owner_sms",
        "rule_id": "freezer",
        "kind": DeliveryKind.EVENT,
        "status": status,
        "text": "Freezer warming",
        "attempts": 1,
        "created_at": BASE,
        "updated_at": BASE,
    }
    fields.update(changes)
    return DeliveryRecord(**fields)


def raw(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path / DB_FILENAME, autocommit=True)


def query(path: Path, sql: str) -> list[tuple[Any, ...]]:
    with closing(raw(path)) as connection:
        return connection.execute(sql).fetchall()


@pytest.fixture
def opened(tmp_path: Path) -> Iterator[StateStore]:
    store = StateStore(tmp_path)
    store.load(BASE)
    yield store
    store.close()


def reopen(path: Path, now: datetime = BASE, **kwargs: Any) -> tuple[StateStore, Any]:
    store = StateStore(path, **kwargs)
    return store, store.load(now)


# Schema and files ------------------------------------------------------------------


def test_fresh_directory_gets_the_current_schema_and_private_files(tmp_path: Path) -> None:
    store, snapshot = reopen(tmp_path)
    assert store.path == tmp_path / DB_FILENAME
    assert store.healthy
    assert store.error is None
    assert snapshot.deliveries == ()
    assert snapshot.suppression == SuppressionState()
    assert store.flush(Changes(), BASE)
    for name in (DB_FILENAME, LOCK_FILENAME, f"{DB_FILENAME}-wal", f"{DB_FILENAME}-shm"):
        assert stat.S_IMODE((tmp_path / name).stat().st_mode) == 0o600, name
    store.close()
    store.close()
    with closing(raw(tmp_path)) as connection:
        assert schema_version(connection) == SCHEMA_VERSION
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_existing_permissive_files_are_tightened(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path)
    store.close()
    (tmp_path / f"{DB_FILENAME}-wal").write_bytes(b"")
    for name in (DB_FILENAME, f"{DB_FILENAME}-wal", LOCK_FILENAME):
        (tmp_path / name).chmod(0o644)
    store, _ = reopen(tmp_path)
    for name in (DB_FILENAME, f"{DB_FILENAME}-wal", LOCK_FILENAME):
        assert stat.S_IMODE((tmp_path / name).stat().st_mode) == 0o600, name
    store.close()


def test_migrate_runs_forward_and_rereads_the_version(tmp_path: Path) -> None:
    extended = (*MIGRATIONS, ("CREATE TABLE future_extra (x INTEGER) STRICT",))
    with closing(raw(tmp_path)) as connection:
        assert migrate(connection) == 1
        assert migrate(connection, extended) == 2
        assert migrate(connection, extended) == 2
        assert schema_version(connection) == 2


def test_failed_migration_rolls_back(tmp_path: Path) -> None:
    broken = (("CREATE TABLE half (x INTEGER)", "NOT VALID SQL"),)
    with closing(raw(tmp_path)) as connection:
        with pytest.raises(sqlite3.OperationalError):
            migrate(connection, broken)
        assert schema_version(connection) == 0
        assert connection.execute("SELECT count(*) FROM sqlite_master").fetchone() == (0,)


def test_newer_schema_is_left_untouched_and_reported(tmp_path: Path) -> None:
    with closing(raw(tmp_path)) as connection:
        connection.execute("PRAGMA user_version = 99")
    store, snapshot = reopen(tmp_path)
    assert snapshot.deliveries == ()
    assert not store.healthy
    assert store.error is not None
    assert store.error.startswith("SchemaTooNewError")
    assert not store.flush(Changes(), BASE)
    store.close()
    with closing(raw(tmp_path)) as connection:
        assert schema_version(connection) == 99
        with pytest.raises(SchemaTooNewError):
            migrate(connection)


# Lock and paths --------------------------------------------------------------------


def test_second_store_on_the_same_directory_is_refused(opened: StateStore, tmp_path: Path) -> None:
    with pytest.raises(StateLockedError):
        StateStore(tmp_path).load(BASE)
    other = StateStore(tmp_path)
    assert not other.journal((JournalEntry(record(1), attempt=True),), BASE)
    assert other.error == "StateLockedError: another relay process is using the state directory"
    opened.close()
    store, _ = reopen(tmp_path)
    store.close()


def _refused(store: StateStore, snapshot: Snapshot, reason: str) -> None:
    """An unsafe path makes storage unavailable; the relay is not stopped (ADR 0002)."""
    assert not snapshot.complete
    assert not store.healthy
    assert store.error is not None
    assert reason in store.error
    assert not store.flush(Changes(deliveries=(record(1),)), BASE)
    store.close()


def test_symlinked_state_directory_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    store = StateStore(tmp_path / "link")
    _refused(store, store.load(BASE), "symlink")
    assert list(real.iterdir()) == []


def test_state_directory_that_is_a_file_is_refused(tmp_path: Path) -> None:
    (tmp_path / "file").write_text("")
    store = StateStore(tmp_path / "file")
    _refused(store, store.load(BASE), "ot a directory")


@pytest.mark.parametrize(
    "name",
    [DB_FILENAME, f"{DB_FILENAME}-wal", f"{DB_FILENAME}-shm", LOCK_FILENAME, JOURNAL_FILENAME],
)
def test_symlinked_state_files_are_refused(tmp_path: Path, name: str) -> None:
    target = tmp_path / "elsewhere"
    target.write_text("")
    (tmp_path / name).symlink_to(target)
    store = StateStore(tmp_path)
    snapshot = store.load(BASE)
    assert target.read_text() == ""
    if name == JOURNAL_FILENAME:
        # The database still works; the history is incomplete until the journal is readable.
        assert not snapshot.complete
        assert store.error is not None
        assert "symlink" in store.error
        store.close()
        return
    _refused(store, snapshot, "symlink")


def test_non_regular_database_is_refused(tmp_path: Path) -> None:
    os.mkfifo(tmp_path / DB_FILENAME)
    store = StateStore(tmp_path)
    _refused(store, store.load(BASE), "not a regular file")
    assert stat.S_ISFIFO((tmp_path / DB_FILENAME).lstat().st_mode)


def test_unsafe_path_at_runtime_is_a_storage_failure(opened: StateStore, tmp_path: Path) -> None:
    opened.close()
    store, _ = reopen(tmp_path)
    (tmp_path / f"{DB_FILENAME}-wal").unlink(missing_ok=True)
    store.close()
    store = StateStore(tmp_path)
    store.load(BASE)
    store._connection.close()  # type: ignore[union-attr]
    store._connection = None
    (tmp_path / f"{DB_FILENAME}-wal").symlink_to(tmp_path / "elsewhere")
    assert not store.flush(Changes(), BASE)
    assert store.error == "UnsafeStateError: state file relay-state.sqlite3-wal is a symlink"
    store.close()


def test_group_writable_state_directory_draws_a_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    state.chmod(0o770)
    with caplog.at_level(logging.WARNING, logger="vrm_alert_relay.state"):
        store, _ = reopen(state)
    assert "state.directory_permissive" in [r.__dict__.get("event") for r in caplog.records]
    store.close()


# Round trip ---------------------------------------------------------------------------


def test_everything_round_trips_across_a_reopen(tmp_path: Path) -> None:
    state, _ = evaluate(RULE, RuleState(), Sample(-3.0, BASE), BASE)
    records = (
        record(1),
        record(
            2,
            DeliveryStatus.AMBIGUOUS,
            kind=DeliveryKind.SUMMARY,
            rule_id=None,
            next_attempt_at=BASE + timedelta(minutes=1),
            last_attempt_at=BASE,
            provider_message_id="provider-id-9",
            covers=4,
        ),
    )
    attempts = (
        AttemptMark("evt_0001", "owner_sms", 1, BASE),
        AttemptMark("evt_0003", "audit", 1, BASE + timedelta(seconds=1), live=False),
    )
    suppression = SuppressionState(
        count=3,
        since=BASE,
        last_summary_at=BASE - timedelta(hours=2),
        summary_event_id="sum_1",
        summary_count=2,
    )
    store, _ = reopen(tmp_path)
    changes = Changes(
        rule_states=MappingProxyType({"freezer": state}),
        deliveries=records,
        attempts=attempts,
        suppression=suppression,
    )
    assert store.flush(changes, BASE)
    store.close()
    store, snapshot = reopen(tmp_path, BASE + timedelta(minutes=1))
    assert snapshot.rule_states == {"freezer": state}
    assert snapshot.deliveries == records
    assert snapshot.attempts == attempts[:1]  # dry-run sends are never stored
    assert snapshot.suppression == suppression
    assert snapshot.last_seen == BASE
    assert snapshot.clock_moved_backwards is False
    store.close()


# Corruption -----------------------------------------------------------------------------


def _insert_delivery(connection: sqlite3.Connection, **values: Any) -> None:
    row = {
        "event_id": "evt_x",
        "recipient": "owner_sms",
        "rule_id": None,
        "kind": "event",
        "status": "pending",
        "text": "Freezer warming",
        "attempts": 0,
        "created_at": BASE.isoformat(),
        "updated_at": BASE.isoformat(),
        "next_attempt_at": None,
        "last_attempt_at": None,
        "provider_message_id": None,
    }
    row.update(values)
    columns = ", ".join(row)
    marks = ", ".join("?" for _ in row)
    connection.execute(f"INSERT INTO delivery ({columns}) VALUES ({marks})", tuple(row.values()))  # noqa: S608  # test-only constant columns


def test_corrupt_rule_states_are_logged_and_start_fresh(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    state, _ = evaluate(RULE, RuleState(), Sample(-3.0, BASE), BASE)
    store, _ = reopen(tmp_path)
    assert store.flush(Changes(rule_states=MappingProxyType({"freezer": state})), BASE)
    store.close()
    with closing(raw(tmp_path)) as connection:
        connection.executemany(
            "INSERT INTO rule_state (rule_id, state, updated_at) VALUES (?, ?, ?)",
            [
                ("bad", "not json", "x"),
                ("deep", "[" * 5000, "x"),
                ("wrong-shape", '{"version": 3}', "x"),
                ("bad id!", '{"version": 3}', "x"),
                ("huge", "x" * (64 * 1024 + 1), "x"),
            ],
        )
    with caplog.at_level(logging.WARNING, logger="vrm_alert_relay.state"):
        store, snapshot = reopen(tmp_path)
    assert set(snapshot.rule_states) == {"freezer"}
    assert snapshot.problems == 5
    assert not store.healthy
    assert store.error == "corrupt state: 5 unreadable rows or journal lines"
    ids = [r.__dict__["rule_id"] for r in caplog.records if "rule_id" in r.__dict__]
    assert None in ids
    # A later successful write does not hide that corruption was found.
    assert store.flush(Changes(), BASE)
    assert not store.healthy
    store.close()


def test_corrupt_deliveries_are_recovered_or_accounted(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path)
    state, _ = evaluate(RULE, RuleState(), Sample(-3.0, BASE), BASE)
    assert store.flush(
        Changes(
            rule_states=MappingProxyType({"freezer": state, "battery": state}),
            suppression=SuppressionState(count=2, since=BASE),
        ),
        BASE,
    )
    store.close()
    with closing(raw(tmp_path)) as connection:
        # Readable identity, unfinished: recovered as ambiguous, defaults filled in.
        _insert_delivery(
            connection,
            event_id="evt_a",
            status="exploded",
            kind="nonsense",
            text="x" * 1500,
            attempts=-4,
            created_at="garbage",
            last_attempt_at="2035-01-01T00:00:00",
            provider_message_id="id\x1b",
            rule_id="bad id",
        )
        _insert_delivery(connection, event_id="evt_b", rule_id="freezer", attempts=500)
        # Readable identity, finished: kept as finished.
        _insert_delivery(
            connection, event_id="evt_c", status="delivered", attempts=1, updated_at="x"
        )
        # Unreadable identity, finished: dropped.
        _insert_delivery(connection, event_id="bad id 1", status="failed")
        # Unreadable identity, readable rule: the rule starts fresh.
        _insert_delivery(connection, event_id="bad id 2", rule_id="battery")
        # Nothing readable: counted as held back.
        _insert_delivery(connection, event_id="bad id 3")
    store, snapshot = reopen(tmp_path, BASE + timedelta(minutes=5))
    later = BASE + timedelta(minutes=5)
    by_id = {r.event_id: r for r in snapshot.deliveries}
    assert set(by_id) == {"evt_a", "evt_b", "evt_c"}
    a = by_id["evt_a"]
    assert (a.status, a.kind, a.attempts, a.created_at) == (
        DeliveryStatus.AMBIGUOUS,
        DeliveryKind.EVENT,
        1,
        later,
    )
    assert (len(a.text), a.provider_message_id, a.rule_id, a.last_attempt_at) == (
        1000,
        None,
        None,
        None,
    )
    assert by_id["evt_b"].attempts == 100
    assert by_id["evt_c"].status is DeliveryStatus.DELIVERED
    assert set(snapshot.rule_states) == {"freezer"}
    assert snapshot.suppression.count == 3
    assert snapshot.problems == 6
    store.close()
    # The repairs were written back, so a second load is clean.
    store, snapshot = reopen(tmp_path, later)
    assert snapshot.problems == 0
    assert snapshot.suppression.count == 3
    assert query(tmp_path, "SELECT rule_id FROM rule_state") == [("freezer",)]
    store.close()


def test_unreadable_text_is_replaced_by_a_notice(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path)
    store.close()
    with closing(raw(tmp_path)) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            "CREATE TABLE tmp AS SELECT * FROM delivery"
        )  # schema copy without STRICT to allow a NULL text
        connection.execute("DROP TABLE delivery")
        connection.execute(
            "CREATE TABLE delivery (event_id TEXT, recipient TEXT, rule_id TEXT, kind TEXT, "
            "status TEXT, text TEXT, attempts INTEGER, created_at TEXT, updated_at TEXT, "
            "next_attempt_at TEXT, last_attempt_at TEXT, provider_message_id TEXT, "
            "covers INTEGER, PRIMARY KEY (event_id, recipient))"
        )
        _insert_delivery(connection, event_id="evt_t", text=None, attempts=True)
    store, snapshot = reopen(tmp_path)
    assert snapshot.deliveries[0].text == store_module.UNREADABLE_TEXT
    assert snapshot.deliveries[0].attempts == 1
    store.close()


def test_corrupt_attempts_and_meta_fail_closed(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path)
    assert store.flush(Changes(attempts=(AttemptMark("evt_1", "owner_sms", 1, BASE),)), BASE)
    store.close()
    with closing(raw(tmp_path)) as connection:
        connection.executemany(
            "INSERT INTO send_attempt (event_id, recipient, attempt, at) VALUES (?, ?, ?, ?)",
            [
                ("evt_2", "owner_sms", 1, "garbage"),
                ("evt_3", "owner_sms", 1, "x" * 10_000),
                ("bad id", "owner_sms", 1, BASE.isoformat()),
            ],
        )
        connection.executemany(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            [
                ("suppressed_count", "lots"),
                ("summary_count", "-1"),
                ("suppressed_since", "yesterday"),
                ("summary_event_id", "bad id"),
                ("last_seen", "x"),
            ],
        )
    later = BASE + timedelta(minutes=10)
    store, snapshot = reopen(tmp_path, later)
    assert snapshot.problems == 8
    assert len(snapshot.attempts) == 4
    assert sum(1 for mark in snapshot.attempts if mark.at == later) == 3
    assert snapshot.suppression == SuppressionState(count=1)
    assert snapshot.last_seen is None
    store.close()
    # Unreadable attempts were replaced by readable ones that age out normally.
    store, snapshot = reopen(tmp_path, later)
    assert snapshot.problems == 1  # the repair rewrote all but last_seen, which a flush sets
    assert len(snapshot.attempts) == 4
    store.close()


# Clock discontinuities and pruning ----------------------------------------------------


def test_attempts_from_the_future_count_as_now(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path)
    ahead = BASE + timedelta(days=2)
    assert store.flush(Changes(attempts=(AttemptMark("evt_1", "owner_sms", 1, ahead),)), ahead)
    store.close()
    store, snapshot = reopen(tmp_path)
    assert snapshot.clock_moved_backwards is True
    assert snapshot.attempts == (AttemptMark("evt_1", "owner_sms", 1, BASE),)
    store.close()


def test_old_attempts_are_pruned_only_when_the_clock_has_not_moved_back(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path)
    marks = (AttemptMark("evt_old", "owner_sms", 1, BASE), AttemptMark("evt_new", "x", 1, BASE))
    assert store.flush(Changes(attempts=marks[:1]), BASE + timedelta(days=3))
    store.close()
    store, snapshot = reopen(tmp_path, BASE + timedelta(days=2))  # backwards
    assert snapshot.attempts == marks[:1]
    store.close()
    assert len(query(tmp_path, "SELECT id FROM send_attempt")) == 1
    store, snapshot = reopen(tmp_path, BASE + timedelta(days=4))  # forward again
    assert snapshot.attempts == ()
    store.close()
    assert query(tmp_path, "SELECT id FROM send_attempt") == []


def test_expired_attempts_are_deleted_by_key(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path)
    marks = tuple(AttemptMark(f"evt_{n}", "owner_sms", 1, BASE) for n in range(3))
    assert store.flush(Changes(attempts=marks), BASE)
    assert store.flush(Changes(expired_attempts=(marks[0].key, marks[2].key)), BASE)
    assert query(tmp_path, "SELECT event_id FROM send_attempt") == [("evt_1",)]
    store.close()


def test_pruning_bounds_records_attempts_and_rule_states(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module, "MAX_ATTEMPT_ROWS", 5)
    monkeypatch.setattr(store_module, "MAX_RULE_STATES", 3)
    store, _ = reopen(tmp_path, retention=timedelta(days=2), max_records=4)
    now = BASE + timedelta(days=3)
    old = [record(n, updated_at=BASE) for n in range(3)]
    old_pending = [record(n, DeliveryStatus.PENDING, updated_at=BASE) for n in range(3, 5)]
    recent = [
        record(n, DeliveryStatus.FAILED, updated_at=now - timedelta(minutes=n))
        for n in range(5, 12)
    ]
    attempts = tuple(AttemptMark(f"evt_{n}", "owner_sms", 1, now) for n in range(10))
    states = {f"rule-{n}": RuleState() for n in range(5)}
    assert store.flush(
        Changes(
            rule_states=MappingProxyType(states),
            deliveries=(*old, *old_pending, *recent),
            attempts=attempts,
        ),
        now,
    )
    remaining = {row[0] for row in query(tmp_path, "SELECT event_id FROM delivery")}
    assert remaining == {"evt_0003", "evt_0004", "evt_0005", "evt_0006", "evt_0007", "evt_0008"}
    assert len(query(tmp_path, "SELECT id FROM send_attempt")) == 5
    assert len(query(tmp_path, "SELECT rule_id FROM rule_state")) == 3
    store.close()


def test_retention_uses_the_latest_time_seen(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path, retention=timedelta(days=2))
    assert store.flush(Changes(), BASE + timedelta(days=10))  # last seen far ahead
    assert store.flush(Changes(deliveries=(record(1, updated_at=BASE),)), BASE)
    assert query(tmp_path, "SELECT event_id FROM delivery") == []
    store.close()


def test_store_arguments_are_validated(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="retention"):
        StateStore(tmp_path, retention=timedelta(0))
    with pytest.raises(ValueError, match="max_records"):
        StateStore(tmp_path, max_records=0)


# Journal ---------------------------------------------------------------------------------


def test_journal_is_replayed_at_load_and_merged_by_the_next_flush(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path)
    assert store.flush(Changes(deliveries=(record(1, DeliveryStatus.PENDING, attempts=0),)), BASE)
    in_flight = record(1, DeliveryStatus.IN_FLIGHT, attempts=1, last_attempt_at=BASE)
    delivered = record(1, DeliveryStatus.DELIVERED, attempts=1, last_attempt_at=BASE)
    other = record(2, DeliveryStatus.IN_FLIGHT, attempts=1, last_attempt_at=BASE)
    assert store.journal(
        (JournalEntry(in_flight, attempt=True), JournalEntry(other, attempt=True)), BASE
    )
    assert store.journal((JournalEntry(delivered, attempt=False),), BASE)
    store.close()
    with (tmp_path / JOURNAL_FILENAME).open("ab") as handle:
        handle.write(b'{"v": 1, "torn')

    store, snapshot = reopen(tmp_path)
    assert {r.event_id: r.status for r in snapshot.deliveries} == {
        "evt_0001": DeliveryStatus.DELIVERED,
        "evt_0002": DeliveryStatus.IN_FLIGHT,
    }
    assert {mark.key for mark in snapshot.attempts} == {
        ("evt_0001", "owner_sms", 1),
        ("evt_0002", "owner_sms", 1),
    }
    # An older journal version does not overwrite a newer row.
    with closing(raw(tmp_path)) as connection:
        connection.execute("UPDATE delivery SET status = 'failed', attempts = 3")
    assert store.flush(Changes(), BASE)
    assert not (tmp_path / JOURNAL_FILENAME).exists()
    rows = query(tmp_path, "SELECT event_id, status, attempts FROM delivery ORDER BY event_id")
    assert rows == [("evt_0001", "failed", 3), ("evt_0002", "in_flight", 1)]
    assert len(query(tmp_path, "SELECT id FROM send_attempt")) == 2
    store.close()


def test_an_older_journal_version_does_not_replace_a_newer_row(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path)
    in_flight = record(1, DeliveryStatus.IN_FLIGHT, attempts=1, last_attempt_at=BASE)
    assert store.journal((JournalEntry(in_flight, attempt=True),), BASE)
    with closing(raw(tmp_path)) as connection:
        _insert_delivery(connection, event_id="evt_0001", status="delivered", attempts=1)
    store.close()
    store, snapshot = reopen(tmp_path)
    assert [r.status for r in snapshot.deliveries] == [DeliveryStatus.DELIVERED]
    store.close()


def test_corrupt_journal_lines_occupy_slots(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path)
    store.close()
    (tmp_path / JOURNAL_FILENAME).write_bytes(b"garbage\n" + json.dumps({"v": 2}).encode() + b"\n")
    store, snapshot = reopen(tmp_path)
    assert snapshot.problems == 2
    assert len(snapshot.attempts) == 2
    assert all(mark.at == BASE for mark in snapshot.attempts)
    assert store.flush(Changes(), BASE)
    assert len(query(tmp_path, "SELECT id FROM send_attempt")) == 2
    store.close()


def test_a_corrupt_row_is_replaced_by_the_journal_version(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path)
    in_flight = record(1, DeliveryStatus.IN_FLIGHT, attempts=1, last_attempt_at=BASE)
    assert store.journal((JournalEntry(in_flight, attempt=True),), BASE)
    with closing(raw(tmp_path)) as connection:
        _insert_delivery(connection, event_id="evt_0001", created_at="garbage")
    assert store.flush(Changes(), BASE)
    assert query(tmp_path, "SELECT status FROM delivery") == [("in_flight",)]
    store.close()


def test_an_unreadable_journal_fails_the_flush_and_is_kept(
    opened: StateStore, tmp_path: Path
) -> None:
    assert opened.journal((JournalEntry(record(1), attempt=True),), BASE)
    (tmp_path / JOURNAL_FILENAME).chmod(0o000)
    try:
        assert not opened.flush(Changes(), BASE)
    finally:
        (tmp_path / JOURNAL_FILENAME).chmod(0o600)
    assert (tmp_path / JOURNAL_FILENAME).exists()
    assert opened.flush(Changes(), BASE)


def test_an_unreadable_journal_at_load_is_reported(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path)
    assert store.journal((JournalEntry(record(1), attempt=True),), BASE)
    store.close()
    (tmp_path / JOURNAL_FILENAME).chmod(0o000)
    try:
        store, snapshot = reopen(tmp_path)
        assert snapshot.deliveries == ()
        assert not snapshot.complete
        assert not store.readable
        assert store.error == "PermissionError: Permission denied"
        assert store.reload(BASE) is None
    finally:
        (tmp_path / JOURNAL_FILENAME).chmod(0o600)
    reloaded = store.reload(BASE)
    assert reloaded is not None
    assert reloaded.complete
    assert [r.event_id for r in reloaded.deliveries] == ["evt_0001"]
    assert store.readable
    store.close()


def test_journal_clear_failure_keeps_the_store_unhealthy(
    opened: StateStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert opened.journal((JournalEntry(record(1), attempt=True),), BASE)

    def refuse() -> None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(opened._journal, "clear", refuse)
    assert opened.flush(Changes(), BASE)
    assert not opened.healthy
    monkeypatch.undo()
    assert opened.flush(Changes(), BASE)
    assert opened.healthy


# Failures ---------------------------------------------------------------------------------


class Failing:
    """A connection whose statements fail on demand."""

    def __init__(self, inner: sqlite3.Connection, plan: dict[str, Any]) -> None:
        self.inner = inner
        self.plan = plan

    def _check(self, sql: str) -> None:
        if self.plan["fail"] and self.plan["match"] in sql:
            raise sqlite3.OperationalError(self.plan["error"])

    def execute(self, sql: str, params: Any = ()) -> sqlite3.Cursor:
        self._check(sql)
        return self.inner.execute(sql, params)

    def executemany(self, sql: str, params: Any) -> sqlite3.Cursor:
        self._check(sql)
        return self.inner.executemany(sql, params)

    def close(self) -> None:
        self.inner.close()
        if self.plan.get("close_fails"):
            raise sqlite3.ProgrammingError("close failed")


def failing_store(tmp_path: Path, plan: dict[str, Any]) -> StateStore:
    def connect(path: Path) -> Any:
        return Failing(sqlite3.connect(path, autocommit=True), plan)

    return StateStore(tmp_path, connect=connect)


def test_failed_flush_rolls_back_and_recovers(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    plan = {"fail": False, "match": "INSERT OR IGNORE INTO send_attempt", "error": "locked"}
    store = failing_store(tmp_path, plan)
    store.load(BASE)
    plan["fail"] = True
    mark = AttemptMark("evt_1", "owner_sms", 1, BASE)
    with caplog.at_level(logging.WARNING, logger="vrm_alert_relay.state"):
        assert not store.flush(Changes(deliveries=(record(1),), attempts=(mark,)), BASE)
        assert store.error == "OperationalError: locked"
        assert query(tmp_path, "SELECT * FROM delivery") == []
        plan["fail"] = False
        assert store.flush(Changes(deliveries=(record(1),), attempts=(mark,)), BASE)
    assert store.healthy
    logged = [r.__dict__.get("event") for r in caplog.records]
    assert logged == ["state.persistence_failed", "state.persistence_recovered"]
    store.close()


def test_rollback_and_close_failures_are_contained(tmp_path: Path) -> None:
    plan = {"fail": False, "match": "", "error": "disk I/O error", "close_fails": True}
    store = failing_store(tmp_path, plan)
    store.load(BASE)
    plan["fail"] = True
    assert not store.flush(Changes(), BASE)
    assert store.error == "OperationalError: disk I/O error"
    store.close()


def test_failed_load_reads_what_it_can_and_writes_nothing(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path)
    assert store.flush(Changes(deliveries=(record(1),), suppression=SuppressionState(2)), BASE)
    store.close()
    plan = {"fail": True, "match": "FROM meta", "error": "disk I/O error"}
    store = failing_store(tmp_path, plan)
    snapshot = store.load(BASE)
    assert [r.event_id for r in snapshot.deliveries] == ["evt_0001"]  # H5: other tables read
    assert not snapshot.complete
    assert not snapshot.suppression_read
    assert not store.healthy
    assert not store.flush(Changes(deliveries=(record(2),)), BASE)  # untouched until re-read
    assert store.reload(BASE) is None
    plan["fail"] = False
    reloaded = store.reload(BASE)
    assert reloaded is not None
    assert reloaded.complete
    assert reloaded.suppression.count == 2
    assert store.flush(Changes(deliveries=(record(2),)), BASE)
    assert store.healthy
    store.close()


def test_failed_repair_still_returns_what_was_read(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path)
    store.close()
    with closing(raw(tmp_path)) as connection:
        _insert_delivery(connection, event_id="evt_r", created_at="garbage")
    plan = {"fail": True, "match": "DELETE FROM delivery WHERE rowid", "error": "read-only"}
    store = failing_store(tmp_path, plan)
    snapshot = store.load(BASE)
    assert [r.event_id for r in snapshot.deliveries] == ["evt_r"]
    assert store.error == "OperationalError: read-only"
    store.close()


def test_not_a_database_is_moved_aside_and_state_starts_afresh(tmp_path: Path) -> None:
    garbage = b"this is not an SQLite file" * 100
    (tmp_path / DB_FILENAME).write_bytes(garbage)
    (tmp_path / DB_FILENAME).chmod(0o644)
    store, snapshot = reopen(tmp_path)
    assert snapshot.reset
    assert snapshot.complete
    assert not store.healthy
    assert store.flush(Changes(deliveries=(record(1),)), BASE)
    assert not store.healthy  # for the rest of the run
    assert store.error == "corrupt database moved aside; state started afresh"
    [moved] = tmp_path.glob(f"{DB_FILENAME}.corrupt-*")
    assert moved.name == f"{DB_FILENAME}.corrupt-20350101T000000000000Z"
    assert moved.read_bytes() == garbage
    assert stat.S_IMODE(moved.stat().st_mode) == 0o600
    store.close()
    store, snapshot = reopen(tmp_path)
    assert [r.event_id for r in snapshot.deliveries] == ["evt_0001"]
    assert store.healthy
    store.close()


def test_missing_directory_error_omits_the_path(tmp_path: Path) -> None:
    store, snapshot = reopen(tmp_path / "missing")
    assert not snapshot.complete
    assert store.error == "FileNotFoundError: No such file or directory"
    assert not store.journal((JournalEntry(record(1), attempt=True),), BASE)


def test_read_only_volume_is_a_storage_failure_not_a_crash(tmp_path: Path) -> None:
    store, _ = reopen(tmp_path)
    assert store.flush(Changes(deliveries=(record(1),)), BASE)
    store.close()
    for path in tmp_path.iterdir():
        path.chmod(0o400)
    tmp_path.chmod(0o500)
    try:
        store, _ = reopen(tmp_path)
        assert not store.healthy
        assert not store.flush(Changes(deliveries=(record(2),)), BASE)
        assert not store.journal((JournalEntry(record(2), attempt=True),), BASE)
        with pytest.raises(StateLockedError):
            StateStore(tmp_path).load(BASE)  # the read-only lock file still locks
        store.close()
    finally:
        tmp_path.chmod(0o700)


def test_oserror_without_reason_is_described(tmp_path: Path) -> None:
    def connect(path: Path) -> sqlite3.Connection:
        raise OSError

    store = StateStore(tmp_path, connect=connect)
    store.load(BASE)
    assert store.error == "OSError: operating system error"
    store.close()


def test_other_open_errors_are_storage_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = store_module.open_private

    refused: list[str] = []

    def refuse(path: Path, flags: int) -> int:
        if path.name in refused:
            raise OSError(28, "No space left on device")
        return original(path, flags)

    monkeypatch.setattr(store_module, "open_private", refuse)
    for name in (LOCK_FILENAME, DB_FILENAME):
        refused[:] = [name]
        store, _ = reopen(tmp_path)
        assert store.error == "OSError: No space left on device"
        store.close()

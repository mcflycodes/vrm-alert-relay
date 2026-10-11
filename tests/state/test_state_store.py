"""SQLite state store: schema, round trips, corruption, pruning, and failures.

Every identifier here is fictitious.
"""

from __future__ import annotations

import logging
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
    SCHEMA_VERSION,
    Changes,
    DeliveryKind,
    DeliveryRecord,
    DeliveryStatus,
    SchemaTooNewError,
    StateStore,
    Suppression,
    migrate,
)
from vrm_alert_relay.state import store as store_module
from vrm_alert_relay.state.schema import MIGRATIONS, schema_version

if TYPE_CHECKING:
    from pathlib import Path

BASE = datetime(2035, 1, 1, tzinfo=UTC)
RULE = RuleSpec("freezer", Direction.RISING, (LevelSpec("warning", -12.0),))


def record(
    n: int, status: DeliveryStatus = DeliveryStatus.DELIVERED, **changes: Any
) -> DeliveryRecord:
    fields: dict[str, Any] = {
        "event_id": f"evt_{n:04d}",
        "recipient": "owner_sms",
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


def count(path: Path, table: str) -> int:
    with closing(raw(path)) as connection:
        return int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])  # noqa: S608  # test-only constant table names


# Schema -------------------------------------------------------------------------


def test_fresh_directory_gets_the_current_schema(tmp_path: Path) -> None:
    store = StateStore(tmp_path)
    assert store.path == tmp_path / DB_FILENAME
    snapshot = store.load()
    assert store.healthy
    assert store.error is None
    assert snapshot.rule_states == {}
    assert snapshot.deliveries == ()
    assert snapshot.attempts == ()
    assert snapshot.suppression == Suppression()
    store.close()
    store.close()
    assert stat.S_IMODE((tmp_path / DB_FILENAME).stat().st_mode) == 0o600
    with closing(raw(tmp_path)) as connection:
        assert schema_version(connection) == SCHEMA_VERSION
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master")}
    assert {"rule_state", "delivery", "send_attempt", "suppressed", "meta"} <= tables


def test_migrate_runs_forward_from_an_older_version(tmp_path: Path) -> None:
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
        assert connection.execute("SELECT count(*) FROM sqlite_master").fetchone()[0] == 0


def test_newer_schema_is_left_untouched_and_reported(tmp_path: Path) -> None:
    with closing(raw(tmp_path)) as connection:
        connection.execute("PRAGMA user_version = 99")
    store = StateStore(tmp_path)
    assert store.load().deliveries == ()
    assert not store.healthy
    assert store.error is not None
    assert store.error.startswith("SchemaTooNewError")
    assert not store.flush(Changes(), BASE)
    with closing(raw(tmp_path)) as connection:
        assert schema_version(connection) == 99
    with closing(raw(tmp_path)) as connection, pytest.raises(SchemaTooNewError):
        migrate(connection)


# Round trip ---------------------------------------------------------------------------


def test_everything_round_trips_across_a_reopen(tmp_path: Path) -> None:
    state, _ = evaluate(RULE, RuleState(), Sample(-3.0, BASE), BASE)
    records = (
        record(1),
        record(
            2,
            DeliveryStatus.AMBIGUOUS,
            kind=DeliveryKind.SUMMARY,
            next_attempt_at=BASE + timedelta(minutes=1),
            last_attempt_at=BASE,
            provider_message_id="provider-id-9",
        ),
    )
    attempts = (BASE, BASE + timedelta(seconds=1))
    suppression = Suppression(
        counts=MappingProxyType({"owner_sms": 3, "partner_sms": 0}),
        since=BASE,
        last_summary_at=BASE - timedelta(hours=2),
    )
    store = StateStore(tmp_path)
    assert store.flush(
        Changes(
            rule_states=MappingProxyType({"freezer": state}),
            deliveries=records,
            attempts=attempts,
            suppression=suppression,
        ),
        BASE,
    )
    store.close()
    snapshot = StateStore(tmp_path).load()
    assert snapshot.rule_states == {"freezer": state}
    assert snapshot.deliveries == records
    assert snapshot.attempts == attempts
    assert snapshot.suppression == Suppression(
        counts=MappingProxyType({"owner_sms": 3}),
        since=BASE,
        last_summary_at=BASE - timedelta(hours=2),
    )


def test_upserts_replace_rows_and_clear_suppression(tmp_path: Path) -> None:
    store = StateStore(tmp_path)
    suppression = Suppression(counts=MappingProxyType({"owner_sms": 3}), since=BASE)
    assert store.flush(
        Changes(deliveries=(record(1, DeliveryStatus.PENDING),), suppression=suppression), BASE
    )
    assert store.flush(Changes(deliveries=(record(1),)), BASE)
    snapshot = store.load()
    assert [r.status for r in snapshot.deliveries] == [DeliveryStatus.DELIVERED]
    assert snapshot.suppression == Suppression()


# Corruption -----------------------------------------------------------------------------


def test_corrupt_rows_are_logged_and_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    state, _ = evaluate(RULE, RuleState(), Sample(-3.0, BASE), BASE)
    store = StateStore(tmp_path)
    assert store.flush(
        Changes(
            rule_states=MappingProxyType({"freezer": state, "battery": state}),
            deliveries=(record(1),),
            attempts=(BASE,),
            suppression=Suppression(counts=MappingProxyType({"owner_sms": 2}), since=BASE),
        ),
        BASE,
    )
    store.close()
    stamp = BASE.isoformat()
    with closing(raw(tmp_path)) as connection:
        rows = [
            ("bad", "not json"),
            ("deep", "[" * 5000),
            ("wrong-shape", '{"version": 3}'),
            ("bad id!", '{"version": 3}'),
            ("huge", "x" * (64 * 1024 + 1)),
        ]
        connection.executemany(
            "INSERT INTO rule_state (rule_id, state, updated_at) VALUES (?, ?, ?)",
            [(rule_id, body, stamp) for rule_id, body in rows],
        )
        bad_deliveries = [
            ("evt_a", "owner_sms", "event", "exploded", "x", 1, stamp, stamp),
            ("evt_b", "owner_sms", "event", "delivered", "x", 1, "2035-01-01T00:00:00", stamp),
            ("evt_c", "owner_sms", "event", "delivered", "x", 1, "x" * 65, stamp),
            ("evt_d", "owner_sms", "event", "delivered", "x", 1, "yesterday", stamp),
            ("evt_e", "owner_sms", "event", "delivered", "x", -1, stamp, stamp),
            ("evt_f", "owner_sms", "nonsense", "delivered", "x", 1, stamp, stamp),
        ]
        connection.executemany(
            "INSERT INTO delivery (event_id, recipient, kind, status, text, attempts, "
            "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            bad_deliveries,
        )
        connection.executemany(
            "INSERT INTO send_attempt (at) VALUES (?)", [("garbage",), ("2035-01-01T00:00:01",)]
        )
        connection.executemany(
            "INSERT INTO suppressed (recipient, count) VALUES (?, ?)",
            [("bad id!", 4), ("partner_sms", -2), ("hook", 0)],
        )
        connection.execute("UPDATE meta SET value = 'not a time' WHERE key = 'suppressed_since'")
        connection.execute("INSERT INTO meta (key, value) VALUES ('last_summary_at', 'x')")
    with caplog.at_level(logging.WARNING, logger="vrm_alert_relay.state"):
        snapshot = StateStore(tmp_path).load()
    assert set(snapshot.rule_states) == {"freezer", "battery"}
    assert [r.event_id for r in snapshot.deliveries] == ["evt_0001"]
    assert snapshot.attempts == (BASE,)
    assert snapshot.suppression == Suppression(counts=MappingProxyType({"owner_sms": 2}))
    logged = [r.__dict__.get("event") for r in caplog.records]
    assert logged.count("state.rule_state_corrupt") == 5
    assert logged.count("state.delivery_corrupt") == 1
    assert logged.count("state.attempt_corrupt") == 2
    corrupt_ids = [
        r.__dict__["rule_id"]
        for r in caplog.records
        if r.__dict__.get("event") == "state.rule_state_corrupt"
    ]
    assert None in corrupt_ids


# Pruning -------------------------------------------------------------------------------


def test_pruning_bounds_records_attempts_and_rule_states(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module, "MAX_ATTEMPT_ROWS", 5)
    monkeypatch.setattr(store_module, "MAX_RULE_STATES", 3)
    store = StateStore(tmp_path, retention=timedelta(days=2), max_records=4)
    now = BASE + timedelta(days=3)
    old = [record(n, updated_at=BASE) for n in range(3)]
    old_pending = [record(n, DeliveryStatus.PENDING, updated_at=BASE) for n in range(3, 5)]
    recent = [
        record(n, DeliveryStatus.FAILED, updated_at=now - timedelta(minutes=n))
        for n in range(5, 12)
    ]
    attempts = (
        now - timedelta(days=1),
        *(now - timedelta(minutes=n) for n in range(10)),
    )
    states = {f"rule-{n}": RuleState() for n in range(5)}
    assert store.flush(
        Changes(
            rule_states=MappingProxyType(states),
            deliveries=(*old, *old_pending, *recent),
            attempts=attempts,
        ),
        now,
    )
    snapshot = store.load()
    remaining = {r.event_id for r in snapshot.deliveries}
    # Old finished records age out; pending ones stay; finished ones are capped by count.
    assert remaining == {"evt_0003", "evt_0004", "evt_0005", "evt_0006", "evt_0007", "evt_0008"}
    assert count(tmp_path, "send_attempt") == 5
    assert snapshot.attempts == tuple(sorted(now - timedelta(minutes=n) for n in range(5)))
    assert count(tmp_path, "rule_state") == 3


def test_store_arguments_are_validated(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="retention"):
        StateStore(tmp_path, retention=timedelta(0))
    with pytest.raises(ValueError, match="max_records"):
        StateStore(tmp_path, max_records=0)


# Failures ---------------------------------------------------------------------------------


class Failing:
    """A connection whose statements start failing after ``healthy`` statements."""

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
        if self.plan.get("close_fails"):
            self.inner.close()
            raise sqlite3.ProgrammingError("close failed")
        self.inner.close()


def failing_store(tmp_path: Path, plan: dict[str, Any]) -> StateStore:
    def connect(path: Path) -> Any:
        return Failing(sqlite3.connect(path, autocommit=True), plan)

    return StateStore(tmp_path, connect=connect)


def test_failed_flush_rolls_back_and_recovers(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    plan = {"fail": False, "match": "INSERT INTO send_attempt", "error": "database is locked"}
    store = failing_store(tmp_path, plan)
    store.load()
    plan["fail"] = True
    with caplog.at_level(logging.WARNING, logger="vrm_alert_relay.state"):
        assert not store.flush(Changes(deliveries=(record(1),), attempts=(BASE,)), BASE)
        assert not store.healthy
        assert store.error == "OperationalError: database is locked"
        assert count(tmp_path, "delivery") == 0  # the whole transaction rolled back
        plan["fail"] = False
        assert store.flush(Changes(deliveries=(record(1),), attempts=(BASE,)), BASE)
    assert store.healthy
    assert store.error is None
    assert count(tmp_path, "delivery") == 1
    logged = [r.__dict__.get("event") for r in caplog.records]
    assert logged == ["state.persistence_failed", "state.persistence_recovered"]


def test_rollback_and_close_failures_are_contained(tmp_path: Path) -> None:
    plan = {"fail": False, "match": "", "error": "disk I/O error", "close_fails": True}
    store = failing_store(tmp_path, plan)
    store.load()
    plan["fail"] = True  # every statement fails, including COMMIT and ROLLBACK
    assert not store.flush(Changes(), BASE)
    assert store.error == "OperationalError: disk I/O error"


def test_failed_load_returns_empty_state(tmp_path: Path) -> None:
    plan = {"fail": True, "match": "SELECT rule_id", "error": "database disk image is malformed"}
    store = failing_store(tmp_path, plan)
    snapshot = store.load()
    assert snapshot.rule_states == {}
    assert not store.healthy


def test_migration_failure_on_connect_closes_the_connection(tmp_path: Path) -> None:
    plan = {"fail": True, "match": "CREATE TABLE", "error": "attempt to write a readonly database"}
    store = failing_store(tmp_path, plan)
    store.load()
    assert store.error == "OperationalError: attempt to write a readonly database"


def test_not_a_database_is_reported_not_overwritten(tmp_path: Path) -> None:
    (tmp_path / DB_FILENAME).write_bytes(b"this is not an SQLite file" * 100)
    store = StateStore(tmp_path)
    assert store.load().deliveries == ()
    assert not store.flush(Changes(), BASE)
    assert store.error is not None
    assert store.error.startswith("DatabaseError")
    assert (tmp_path / DB_FILENAME).read_bytes().startswith(b"this is not an SQLite file")


def test_missing_directory_error_omits_the_path(tmp_path: Path) -> None:
    store = StateStore(tmp_path / "missing")
    store.load()
    assert store.error == "FileNotFoundError: No such file or directory"


def test_oserror_without_reason_is_described(tmp_path: Path) -> None:
    def connect(path: Path) -> sqlite3.Connection:
        raise OSError

    store = StateStore(tmp_path, connect=connect)
    store.load()
    assert store.error == "OSError: operating system error"

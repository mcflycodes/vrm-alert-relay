"""State store failure modes from the second review: each test names its finding.

Every identifier here is fictitious.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import UTC, datetime, timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

import pytest

from vrm_alert_relay.engine import RuleState
from vrm_alert_relay.state import (
    DB_FILENAME,
    LOCK_FILENAME,
    AttemptMark,
    Changes,
    DeliveryKind,
    DeliveryRecord,
    DeliveryStatus,
    JournalEntry,
    StateStore,
    SuppressionState,
    UnsafeStateError,
)
from vrm_alert_relay.state import store as store_module

if TYPE_CHECKING:
    from pathlib import Path

BASE = datetime(2035, 1, 1, tzinfo=UTC)


def record(n: int, status: DeliveryStatus = DeliveryStatus.PENDING) -> DeliveryRecord:
    return DeliveryRecord(
        event_id=f"evt_{n:04d}",
        recipient="owner_sms",
        rule_id="freezer",
        kind=DeliveryKind.EVENT,
        status=status,
        text="Freezer warming",
        attempts=0,
        created_at=BASE,
        updated_at=BASE,
        next_attempt_at=None if status.terminal else BASE,
    )


class Failing:
    """A real connection whose statements containing ``match`` fail."""

    def __init__(self, inner: sqlite3.Connection, match: str) -> None:
        self.inner = inner
        self.match = match

    def execute(self, sql: str, params: Any = ()) -> sqlite3.Cursor:
        if self.match in sql:
            raise sqlite3.OperationalError("disk I/O error")
        return self.inner.execute(sql, params)

    def executemany(self, sql: str, params: Any) -> sqlite3.Cursor:
        return self.inner.executemany(sql, params)

    def close(self) -> None:
        self.inner.close()


def seed(path: Path) -> None:
    store = StateStore(path)
    store.load(BASE)
    assert store.flush(
        Changes(
            rule_states=MappingProxyType({"freezer": RuleState()}),
            deliveries=(record(1),),
            attempts=(AttemptMark("evt_0009", "owner_sms", 1, BASE),),
            suppression=SuppressionState(count=2, since=BASE),
        ),
        BASE,
    )
    store.close()


def test_dry_run_marks_never_evict_live_cap_evidence(tmp_path: Path) -> None:
    """B1: a dry-run flood newer than a real send leaves the real send's slot in place."""
    store = StateStore(tmp_path)
    store.load(BASE)
    live = AttemptMark("evt_live", "owner_sms", 1, BASE)
    assert store.flush(Changes(attempts=(live,)), BASE)
    later = BASE + timedelta(minutes=1)
    flood = tuple(AttemptMark(f"evt_dry_{n}", "audit", 1, later, live=False) for n in range(10_001))
    assert store.flush(Changes(attempts=flood), later)
    store.close()
    store = StateStore(tmp_path)
    snapshot = store.load(later)
    assert [mark.key for mark in snapshot.attempts] == [live.key]
    store.close()


@pytest.mark.parametrize("table", ["meta", "delivery", "rule_state", "send_attempt"])
def test_one_unreadable_table_hides_no_other(tmp_path: Path, table: str) -> None:
    """H5: every table is read on its own, so a failure in one salvages the rest."""
    seed(tmp_path)

    def connect(path: Path) -> Any:
        return Failing(sqlite3.connect(path, autocommit=True), f"FROM {table} ")

    store = StateStore(tmp_path, connect=connect)
    snapshot = store.load(BASE)
    assert not store.healthy
    assert (snapshot.suppression.count == 2) is (table != "meta")
    assert (len(snapshot.deliveries) == 1) is (table != "delivery")
    assert ("freezer" in snapshot.rule_states) is (table != "rule_state")
    assert (len(snapshot.attempts) == 1) is (table != "send_attempt")
    store.close()


class Rows(list[Any]):
    def fetchone(self) -> Any:
        return self[0] if self else None

    def fetchall(self) -> list[Any]:
        return list(self)


class Recording:
    """A real connection that keeps every value it returned."""

    def __init__(self, inner: sqlite3.Connection, seen: list[object]) -> None:
        self.inner = inner
        self.seen = seen

    def execute(self, sql: str, params: Any = ()) -> Rows:
        rows = Rows(self.inner.execute(sql, params).fetchall())
        for row in rows:
            self.seen.extend(row)
        return rows

    def executemany(self, sql: str, params: Any) -> sqlite3.Cursor:
        return self.inner.executemany(sql, params)

    def close(self) -> None:
        self.inner.close()


def test_oversized_cells_are_never_read_and_count_as_corrupt(tmp_path: Path) -> None:
    """M9: no cell larger than its bound reaches Python; its row is recovered as corrupt."""
    seed(tmp_path)
    huge = "x" * 300_000  # beyond every bound, including 4 bytes per character
    with closing(sqlite3.connect(tmp_path / DB_FILENAME, autocommit=True)) as connection:
        connection.execute(
            "INSERT INTO delivery (event_id, recipient, rule_id, kind, status, text, attempts, "
            "created_at, updated_at) VALUES ('evt_big', 'owner_sms', 'freezer', 'event', "
            "'pending', ?, 0, ?, ?)",
            (huge, BASE.isoformat(), BASE.isoformat()),
        )
        connection.execute(
            "INSERT INTO delivery (event_id, recipient, rule_id, kind, status, text, attempts, "
            "created_at, updated_at) VALUES (?, 'owner_sms', 'battery', 'event', 'pending', "
            "'x', 0, ?, ?)",
            (huge, BASE.isoformat(), BASE.isoformat()),
        )
        connection.execute(
            "INSERT INTO send_attempt (event_id, recipient, attempt, at) VALUES (?, 'x', 1, ?)",
            (huge, BASE.isoformat()),
        )
        connection.execute(
            "INSERT INTO rule_state (rule_id, state, updated_at) VALUES ('pump', ?, 'x')",
            ("[" + huge,),
        )
        connection.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('suppressed_count', ?)", (huge,)
        )
    seen: list[object] = []

    def connect(path: Path) -> Any:
        return Recording(sqlite3.connect(path, autocommit=True), seen)

    store = StateStore(tmp_path, connect=connect)
    snapshot = store.load(BASE)
    assert max(len(value) for value in seen if isinstance(value, str)) <= 64 * 1024 * 4
    assert not any(isinstance(value, str) and len(value) >= len(huge) for value in seen)
    by_id = {r.event_id: r for r in snapshot.deliveries}
    assert by_id["evt_big"].status is DeliveryStatus.AMBIGUOUS  # recovered, text replaced
    assert by_id["evt_big"].text.startswith("VRM Alert Relay: an alert could not be read")
    assert "pump" not in snapshot.rule_states
    assert snapshot.suppression.count == 1  # an unreadable count still reports something held
    assert any(mark.recipient == "unknown" for mark in snapshot.attempts)
    assert snapshot.problems == 6  # four rows, the oversized meta value, its unreadable count
    store.close()


def test_a_database_swapped_while_sqlite_opens_it_is_not_used(tmp_path: Path) -> None:
    """M8: SQLite must open the file that was validated, not a symlink's target."""
    seed(tmp_path)
    target = tmp_path / "someone-elses.sqlite3"
    with closing(sqlite3.connect(target)) as connection:
        connection.execute("CREATE TABLE other (x TEXT)")
    before = target.read_bytes()

    def racing_connect(path: Path) -> sqlite3.Connection:
        moved = path.with_name("moved-aside")
        path.rename(moved)
        path.symlink_to(target)
        try:
            return sqlite3.connect(path, autocommit=True)
        finally:
            path.unlink()
            moved.rename(path)

    store = StateStore(tmp_path, connect=racing_connect)
    snapshot = store.load(BASE)
    assert target.read_bytes() == before
    assert not snapshot.complete
    assert not store.healthy
    assert store.error == "UnsafeStateError: the database path was replaced while it was opened"
    assert not store.flush(Changes(deliveries=(record(2),)), BASE)
    store.close()


def test_a_replaced_lock_file_makes_storage_unavailable(tmp_path: Path) -> None:
    """M8: if the lock file is swapped, another process could lock the new one."""
    store = StateStore(tmp_path)
    store.load(BASE)
    lock = tmp_path / LOCK_FILENAME
    lock.unlink()
    lock.write_text("")
    store._close_connection()
    assert not store.flush(Changes(deliveries=(record(1),)), BASE)
    assert store.error == f"UnsafeStateError: state file {LOCK_FILENAME} was replaced"
    store.close()


def _corrupt_table(path: Path, table: str) -> None:
    """Overwrite the root page of ``table`` so SQLite reports a malformed database."""
    with closing(sqlite3.connect(path / DB_FILENAME, autocommit=True)) as connection:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        root = connection.execute(
            "SELECT rootpage FROM sqlite_master WHERE name = ?", (table,)
        ).fetchone()[0]
        size = connection.execute("PRAGMA page_size").fetchone()[0]
    with (path / DB_FILENAME).open("r+b") as handle:
        handle.seek((root - 1) * size)
        handle.write(b"\xa5" * size)


def test_a_corrupt_database_is_quarantined_after_salvage(tmp_path: Path) -> None:
    """R2: a malformed file is moved aside with what was readable kept in memory."""
    seed(tmp_path)
    _corrupt_table(tmp_path, "delivery")
    store = StateStore(tmp_path)
    snapshot = store.load(BASE)
    assert snapshot.reset
    assert snapshot.complete
    assert "freezer" in snapshot.rule_states  # salvaged before the move
    assert [mark.event_id for mark in snapshot.attempts] == ["evt_0009"]
    assert snapshot.suppression.count == 2
    assert snapshot.deliveries == ()
    [moved] = tmp_path.glob(f"{DB_FILENAME}.corrupt-*")
    assert (
        not (tmp_path / f"{DB_FILENAME}-wal").exists()
        or (tmp_path / f"{DB_FILENAME}-wal").stat().st_size < moved.stat().st_size
    )
    assert store.flush(Changes(deliveries=(record(2),)), BASE)  # the fresh database works
    store.close()


def test_quarantine_names_never_collide_and_failures_keep_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / f"{DB_FILENAME}.corrupt-20350101T000000000000Z").write_text("earlier")
    (tmp_path / DB_FILENAME).write_bytes(b"not a database" * 64)
    store = StateStore(tmp_path)
    assert store.load(BASE).reset
    assert (tmp_path / f"{DB_FILENAME}.corrupt-20350101T000000000000Z-1").exists()
    store.close()

    (tmp_path / DB_FILENAME).unlink(missing_ok=True)
    (tmp_path / DB_FILENAME).write_bytes(b"not a database" * 64)

    def refuse(self: Path, target: Path) -> Path:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(type(tmp_path), "replace", refuse)
    store = StateStore(tmp_path)
    snapshot = store.load(BASE)
    assert not snapshot.reset
    assert not snapshot.complete  # left untouched and unread; alerting continues in memory
    assert (tmp_path / DB_FILENAME).read_bytes().startswith(b"not a database")
    store.close()


def test_a_newer_schema_is_never_quarantined(tmp_path: Path) -> None:
    """R2: a schema from a newer release is left alone and read again each cycle."""
    seed(tmp_path)
    with closing(sqlite3.connect(tmp_path / DB_FILENAME, autocommit=True)) as connection:
        connection.execute("PRAGMA user_version = 99")
    store = StateStore(tmp_path)
    snapshot = store.load(BASE)
    assert not snapshot.reset
    assert not snapshot.complete
    assert list(tmp_path.glob(f"{DB_FILENAME}.corrupt-*")) == []
    assert store.reload(BASE) is None
    store.close()


def test_reload_quarantines_a_database_found_corrupt_later(tmp_path: Path) -> None:
    seed(tmp_path)
    state = {"fail": True}

    def connect(path: Path) -> Any:
        if state["fail"]:
            raise sqlite3.OperationalError("database is locked")
        return sqlite3.connect(path, autocommit=True)

    store = StateStore(tmp_path, connect=connect)
    assert not store.load(BASE).complete
    (tmp_path / DB_FILENAME).write_bytes(b"not a database" * 64)
    for suffix in ("-wal", "-shm"):
        (tmp_path / f"{DB_FILENAME}{suffix}").unlink(missing_ok=True)
    state["fail"] = False
    snapshot = store.reload(BASE)
    assert snapshot is not None
    assert snapshot.reset
    assert store.readable
    store.close()


def test_a_suppression_already_stored_is_not_counted_again_from_the_journal(
    tmp_path: Path,
) -> None:
    """H4: journal suppression changes apply once, keyed by delivery identity."""
    held = record(1, DeliveryStatus.SUPPRESSED)
    store = StateStore(tmp_path)
    store.load(BASE)
    assert store.flush(
        Changes(deliveries=(held,), suppression=SuppressionState(count=1, since=BASE)), BASE
    )
    # The flush reached SQLite, but the same change was also journaled.
    assert store.journal((JournalEntry(held, attempt=False),), BASE)
    store.close()
    store = StateStore(tmp_path)
    assert store.load(BASE).suppression.count == 1
    store.close()


def test_quarantine_moves_the_sidecars_with_the_database(tmp_path: Path) -> None:
    (tmp_path / DB_FILENAME).write_bytes(b"not a database" * 64)
    (tmp_path / f"{DB_FILENAME}-wal").write_bytes(b"wal frames")

    def not_a_database(path: Path) -> sqlite3.Connection:
        # As SQLite reports it, but before SQLite could tidy the sidecars away.
        error = sqlite3.DatabaseError("file is not a database")
        error.sqlite_errorcode = 26
        raise error

    store = StateStore(tmp_path, connect=not_a_database)
    assert store.load(BASE).reset
    [moved_wal] = tmp_path.glob(f"{DB_FILENAME}.corrupt-*-wal")
    assert moved_wal.read_bytes() == b"wal frames"
    store.close()


def test_a_lock_file_swapped_before_it_is_locked_is_not_trusted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def replaced(path: Path, expected: object) -> None:
        raise UnsafeStateError(f"state file {path.name} was replaced")

    monkeypatch.setattr(store_module, "check_identity", replaced)
    store = StateStore(tmp_path)
    snapshot = store.load(BASE)
    assert not snapshot.complete
    assert store._lock is None
    assert store.error == f"UnsafeStateError: state file {LOCK_FILENAME} was replaced"
    store.close()


def test_without_proc_the_path_check_alone_is_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(store_module, "open_descriptors", lambda: None)
    store = StateStore(tmp_path)
    assert store.load(BASE).complete
    assert store.flush(Changes(deliveries=(record(1),)), BASE)
    store.close()


def test_old_notices_are_pruned_whatever_their_status(tmp_path: Path) -> None:
    notice = DeliveryRecord(
        event_id="notice_1",
        recipient="owner_sms",
        kind=DeliveryKind.NOTICE,
        status=DeliveryStatus.AMBIGUOUS,
        text="Storage notice",
        attempts=1,
        created_at=BASE,
        updated_at=BASE,
    )
    store = StateStore(tmp_path, retention=timedelta(days=2))
    store.load(BASE)
    assert store.flush(Changes(deliveries=(notice, record(1))), BASE)
    assert store.flush(Changes(), BASE + timedelta(days=3))
    store.close()
    store = StateStore(tmp_path)
    assert [r.event_id for r in store.load(BASE + timedelta(days=3)).deliveries] == ["evt_0001"]
    store.close()

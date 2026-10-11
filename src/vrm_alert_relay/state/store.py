"""SQLite persistence that degrades instead of failing, with a fallback journal.

Startup (:meth:`StateStore.load`) takes an exclusive lock on the state
directory and refuses unsafe paths; both raise, because running two relays
on one state directory, or following a planted symlink, must stop loudly.
Every other storage failure is logged at ``ERROR``, marks the store
unhealthy, and returns a safe fallback (``False`` from :meth:`flush` and
:meth:`journal`, partial data from :meth:`load`), so the caller keeps its
in-memory state and tries again later.

Nothing that limits sending is thrown away: unreadable send-attempt rows
become attempts at load time, unreadable unfinished deliveries are recovered
as ambiguous or reset their rule, and a failed load is never mistaken for an
empty database.
"""

from __future__ import annotations

import errno
import fcntl
import json
import logging
import os
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import partial
from pathlib import Path
from types import MappingProxyType
from typing import Final

from vrm_alert_relay.engine import RuleState

from .journal import MAX_JOURNAL_BYTES, AttemptJournal
from .models import (
    MAX_ATTEMPTS,
    MAX_COUNTER,
    MAX_MESSAGE_LENGTH,
    AttemptMark,
    Changes,
    DeliveryKind,
    DeliveryRecord,
    DeliveryStatus,
    InvalidRecordError,
    JournalEntry,
    Snapshot,
    SuppressionState,
    decode_optional_time,
    decode_time,
    encode_time,
    is_counter,
    is_identifier,
    is_message_id,
)
from .paths import (
    SIDECAR_SUFFIXES,
    StateLockedError,
    UnsafeStateError,
    check_directory,
    open_private,
    secure_existing,
)
from .schema import SchemaTooNewError, migrate

__all__ = [
    "ATTEMPT_WINDOW",
    "DB_FILENAME",
    "DEFAULT_MAX_RECORDS",
    "DEFAULT_RETENTION",
    "LOCK_FILENAME",
    "MAX_ATTEMPT_ROWS",
    "MAX_RULE_STATES",
    "UNREADABLE_TEXT",
    "Connect",
    "StateStore",
]

logger = logging.getLogger(__name__)

DB_FILENAME: Final = "relay-state.sqlite3"
LOCK_FILENAME: Final = "relay-state.lock"
DEFAULT_RETENTION: Final = timedelta(days=7)
DEFAULT_MAX_RECORDS: Final = 5000
MAX_RULE_STATES: Final = 1000
ATTEMPT_WINDOW: Final = timedelta(days=1)
MAX_ATTEMPT_ROWS: Final = 10_000
MAX_STATE_JSON_LENGTH: Final = 64 * 1024
MAX_ERROR_LENGTH: Final = 200
BUSY_TIMEOUT_SECONDS: Final = 5.0
UNREADABLE_TEXT: Final = (
    "VRM Alert Relay: an alert could not be read back from storage; check the relay."
)

_META_LAST_SEEN: Final = "last_seen"
_META_COUNT: Final = "suppressed_count"
_META_SINCE: Final = "suppressed_since"
_META_LAST_SUMMARY: Final = "last_summary_at"
_META_SUMMARY_ID: Final = "summary_event_id"
_META_SUMMARY_COUNT: Final = "summary_count"
_TERMINAL: Final = tuple(status.value for status in DeliveryStatus if status.terminal)
_TERMINAL_IN: Final = ", ".join("?" for _ in _TERMINAL)
_RUNTIME_FAILURES: Final = (
    sqlite3.Error,
    OSError,
    SchemaTooNewError,
    UnsafeStateError,
    StateLockedError,
)
_READ_ONLY_ERRNOS: Final = frozenset({errno.EROFS, errno.EACCES, errno.EPERM})
_DELIVERY_COLUMNS: Final = (
    "event_id, recipient, rule_id, kind, status, text, attempts, created_at, updated_at, "
    "next_attempt_at, last_attempt_at, provider_message_id"
)

type Connect = Callable[[Path], sqlite3.Connection]


def _default_connect(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path, timeout=BUSY_TIMEOUT_SECONDS, autocommit=True)


@contextmanager
def _transaction(connection: sqlite3.Connection) -> Iterator[None]:
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        with suppress(sqlite3.Error):
            connection.execute("ROLLBACK")
        raise
    connection.execute("COMMIT")


def _describe(exc: BaseException) -> str:
    if isinstance(exc, OSError) and not isinstance(exc, sqlite3.Error):
        # str(OSError) includes the file path; keep only the reason.
        detail = exc.strerror or "operating system error"
    else:
        detail = str(exc)
    return f"{type(exc).__name__}: {detail}"[:MAX_ERROR_LENGTH]


def _decode_rule_state(rule_id: object, raw: object) -> tuple[str, RuleState]:
    if not is_identifier(rule_id):
        raise InvalidRecordError("rule_id must be a bounded identifier")  # noqa: TRY003  # per-check validation message
    if not isinstance(raw, str) or len(raw) > MAX_STATE_JSON_LENGTH:
        raise InvalidRecordError("rule state must be bounded JSON text")  # noqa: TRY003  # per-check validation message
    return str(rule_id), RuleState.from_dict(json.loads(raw))


def _decode_delivery(row: tuple[object, ...]) -> DeliveryRecord:
    (
        event_id,
        recipient,
        rule_id,
        kind,
        status,
        text,
        attempts,
        created_at,
        updated_at,
        next_attempt_at,
        last_attempt_at,
        provider_message_id,
    ) = row
    return DeliveryRecord(
        event_id=event_id,  # type: ignore[arg-type]  # validated by DeliveryRecord
        recipient=recipient,  # type: ignore[arg-type]  # validated by DeliveryRecord
        rule_id=rule_id,  # type: ignore[arg-type]  # validated by DeliveryRecord
        kind=DeliveryKind(str(kind)),
        status=DeliveryStatus(str(status)),
        text=text,  # type: ignore[arg-type]  # validated by DeliveryRecord
        attempts=attempts,  # type: ignore[arg-type]  # validated by DeliveryRecord
        created_at=decode_time(created_at),
        updated_at=decode_time(updated_at),
        next_attempt_at=decode_optional_time(next_attempt_at),
        last_attempt_at=decode_optional_time(last_attempt_at),
        provider_message_id=provider_message_id,  # type: ignore[arg-type]  # validated by DeliveryRecord
    )


def _encode_delivery(record: DeliveryRecord) -> tuple[object, ...]:
    return (
        record.event_id,
        record.recipient,
        record.rule_id,
        record.kind.value,
        record.status.value,
        record.text,
        record.attempts,
        encode_time(record.created_at),
        encode_time(record.updated_at),
        None if record.next_attempt_at is None else encode_time(record.next_attempt_at),
        None if record.last_attempt_at is None else encode_time(record.last_attempt_at),
        record.provider_message_id,
    )


def _time_or(raw: object, default: datetime) -> datetime:
    try:
        return decode_time(raw)
    except ValueError:
        return default


def _optional_time_or_none(raw: object) -> datetime | None:
    try:
        return decode_optional_time(raw)
    except ValueError:
        return None


def _status_or_none(raw: object) -> DeliveryStatus | None:
    try:
        return DeliveryStatus(str(raw))
    except ValueError:
        return None


def _kind_or_event(raw: object) -> DeliveryKind:
    try:
        return DeliveryKind(str(raw))
    except ValueError:
        return DeliveryKind.EVENT


def _decode_mark(row: tuple[object, ...]) -> AttemptMark:
    _, event_id, recipient, attempt, at, live = row
    if live not in (0, 1) or isinstance(live, bool):
        raise InvalidRecordError("live must be 0 or 1")  # noqa: TRY003  # per-check validation message
    return AttemptMark(
        event_id=event_id,  # type: ignore[arg-type]  # validated by AttemptMark
        recipient=recipient,  # type: ignore[arg-type]  # validated by AttemptMark
        attempt=attempt,  # type: ignore[arg-type]  # validated by AttemptMark
        at=decode_time(at),
        live=live == 1,
    )


def _newer(candidate: DeliveryRecord, existing: DeliveryRecord | None) -> bool:
    return existing is None or candidate.progress() > existing.progress()


@dataclass(slots=True)
class _Loaded:
    """What a load read, and the repairs to write back afterwards."""

    rule_states: dict[str, RuleState] = field(default_factory=dict)
    deliveries: dict[tuple[str, str], DeliveryRecord] = field(default_factory=dict)
    marks: dict[tuple[str, str, int], AttemptMark] = field(default_factory=dict)
    suppression: SuppressionState = field(default_factory=SuppressionState)
    last_seen: datetime | None = None
    problems: int = 0
    attempts_read: bool = False
    unrecoverable: int = 0
    invalidated_rules: set[str] = field(default_factory=set)
    repaired: list[DeliveryRecord] = field(default_factory=list)
    delete_delivery_rows: list[int] = field(default_factory=list)
    replace_attempt_rows: list[tuple[int, AttemptMark]] = field(default_factory=list)
    expired_attempt_rows: list[int] = field(default_factory=list)


class StateStore:
    """Durable relay state in a lock-protected state directory.

    Files: ``relay-state.sqlite3`` (WAL, ``synchronous=FULL``), its SQLite
    sidecars, ``relay-state.lock``, and the fallback journal
    ``relay-state.journal`` (see :class:`~vrm_alert_relay.state.journal.AttemptJournal`).
    Every file is a regular, owner-only (0600) file opened without following
    symlinks. Each :meth:`flush` is one transaction; a successful flush also
    merges the journal into SQLite and then removes it.
    """

    def __init__(
        self,
        state_dir: Path,
        *,
        retention: timedelta = DEFAULT_RETENTION,
        max_records: int = DEFAULT_MAX_RECORDS,
        journal_max_bytes: int = MAX_JOURNAL_BYTES,
        connect: Connect = _default_connect,
    ) -> None:
        if retention <= timedelta(0):
            raise ValueError("retention must be positive")  # noqa: TRY003  # per-check validation message
        if max_records < 1:
            raise ValueError("max_records must be at least 1")  # noqa: TRY003  # per-check validation message
        self._directory = state_dir
        self._path = state_dir / DB_FILENAME
        self._lock_path = state_dir / LOCK_FILENAME
        self._journal = AttemptJournal(state_dir, max_bytes=journal_max_bytes)
        self._retention = retention
        self._max_records = max_records
        self._connect_fn = connect
        self._connection: sqlite3.Connection | None = None
        self._lock: int | None = None
        self._failing = False
        self._error: str | None = None
        self._problems = 0
        self._journal_pending = False
        self._last_seen: datetime | None = None

    @property
    def path(self) -> Path:
        return self._path

    @property
    def healthy(self) -> bool:
        """False while writes fail, and for the rest of the run once corrupt data was found."""
        return not self._failing and self._problems == 0

    @property
    def error(self) -> str | None:
        """A short description of the latest problem, without file paths."""
        if self._error is None and self._problems:
            return f"corrupt state: {self._problems} unreadable rows or journal lines"
        return self._error

    # Startup ------------------------------------------------------------------

    def load(self, now: datetime) -> Snapshot:
        """Lock the state directory and read everything that can be read.

        Raises :class:`StateLockedError` when another process holds the
        directory and :class:`UnsafeStateError` for a symlinked or irregular
        state path. Other failures are logged and leave the store unhealthy;
        the files are not modified.
        """
        try:
            self._acquire()
        except OSError as exc:
            self._fail("lock", exc)
        loaded = _Loaded()
        try:
            connection = self._connect()
            self._read(connection, now, loaded)
        except (sqlite3.Error, OSError, SchemaTooNewError) as exc:
            # Nothing could be read; that is unknown history, not an empty database.
            self._fail("load", exc)
        try:
            entries, corrupt = self._journal.read()
        except OSError as exc:
            self._fail("journal_read", exc)
            loaded.attempts_read = False  # attempts may be recorded only there
        else:
            self._merge_journal_into(loaded, entries, corrupt, now)
            self._journal_pending = bool(entries or corrupt)
        if loaded.problems:
            self._problems += loaded.problems
            logger.error(
                "corrupt state was found and handled conservatively",
                extra={"event": "state.corrupt", "count": loaded.problems},
            )
        self._repair(loaded, now)
        if loaded.last_seen is not None:
            self._last_seen = loaded.last_seen
        backwards = loaded.last_seen is not None and now < loaded.last_seen
        if backwards:
            logger.warning(
                "the clock is earlier than when state was last written; keeping all attempts",
                extra={"event": "state.clock_backwards"},
            )
        return Snapshot(
            rule_states=MappingProxyType(loaded.rule_states),
            deliveries=tuple(
                sorted(loaded.deliveries.values(), key=lambda r: (r.created_at, r.key))
            ),
            attempts=self._clamped(loaded, now),
            attempts_complete=loaded.attempts_read,
            suppression=loaded.suppression,
            last_seen=loaded.last_seen,
            clock_moved_backwards=backwards,
            problems=loaded.problems,
        )

    def _read(self, connection: sqlite3.Connection, now: datetime, loaded: _Loaded) -> None:
        """Read each table on its own, so one unreadable table does not hide the others."""
        connection.execute("BEGIN")
        try:
            meta_read = self._attempt_read(
                "load_meta", partial(self._read_meta, connection, loaded)
            )
            # Without the last-seen time, a backwards clock cannot be ruled out.
            prune = meta_read and not (loaded.last_seen is not None and now < loaded.last_seen)
            self._attempt_read(
                "load_deliveries", partial(self._read_deliveries, connection, now, loaded)
            )
            self._attempt_read(
                "load_rule_states", partial(self._read_rule_states, connection, loaded)
            )
            loaded.attempts_read = self._attempt_read(
                "load_attempts",
                partial(self._read_attempts, connection, now, loaded, prune=prune),
            )
        finally:
            with suppress(sqlite3.Error):
                connection.execute("COMMIT")

    def _attempt_read(self, action: str, reader: Callable[[], None]) -> bool:
        try:
            reader()
        except sqlite3.Error as exc:
            self._fail(action, exc)
            return False
        return True

    def reload_attempts(self, now: datetime) -> tuple[AttemptMark, ...] | None:
        """Read the send-attempt history again (SQLite and journal); None if impossible."""
        loaded = _Loaded()
        try:
            connection = self._connect()
            connection.execute("BEGIN")
            try:
                self._read_attempts(connection, now, loaded, prune=False)
            finally:
                with suppress(sqlite3.Error):
                    connection.execute("COMMIT")
            entries, corrupt = self._journal.read()
        except _RUNTIME_FAILURES as exc:
            self._fail("reload_attempts", exc)
            return None
        self._merge_journal_into(loaded, entries, corrupt, now)
        return self._clamped(loaded, now)

    @staticmethod
    def _clamped(loaded: _Loaded, now: datetime) -> tuple[AttemptMark, ...]:
        marks = (
            mark if mark.at <= now else AttemptMark(*mark.key, at=now, live=mark.live)
            for mark in loaded.marks.values()
        )
        return tuple(sorted(marks, key=lambda mark: (mark.at, mark.key)))

    @staticmethod
    def _read_meta(connection: sqlite3.Connection, loaded: _Loaded) -> None:
        meta = dict(connection.execute("SELECT key, value FROM meta LIMIT 100").fetchall())

        def time_of(key: str) -> datetime | None:
            try:
                return decode_optional_time(meta.get(key))
            except ValueError:
                loaded.problems += 1
                return None

        def count_of(key: str, unreadable: int) -> int:
            raw = meta.get(key, "0")
            if isinstance(raw, str) and raw.isdigit() and is_counter(int(raw)):
                return int(raw)
            loaded.problems += 1
            return unreadable

        summary_id = meta.get(_META_SUMMARY_ID)
        if summary_id is not None and not is_identifier(summary_id):
            loaded.problems += 1
            summary_id = None
        loaded.last_seen = time_of(_META_LAST_SEEN)
        loaded.suppression = SuppressionState(
            # An unreadable count still reports that something was held back.
            count=count_of(_META_COUNT, 1),
            since=time_of(_META_SINCE),
            last_summary_at=time_of(_META_LAST_SUMMARY),
            summary_event_id=summary_id,
            summary_count=count_of(_META_SUMMARY_COUNT, 0),
        )

    def _read_deliveries(
        self, connection: sqlite3.Connection, now: datetime, loaded: _Loaded
    ) -> None:
        # Unfinished records first, so the row limit can only ever cut finished ones.
        select = f"SELECT rowid, {_DELIVERY_COLUMNS} FROM delivery "  # noqa: S608  # constant columns
        queries = (
            f"{select}WHERE status NOT IN ({_TERMINAL_IN}) ORDER BY rowid LIMIT ?",
            f"{select}WHERE status IN ({_TERMINAL_IN}) ORDER BY updated_at DESC LIMIT ?",
        )
        for query in queries:
            for row in connection.execute(query, (*_TERMINAL, self._max_records * 2)):
                rowid, *columns = row
                try:
                    record = _decode_delivery(tuple(columns))
                except (ValueError, TypeError):
                    loaded.problems += 1
                    self._salvage(rowid, tuple(columns), now, loaded)
                    continue
                loaded.deliveries[record.key] = record

    @staticmethod
    def _salvage(rowid: int, columns: tuple[object, ...], now: datetime, loaded: _Loaded) -> None:
        """Keep what an unreadable delivery row can still tell us."""
        event_id, recipient, rule_id, kind, status, text, attempts = columns[:7]
        created_at, _, _, last_attempt_at, provider_message_id = columns[7:]
        parsed_status = _status_or_none(status)
        finished = parsed_status is not None and parsed_status.terminal
        rule = rule_id if is_identifier(rule_id) else None
        if is_identifier(event_id) and is_identifier(recipient):
            count = attempts if isinstance(attempts, int) and is_counter(attempts) else 1
            record = DeliveryRecord(
                event_id=str(event_id),
                recipient=str(recipient),
                rule_id=None if rule is None else str(rule),
                kind=_kind_or_event(kind),
                # An unfinished record may have been sent: reconcile, then retry.
                status=parsed_status if finished else DeliveryStatus.AMBIGUOUS,  # type: ignore[arg-type]
                text=text[:MAX_MESSAGE_LENGTH] if isinstance(text, str) else UNREADABLE_TEXT,
                attempts=min(max(count, 0 if finished else 1), MAX_ATTEMPTS),
                created_at=_time_or(created_at, now),
                updated_at=now,
                next_attempt_at=None if finished else now,
                last_attempt_at=_optional_time_or_none(last_attempt_at),
                provider_message_id=(
                    str(provider_message_id) if is_message_id(provider_message_id) else None
                ),
            )
            loaded.deliveries[record.key] = record
            loaded.repaired.append(record)
            return
        loaded.delete_delivery_rows.append(rowid)
        if finished:
            return
        if rule is not None:
            # The rule's next evaluation starts fresh and raises the alert again.
            loaded.invalidated_rules.add(str(rule))
        else:
            loaded.unrecoverable += 1

    @staticmethod
    def _read_rule_states(connection: sqlite3.Connection, loaded: _Loaded) -> None:
        rows = connection.execute(
            "SELECT rule_id, state FROM rule_state ORDER BY updated_at DESC LIMIT ?",
            (MAX_RULE_STATES,),
        )
        for rule_id, raw in rows:
            try:
                key, state = _decode_rule_state(rule_id, raw)
            except (ValueError, RecursionError):
                loaded.problems += 1
                logger.warning(
                    "discarding corrupt rule state; the rule starts from fresh state",
                    extra={
                        "event": "state.rule_state_corrupt",
                        "rule_id": rule_id if is_identifier(rule_id) else None,
                    },
                )
                continue
            if key not in loaded.invalidated_rules:
                loaded.rule_states[key] = state

    @staticmethod
    def _read_attempts(
        connection: sqlite3.Connection, now: datetime, loaded: _Loaded, *, prune: bool
    ) -> None:
        rows = connection.execute(
            "SELECT id, event_id, recipient, attempt, at, live FROM send_attempt "
            "ORDER BY id DESC LIMIT ?",
            (MAX_ATTEMPT_ROWS,),
        )
        for row in rows:
            rowid = row[0]
            try:
                mark = _decode_mark(tuple(row))
            except (ValueError, TypeError):
                # Never erase rate-limit evidence: an unreadable attempt
                # occupies a slot for a full window from now.
                loaded.problems += 1
                mark = AttemptMark(f"attempt_unreadable_{rowid}", "unknown", 0, now)
                loaded.replace_attempt_rows.append((rowid, mark))
            if prune and mark.at <= now - ATTEMPT_WINDOW:
                loaded.expired_attempt_rows.append(rowid)
                continue
            loaded.marks.setdefault(mark.key, mark)

    @staticmethod
    def _merge_journal_into(
        loaded: _Loaded, entries: list[JournalEntry], corrupt: int, now: datetime
    ) -> None:
        for entry in entries:
            if _newer(entry.record, loaded.deliveries.get(entry.record.key)):
                loaded.deliveries[entry.record.key] = entry.record
            mark = entry.mark()
            if mark is not None:
                loaded.marks.setdefault(mark.key, mark)
        stamp = int(now.timestamp() * 1_000_000)
        for index in range(corrupt):
            mark = AttemptMark(f"journal_unreadable_{stamp}_{index}", "unknown", 0, now)
            loaded.marks[mark.key] = mark
        loaded.problems += corrupt

    def _repair(self, loaded: _Loaded, now: datetime) -> None:
        """Write back conservative replacements for unreadable rows, best effort."""
        if loaded.unrecoverable:
            previous = loaded.suppression
            loaded.suppression = SuppressionState(
                count=min(previous.count + loaded.unrecoverable, MAX_COUNTER),
                since=previous.since or now,
                last_summary_at=previous.last_summary_at,
                summary_event_id=previous.summary_event_id,
                summary_count=previous.summary_count,
            )
        if not (
            loaded.repaired
            or loaded.delete_delivery_rows
            or loaded.invalidated_rules
            or loaded.replace_attempt_rows
            or loaded.expired_attempt_rows
            or loaded.unrecoverable
        ):
            return
        try:
            connection = self._connect()
            with _transaction(connection):
                connection.executemany(
                    "DELETE FROM delivery WHERE rowid = ?",
                    [(rowid,) for rowid in loaded.delete_delivery_rows],
                )
                self._upsert_deliveries(connection, loaded.repaired)
                connection.executemany(
                    "DELETE FROM rule_state WHERE rule_id = ?",
                    [(rule,) for rule in sorted(loaded.invalidated_rules)],
                )
                connection.executemany(
                    "DELETE FROM send_attempt WHERE id = ?",
                    [(rowid,) for rowid, _ in loaded.replace_attempt_rows]
                    + [(rowid,) for rowid in loaded.expired_attempt_rows],
                )
                self._insert_marks(connection, [mark for _, mark in loaded.replace_attempt_rows])
                self._write_suppression(connection, loaded.suppression)
        except _RUNTIME_FAILURES as exc:
            self._fail("repair", exc)

    # Writes -------------------------------------------------------------------

    def flush(self, changes: Changes, now: datetime) -> bool:
        """Write ``changes``, merge any journal, and prune old rows in one transaction."""
        try:
            connection = self._connect()
            with _transaction(connection):
                self._write(connection, changes, now)
                if self._journal_pending:
                    self._merge_journal(connection, now)
                self._prune(connection, now)
        except _RUNTIME_FAILURES as exc:
            self._fail("flush", exc)
            return False
        if self._journal_pending:
            try:
                self._journal.clear()
            except OSError as exc:
                self._fail("journal_clear", exc)
                return True
            self._journal_pending = False
        self._recovered()
        return True

    def journal(self, entries: tuple[JournalEntry, ...]) -> bool:
        """Durably append ``entries`` to the fallback journal; False if impossible."""
        try:
            self._acquire()
            self._journal.append(entries)
        except _RUNTIME_FAILURES as exc:
            self._fail("journal", exc)
            return False
        self._journal_pending = True
        return True

    def close(self) -> None:
        """Close the database and release the state-directory lock."""
        if self._connection is not None:
            with suppress(sqlite3.Error):
                self._connection.close()
            self._connection = None
        if self._lock is not None:
            os.close(self._lock)
            self._lock = None

    def _write(self, connection: sqlite3.Connection, changes: Changes, now: datetime) -> None:
        stamp = encode_time(now)
        connection.executemany(
            "INSERT INTO rule_state (rule_id, state, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT (rule_id) DO UPDATE SET "
            "state = excluded.state, updated_at = excluded.updated_at",
            [
                (rule_id, json.dumps(state.to_dict(), separators=(",", ":")), stamp)
                for rule_id, state in changes.rule_states.items()
            ],
        )
        self._upsert_deliveries(connection, changes.deliveries)
        self._insert_marks(connection, changes.attempts)
        connection.executemany(
            "DELETE FROM send_attempt WHERE event_id = ? AND recipient = ? AND attempt = ?",
            changes.expired_attempts,
        )
        self._write_suppression(connection, changes.suppression)
        last_seen = now if self._last_seen is None else max(now, self._last_seen)
        connection.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            (_META_LAST_SEEN, encode_time(last_seen)),
        )
        self._last_seen = last_seen

    @staticmethod
    def _upsert_deliveries(
        connection: sqlite3.Connection, records: list[DeliveryRecord] | tuple[DeliveryRecord, ...]
    ) -> None:
        connection.executemany(
            f"INSERT OR REPLACE INTO delivery ({_DELIVERY_COLUMNS}) "  # noqa: S608  # constant column list
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [_encode_delivery(record) for record in records],
        )

    @staticmethod
    def _insert_marks(
        connection: sqlite3.Connection, marks: list[AttemptMark] | tuple[AttemptMark, ...]
    ) -> None:
        connection.executemany(
            "INSERT OR IGNORE INTO send_attempt (event_id, recipient, attempt, at, live) "
            "VALUES (?, ?, ?, ?, ?)",
            [(*mark.key, encode_time(mark.at), int(mark.live)) for mark in marks],
        )

    @staticmethod
    def _write_suppression(connection: sqlite3.Connection, state: SuppressionState) -> None:
        values: dict[str, str | None] = {
            _META_COUNT: str(state.count),
            _META_SINCE: None if state.since is None else encode_time(state.since),
            _META_LAST_SUMMARY: (
                None if state.last_summary_at is None else encode_time(state.last_summary_at)
            ),
            _META_SUMMARY_ID: state.summary_event_id,
            _META_SUMMARY_COUNT: str(state.summary_count),
        }
        for key, value in values.items():
            if value is None:
                connection.execute("DELETE FROM meta WHERE key = ?", (key,))
            else:
                connection.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value)
                )

    def _merge_journal(self, connection: sqlite3.Connection, now: datetime) -> None:
        # A journal that cannot be read fails the flush, so it is never cleared unmerged.
        entries, corrupt = self._journal.read()
        loaded = _Loaded()
        self._merge_journal_into(loaded, entries, corrupt, now)
        newer: list[DeliveryRecord] = []
        for record in loaded.deliveries.values():
            row = connection.execute(
                f"SELECT {_DELIVERY_COLUMNS} FROM delivery "  # noqa: S608  # constant column list
                "WHERE event_id = ? AND recipient = ?",
                record.key,
            ).fetchone()
            try:
                existing = None if row is None else _decode_delivery(tuple(row))
            except (ValueError, TypeError):
                existing = None
            if _newer(record, existing):
                newer.append(record)
        self._upsert_deliveries(connection, newer)
        self._insert_marks(connection, list(loaded.marks.values()))

    def _prune(self, connection: sqlite3.Connection, now: datetime) -> None:
        reference = now if self._last_seen is None else max(now, self._last_seen)
        connection.execute(
            f"DELETE FROM delivery WHERE status IN ({_TERMINAL_IN}) AND updated_at < ?",  # noqa: S608  # placeholders only
            (*_TERMINAL, encode_time(reference - self._retention)),
        )
        connection.execute(
            "DELETE FROM delivery WHERE rowid IN ("  # noqa: S608  # placeholders only
            f"SELECT rowid FROM delivery WHERE status IN ({_TERMINAL_IN}) "
            "ORDER BY updated_at DESC LIMIT -1 OFFSET ?)",
            (*_TERMINAL, self._max_records),
        )
        connection.execute(
            "DELETE FROM send_attempt WHERE id IN ("
            "SELECT id FROM send_attempt ORDER BY at DESC, id DESC LIMIT -1 OFFSET ?)",
            (MAX_ATTEMPT_ROWS,),
        )
        connection.execute(
            "DELETE FROM rule_state WHERE rule_id IN ("
            "SELECT rule_id FROM rule_state ORDER BY updated_at DESC LIMIT -1 OFFSET ?)",
            (MAX_RULE_STATES,),
        )

    # Files and failures ---------------------------------------------------------

    def _acquire(self) -> None:
        if self._lock is not None:
            return
        check_directory(self._directory)
        try:
            descriptor = open_private(self._lock_path, os.O_RDWR | os.O_CREAT)
        except OSError as exc:
            if exc.errno not in _READ_ONLY_ERRNOS:
                raise
            descriptor = open_private(self._lock_path, os.O_RDONLY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(descriptor)
            raise StateLockedError(  # noqa: TRY003  # per-check validation message
                "another relay process is using the state directory"
            ) from exc
        self._lock = descriptor

    def _connect(self) -> sqlite3.Connection:
        if self._connection is not None:
            return self._connection
        self._acquire()
        try:
            descriptor = open_private(self._path, os.O_RDWR | os.O_CREAT)
        except OSError as exc:
            if exc.errno not in _READ_ONLY_ERRNOS:
                raise
            descriptor = open_private(self._path, os.O_RDONLY)
        os.close(descriptor)
        self._secure_sidecars()
        connection = self._connect_fn(self._path)
        try:
            migrate(connection)
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            self._secure_sidecars()
        except BaseException:
            connection.close()
            raise
        self._connection = connection
        return connection

    def _secure_sidecars(self) -> None:
        for suffix in SIDECAR_SUFFIXES:
            secure_existing(self._path.with_name(self._path.name + suffix))

    def _fail(self, action: str, exc: BaseException) -> None:
        self._failing = True
        self._error = _describe(exc)
        logger.error(
            "state persistence failed",
            extra={"event": "state.persistence_failed", "action": action, "error": self._error},
        )
        if self._connection is not None:
            with suppress(sqlite3.Error):
                self._connection.close()
            self._connection = None

    def _recovered(self) -> None:
        if self._failing:
            logger.warning(
                "state persistence recovered", extra={"event": "state.persistence_recovered"}
            )
        self._failing = False
        self._error = None

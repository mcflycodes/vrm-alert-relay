"""SQLite persistence that degrades to in-memory operation instead of failing.

Every public method catches SQLite and filesystem errors, logs them at
``ERROR``, marks the store unhealthy, and returns a safe fallback: an empty
snapshot from :meth:`StateStore.load`, ``False`` from :meth:`StateStore.flush`.
The caller keeps its in-memory state and flushes again later; the next
successful flush marks the store healthy again. A failure therefore never
stops alerting and never crash-loops the process.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from datetime import datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Final

from vrm_alert_relay.engine import RuleState

from .models import (
    MAX_COUNTER,
    Changes,
    DeliveryKind,
    DeliveryRecord,
    DeliveryStatus,
    InvalidRecordError,
    Snapshot,
    Suppression,
    encode_time,
    is_aware,
    is_identifier,
)
from .schema import SchemaTooNewError, migrate

__all__ = [
    "ATTEMPT_WINDOW",
    "DB_FILENAME",
    "DEFAULT_MAX_RECORDS",
    "DEFAULT_RETENTION",
    "MAX_ATTEMPT_ROWS",
    "MAX_RULE_STATES",
    "Connect",
    "StateStore",
]

logger = logging.getLogger(__name__)

DB_FILENAME: Final = "relay-state.sqlite3"
DEFAULT_RETENTION: Final = timedelta(days=7)
DEFAULT_MAX_RECORDS: Final = 5000
MAX_RULE_STATES: Final = 1000
MAX_SUPPRESSED_ROWS: Final = 1000
ATTEMPT_WINDOW: Final = timedelta(days=1)
MAX_ATTEMPT_ROWS: Final = 10_000
MAX_STATE_JSON_LENGTH: Final = 64 * 1024
MAX_TIME_LENGTH: Final = 64
MAX_ERROR_LENGTH: Final = 200
BUSY_TIMEOUT_SECONDS: Final = 5.0

_META_SINCE: Final = "suppressed_since"
_META_LAST_SUMMARY: Final = "last_summary_at"
_TERMINAL: Final = tuple(status.value for status in DeliveryStatus if status.terminal)
_TERMINAL_IN: Final = ", ".join("?" for _ in _TERMINAL)
_FAILURES: Final = (sqlite3.Error, OSError, SchemaTooNewError)
_DELIVERY_COLUMNS: Final = (
    "event_id, recipient, kind, status, text, attempts, created_at, updated_at, "
    "next_attempt_at, last_attempt_at, provider_message_id"
)

type Connect = Callable[[Path], sqlite3.Connection]


def _default_connect(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path, timeout=BUSY_TIMEOUT_SECONDS, autocommit=True)


def _ensure_file(path: Path) -> None:
    """Create the database file owner-only if it does not exist yet."""
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    os.close(descriptor)


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


def _decode_time(raw: object) -> datetime:
    if not isinstance(raw, str) or len(raw) > MAX_TIME_LENGTH:
        raise InvalidRecordError("timestamp must be a bounded string")  # noqa: TRY003  # per-check validation message
    value = datetime.fromisoformat(raw)
    if not is_aware(value):
        raise InvalidRecordError("timestamp must be timezone-aware")  # noqa: TRY003  # per-check validation message
    return value


def _decode_optional_time(raw: object) -> datetime | None:
    return None if raw is None else _decode_time(raw)


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
        event_id=str(event_id),
        recipient=str(recipient),
        kind=DeliveryKind(str(kind)),
        status=DeliveryStatus(str(status)),
        text=text,  # type: ignore[arg-type]  # validated by DeliveryRecord
        attempts=attempts,  # type: ignore[arg-type]  # validated by DeliveryRecord
        created_at=_decode_time(created_at),
        updated_at=_decode_time(updated_at),
        next_attempt_at=_decode_optional_time(next_attempt_at),
        last_attempt_at=_decode_optional_time(last_attempt_at),
        provider_message_id=provider_message_id,  # type: ignore[arg-type]  # validated by DeliveryRecord
    )


def _encode_delivery(record: DeliveryRecord) -> tuple[object, ...]:
    return (
        record.event_id,
        record.recipient,
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


def _valid_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= MAX_COUNTER


class StateStore:
    """Durable relay state in ``<state_dir>/relay-state.sqlite3``.

    The database uses WAL journaling with ``synchronous=FULL`` so that a
    committed write survives a crash or power loss. Each :meth:`flush` is one
    transaction. Terminal delivery records are pruned by age and count, send
    attempts older than the longest rate window are dropped, and every table
    read at startup is read with a row limit.
    """

    def __init__(
        self,
        state_dir: Path,
        *,
        retention: timedelta = DEFAULT_RETENTION,
        max_records: int = DEFAULT_MAX_RECORDS,
        connect: Connect = _default_connect,
    ) -> None:
        if retention <= timedelta(0):
            raise ValueError("retention must be positive")  # noqa: TRY003  # per-check validation message
        if max_records < 1:
            raise ValueError("max_records must be at least 1")  # noqa: TRY003  # per-check validation message
        self._path = state_dir / DB_FILENAME
        self._retention = retention
        self._max_records = max_records
        self._connect_fn = connect
        self._connection: sqlite3.Connection | None = None
        self._healthy = True
        self._error: str | None = None

    @property
    def path(self) -> Path:
        return self._path

    @property
    def healthy(self) -> bool:
        """False after a failed read or write, until the next successful flush."""
        return self._healthy

    @property
    def error(self) -> str | None:
        """A short description of the latest persistence failure, without file paths."""
        return self._error

    def load(self) -> Snapshot:
        """Read all persisted state; corrupt rows are logged and skipped."""
        try:
            connection = self._connect()
            with _transaction(connection):
                snapshot = Snapshot(
                    rule_states=self._load_rule_states(connection),
                    deliveries=self._load_deliveries(connection),
                    attempts=self._load_attempts(connection),
                    suppression=self._load_suppression(connection),
                )
        except _FAILURES as exc:
            self._fail("load", exc)
            return Snapshot()
        self._recovered()
        return snapshot

    def flush(self, changes: Changes, now: datetime) -> bool:
        """Write ``changes`` and prune old rows in one transaction."""
        try:
            connection = self._connect()
            with _transaction(connection):
                self._write(connection, changes, now)
                self._prune(connection, now)
        except _FAILURES as exc:
            self._fail("flush", exc)
            return False
        self._recovered()
        return True

    def close(self) -> None:
        if self._connection is not None:
            with suppress(sqlite3.Error):
                self._connection.close()
            self._connection = None

    def _connect(self) -> sqlite3.Connection:
        if self._connection is not None:
            return self._connection
        _ensure_file(self._path)
        connection = self._connect_fn(self._path)
        try:
            migrate(connection)
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
        except BaseException:
            connection.close()
            raise
        self._connection = connection
        return connection

    def _fail(self, action: str, exc: BaseException) -> None:
        self._healthy = False
        self._error = _describe(exc)
        logger.error(
            "state persistence failed; delivery continues with in-memory state",
            extra={"event": "state.persistence_failed", "action": action, "error": self._error},
        )
        # Reconnect on the next attempt: the failure may have left the
        # connection unusable (for example a closed or replaced file).
        self.close()

    def _recovered(self) -> None:
        if not self._healthy:
            logger.warning(
                "state persistence recovered",
                extra={"event": "state.persistence_recovered"},
            )
        self._healthy = True
        self._error = None

    @staticmethod
    def _load_rule_states(connection: sqlite3.Connection) -> Mapping[str, RuleState]:
        states: dict[str, RuleState] = {}
        rows = connection.execute(
            "SELECT rule_id, state FROM rule_state ORDER BY updated_at DESC LIMIT ?",
            (MAX_RULE_STATES,),
        )
        for rule_id, raw in rows:
            try:
                key, state = _decode_rule_state(rule_id, raw)
            except (ValueError, RecursionError):
                logger.warning(
                    "discarding corrupt rule state; the rule starts from fresh state",
                    extra={
                        "event": "state.rule_state_corrupt",
                        "rule_id": rule_id if is_identifier(rule_id) else None,
                    },
                )
                continue
            states[key] = state
        return MappingProxyType(states)

    def _load_deliveries(self, connection: sqlite3.Connection) -> tuple[DeliveryRecord, ...]:
        records: list[DeliveryRecord] = []
        rows = connection.execute(
            f"SELECT {_DELIVERY_COLUMNS} FROM delivery "  # noqa: S608  # constant column list
            "ORDER BY updated_at DESC LIMIT ?",
            (self._max_records * 2,),
        )
        corrupt = 0
        for row in rows:
            try:
                records.append(_decode_delivery(tuple(row)))
            except (ValueError, TypeError):
                corrupt += 1
        if corrupt:
            logger.warning(
                "discarding corrupt delivery records",
                extra={"event": "state.delivery_corrupt", "count": corrupt},
            )
        records.reverse()
        return tuple(records)

    @staticmethod
    def _load_attempts(connection: sqlite3.Connection) -> tuple[datetime, ...]:
        attempts: list[datetime] = []
        rows = connection.execute(
            "SELECT at FROM send_attempt ORDER BY at DESC LIMIT ?", (MAX_ATTEMPT_ROWS,)
        )
        for (raw,) in rows:
            try:
                attempts.append(_decode_time(raw))
            except ValueError:
                # A corrupt row is dropped. The global cap may then allow
                # one extra send, which fails toward alerting.
                logger.warning(
                    "discarding a corrupt send-attempt row",
                    extra={"event": "state.attempt_corrupt"},
                )
        attempts.sort()
        return tuple(attempts)

    @staticmethod
    def _load_suppression(connection: sqlite3.Connection) -> Suppression:
        counts: dict[str, int] = {}
        rows = connection.execute(
            "SELECT recipient, count FROM suppressed LIMIT ?", (MAX_SUPPRESSED_ROWS,)
        )
        for recipient, count in rows:
            if is_identifier(recipient) and _valid_count(count):
                counts[recipient] = count
        meta = dict(connection.execute("SELECT key, value FROM meta").fetchall())
        times: dict[str, datetime | None] = {}
        for key in (_META_SINCE, _META_LAST_SUMMARY):
            try:
                times[key] = _decode_optional_time(meta.get(key))
            except ValueError:
                times[key] = None
        return Suppression(
            counts=MappingProxyType(counts),
            since=times[_META_SINCE],
            last_summary_at=times[_META_LAST_SUMMARY],
        )

    @staticmethod
    def _write(connection: sqlite3.Connection, changes: Changes, now: datetime) -> None:
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
        connection.executemany(
            f"INSERT OR REPLACE INTO delivery ({_DELIVERY_COLUMNS}) "  # noqa: S608  # constant column list
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [_encode_delivery(record) for record in changes.deliveries],
        )
        connection.executemany(
            "INSERT INTO send_attempt (at) VALUES (?)",
            [(encode_time(at),) for at in changes.attempts],
        )
        suppression = changes.suppression
        connection.execute("DELETE FROM suppressed")
        connection.executemany(
            "INSERT INTO suppressed (recipient, count) VALUES (?, ?)",
            [(name, count) for name, count in suppression.counts.items() if count > 0],
        )
        for key, value in (
            (_META_SINCE, suppression.since),
            (_META_LAST_SUMMARY, suppression.last_summary_at),
        ):
            if value is None:
                connection.execute("DELETE FROM meta WHERE key = ?", (key,))
            else:
                connection.execute(
                    "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                    (key, encode_time(value)),
                )

    def _prune(self, connection: sqlite3.Connection, now: datetime) -> None:
        connection.execute(
            f"DELETE FROM delivery WHERE status IN ({_TERMINAL_IN}) AND updated_at < ?",  # noqa: S608  # placeholders only
            (*_TERMINAL, encode_time(now - self._retention)),
        )
        connection.execute(
            "DELETE FROM delivery WHERE rowid IN ("  # noqa: S608  # placeholders only
            f"SELECT rowid FROM delivery WHERE status IN ({_TERMINAL_IN}) "
            "ORDER BY updated_at DESC LIMIT -1 OFFSET ?)",
            (*_TERMINAL, self._max_records),
        )
        connection.execute(
            "DELETE FROM send_attempt WHERE at <= ?", (encode_time(now - ATTEMPT_WINDOW),)
        )
        connection.execute(
            "DELETE FROM send_attempt WHERE id IN ("
            "SELECT id FROM send_attempt ORDER BY at DESC LIMIT -1 OFFSET ?)",
            (MAX_ATTEMPT_ROWS,),
        )
        connection.execute(
            "DELETE FROM rule_state WHERE rule_id IN ("
            "SELECT rule_id FROM rule_state ORDER BY updated_at DESC LIMIT -1 OFFSET ?)",
            (MAX_RULE_STATES,),
        )

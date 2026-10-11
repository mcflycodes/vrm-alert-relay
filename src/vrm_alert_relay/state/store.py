"""SQLite persistence that degrades instead of failing, with a fallback journal.

Every storage failure is logged at ``ERROR``, marks the store unhealthy, and
returns a safe fallback (``False`` from :meth:`StateStore.flush` and
:meth:`StateStore.journal`, partial data from :meth:`StateStore.load`), so
the caller keeps its in-memory state, keeps alerting, and tries again later.
The only startup failure that raises is :class:`StateLockedError`: another
relay process already owns the state directory and is alerting.

How an unreadable database is handled (ADR 0002):

* **Corrupt** (SQLite reports a malformed or non-database file): whatever is
  readable is salvaged, the file and its sidecars are moved aside to
  ``relay-state.sqlite3.corrupt-<time>``, and a fresh database is started.
  The caller rewrites everything it holds into it.
* **Otherwise unreadable** (permissions, I/O errors, a lock, a schema from a
  newer release, an unsafe path): the file is left untouched and no write is
  made to it. The caller runs on the journal and in-memory state, and
  :meth:`StateStore.reload` reads the database again on every cycle.

Nothing that limits sending is thrown away: unreadable send-attempt rows
become attempts at load time, unreadable unfinished deliveries are recovered
as ambiguous or reset their rule, and no cell is read beyond its bound.
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
from datetime import UTC, datetime, timedelta
from enum import Enum
from functools import partial
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from vrm_alert_relay.engine import RuleState

from .journal import MAX_COMPACTED_BYTES, MAX_JOURNAL_BYTES, AttemptJournal, JournalContents
from .models import (
    MAX_ATTEMPTS,
    MAX_COUNTER,
    MAX_IDENTIFIER_LENGTH,
    MAX_MESSAGE_LENGTH,
    MAX_PROVIDER_MESSAGE_ID_LENGTH,
    MAX_TIME_LENGTH,
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
    check_identity,
    identity_of,
    open_descriptors,
    open_private,
    secure_existing,
)
from .schema import SchemaTooNewError, migrate

if TYPE_CHECKING:
    from .paths import FileIdentity

__all__ = [
    "ATTEMPT_WINDOW",
    "DB_FILENAME",
    "DEFAULT_MAX_RECORDS",
    "DEFAULT_RETENTION",
    "LOCK_FILENAME",
    "MAX_ATTEMPT_ROWS",
    "MAX_RULE_STATES",
    "QUARANTINE_INFIX",
    "UNREADABLE_TEXT",
    "Connect",
    "StateStore",
]

logger = logging.getLogger(__name__)

DB_FILENAME: Final = "relay-state.sqlite3"
LOCK_FILENAME: Final = "relay-state.lock"
QUARANTINE_INFIX: Final = ".corrupt-"
DEFAULT_RETENTION: Final = timedelta(days=7)
DEFAULT_MAX_RECORDS: Final = 5000
MAX_RULE_STATES: Final = 1000
ATTEMPT_WINDOW: Final = timedelta(days=1)
MAX_ATTEMPT_ROWS: Final = 10_000
MAX_STATE_JSON_LENGTH: Final = 64 * 1024
MAX_META_LENGTH: Final = 256
MAX_ENUM_LENGTH: Final = 32
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
_SQLITE_CORRUPT: Final = 11
_SQLITE_NOTADB: Final = 26
_UTF8_MAX_BYTES: Final = 4


def _bounded(column: str, max_chars: int | None) -> tuple[str, str | None]:
    """A select expression that never reads more than ``max_chars``, and its oversize test.

    SQLite reads a TEXT cell's size from the record header, so ``octet_length``
    does not load the cell; the cell itself is read only when it is in bounds.
    """
    if max_chars is None:
        return column, None
    limit = max_chars * _UTF8_MAX_BYTES
    return (
        f"CASE WHEN octet_length({column}) <= {limit:d} THEN {column} END",
        f"octet_length({column}) > {limit:d}",
    )


def _bounded_select(columns: tuple[tuple[str, int | None], ...]) -> str:
    """Bounded expressions for ``columns``, then one flag: whether any cell was too large."""
    parts = [_bounded(name, bound) for name, bound in columns]
    tests = [test for _, test in parts if test is not None]
    return ", ".join([expression for expression, _ in parts] + [f"({' OR '.join(tests)})"])


_DELIVERY_COLUMNS: Final = (
    ("event_id", MAX_IDENTIFIER_LENGTH),
    ("recipient", MAX_IDENTIFIER_LENGTH),
    ("rule_id", MAX_IDENTIFIER_LENGTH),
    ("kind", MAX_ENUM_LENGTH),
    ("status", MAX_ENUM_LENGTH),
    ("text", MAX_MESSAGE_LENGTH),
    ("attempts", None),
    ("created_at", MAX_TIME_LENGTH),
    ("updated_at", MAX_TIME_LENGTH),
    ("next_attempt_at", MAX_TIME_LENGTH),
    ("last_attempt_at", MAX_TIME_LENGTH),
    ("provider_message_id", MAX_PROVIDER_MESSAGE_ID_LENGTH),
    ("covers", None),
)
_DELIVERY_NAMES: Final = ", ".join(name for name, _ in _DELIVERY_COLUMNS)
_DELIVERY_SELECT: Final = _bounded_select(_DELIVERY_COLUMNS)
_ATTEMPT_SELECT: Final = _bounded_select(
    (
        ("event_id", MAX_IDENTIFIER_LENGTH),
        ("recipient", MAX_IDENTIFIER_LENGTH),
        ("attempt", None),
        ("at", MAX_TIME_LENGTH),
    )
)
_RULE_STATE_SELECT: Final = _bounded_select(
    (("rule_id", MAX_IDENTIFIER_LENGTH), ("state", MAX_STATE_JSON_LENGTH))
)
_META_SELECT: Final = _bounded_select((("key", MAX_META_LENGTH), ("value", MAX_META_LENGTH)))

type Connect = Callable[[Path], sqlite3.Connection]


def _default_connect(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path, timeout=BUSY_TIMEOUT_SECONDS, autocommit=True)


@contextmanager
def _transaction(connection: sqlite3.Connection, begin: str = "BEGIN IMMEDIATE") -> Iterator[None]:
    connection.execute(begin)
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


def _is_corrupt(exc: BaseException) -> bool:
    """Whether SQLite says the file itself is malformed, as opposed to unreachable."""
    code = getattr(exc, "sqlite_errorcode", None)
    return isinstance(code, int) and code & 0xFF in (_SQLITE_CORRUPT, _SQLITE_NOTADB)


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
        covers,
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
        covers=covers,  # type: ignore[arg-type]  # validated by DeliveryRecord
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
        record.covers,
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
    event_id, recipient, attempt, at = row
    return AttemptMark(
        event_id=event_id,  # type: ignore[arg-type]  # validated by AttemptMark
        recipient=recipient,  # type: ignore[arg-type]  # validated by AttemptMark
        attempt=attempt,  # type: ignore[arg-type]  # validated by AttemptMark
        at=decode_time(at),
    )


def _newer(candidate: DeliveryRecord, existing: DeliveryRecord | None) -> bool:
    return existing is None or candidate.progress() > existing.progress()


def _unreadable_mark(label: str, index: int, at: datetime) -> AttemptMark:
    """A slot for a send whose record cannot be read."""
    stamp = int(at.timestamp() * 1_000_000)
    return AttemptMark(f"{label}_unreadable_{stamp}_{index}", "unknown", 0, at)


class _Read(Enum):
    """How a read of the database went."""

    OK = "ok"
    UNREADABLE = "unreadable"
    """Left untouched; read again later."""
    CORRUPT = "corrupt"
    """Malformed; moved aside and replaced."""


@dataclass(slots=True)
class _Loaded:
    """What a load read, and the repairs to write back afterwards."""

    rule_states: dict[str, RuleState] = field(default_factory=dict)
    deliveries: dict[tuple[str, str], DeliveryRecord] = field(default_factory=dict)
    marks: dict[tuple[str, str, int], AttemptMark] = field(default_factory=dict)
    suppression: SuppressionState = field(default_factory=SuppressionState)
    suppression_read: bool = False
    last_seen: datetime | None = None
    problems: int = 0
    unrecoverable: int = 0
    invalidated_rules: set[str] = field(default_factory=set)
    repaired: list[DeliveryRecord] = field(default_factory=list)
    delete_delivery_rows: list[int] = field(default_factory=list)
    replace_attempt_rows: list[tuple[int, AttemptMark]] = field(default_factory=list)
    expired_attempt_rows: list[int] = field(default_factory=list)
    failures: list[BaseException] = field(default_factory=list)


class StateStore:
    """Durable relay state in a lock-protected state directory.

    Files: ``relay-state.sqlite3`` (WAL, ``synchronous=FULL``), its SQLite
    sidecars, ``relay-state.lock``, and the fallback journal
    ``relay-state.journal`` (see :class:`~vrm_alert_relay.state.journal.AttemptJournal`).
    Every file is a regular, owner-only (0600) file opened without following
    symlinks, and the database and lock file are checked to be the files
    that were validated. The state directory must be on a local filesystem:
    ``flock`` and SQLite's WAL mode are not reliable on network filesystems.
    Each :meth:`flush` is one transaction; a successful flush also merges the
    journal into SQLite and then removes it.
    """

    def __init__(  # noqa: PLR0913  # keyword-only bounds and the connection factory
        self,
        state_dir: Path,
        *,
        retention: timedelta = DEFAULT_RETENTION,
        max_records: int = DEFAULT_MAX_RECORDS,
        journal_max_bytes: int = MAX_JOURNAL_BYTES,
        journal_max_compacted_bytes: int = MAX_COMPACTED_BYTES,
        connect: Connect = _default_connect,
    ) -> None:
        if retention <= timedelta(0):
            raise ValueError("retention must be positive")  # noqa: TRY003  # per-check validation message
        if max_records < 1:
            raise ValueError("max_records must be at least 1")  # noqa: TRY003  # per-check validation message
        self._directory = state_dir
        self._path = state_dir / DB_FILENAME
        self._lock_path = state_dir / LOCK_FILENAME
        self._journal = AttemptJournal(
            state_dir, max_bytes=journal_max_bytes, max_compacted_bytes=journal_max_compacted_bytes
        )
        self._retention = retention
        self._max_records = max_records
        self._connect_fn = connect
        self._connection: sqlite3.Connection | None = None
        self._lock: int | None = None
        self._failing = False
        self._error: str | None = None
        self._problems = 0
        self._reset = False
        self._deferred = False
        self._journal_pending = False
        self._journal_read = False
        self._journal_adjusted = False
        self._last_seen: datetime | None = None

    @property
    def path(self) -> Path:
        return self._path

    @property
    def healthy(self) -> bool:
        """False while storage fails, and for the rest of the run once state was corrupt."""
        return not self._failing and self._problems == 0 and not self._reset

    @property
    def readable(self) -> bool:
        """False while the database or the journal could not be read."""
        return not self._deferred and self._journal_read

    @property
    def error(self) -> str | None:
        """A short description of the latest problem, without file paths."""
        if self._error is None and self._reset:
            return "corrupt database moved aside; state started afresh"
        if self._error is None and self._problems:
            return f"corrupt state: {self._problems} unreadable rows or journal lines"
        return self._error

    # Startup ------------------------------------------------------------------

    def load(self, now: datetime) -> Snapshot:
        """Lock the state directory and read everything that can be read.

        Raises :class:`StateLockedError` when another process holds the
        directory. Every other failure is logged and leaves the store
        unhealthy; an unreadable database is left untouched and a corrupt one
        is moved aside (see the module docstring).
        """
        try:
            self._acquire()
        except StateLockedError:
            raise
        except (OSError, UnsafeStateError) as exc:
            self._fail("lock", exc)
        loaded = _Loaded()
        outcome = self._read_database(now, loaded)
        self._read_journal(loaded, now)
        return self._finish_read(loaded, now, outcome)

    def reload(self, now: datetime) -> Snapshot | None:
        """Read what could not be read before; None while some of it still cannot be.

        The database is read again only if it was unreadable, and the journal
        is read again in full. Journal suppression changes are applied only
        by the first successful read of the journal.
        """
        loaded = _Loaded()
        outcome = self._read_database(now, loaded) if self._deferred else _Read.OK
        if outcome is _Read.UNREADABLE:
            return None
        self._read_journal(loaded, now)
        if not self._journal_read:
            return None
        logger.warning("stored state is readable again", extra={"event": "state.readable"})
        return self._finish_read(loaded, now, outcome)

    def _finish_read(self, loaded: _Loaded, now: datetime, outcome: _Read) -> Snapshot:
        if loaded.problems:
            self._problems += loaded.problems
            logger.error(
                "corrupt state was found and handled conservatively",
                extra={"event": "state.corrupt", "count": loaded.problems},
            )
        reset = False
        if outcome is _Read.CORRUPT:
            reset = self._quarantine(now)
            outcome = _Read.OK if reset else _Read.UNREADABLE
        self._deferred = outcome is _Read.UNREADABLE
        if outcome is _Read.OK and not reset:
            self._repair(loaded, now)
        if loaded.last_seen is not None:
            self._last_seen = max(loaded.last_seen, self._last_seen or loaded.last_seen)
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
            complete=outcome is _Read.OK and self._journal_read,
            suppression=loaded.suppression,
            suppression_read=loaded.suppression_read,
            last_seen=loaded.last_seen,
            clock_moved_backwards=backwards,
            problems=loaded.problems,
            reset=reset,
        )

    def _read_database(self, now: datetime, loaded: _Loaded) -> _Read:
        """Read each table in its own transaction, so one failure hides nothing else."""
        try:
            connection = self._connect()
        except _RUNTIME_FAILURES as exc:
            self._fail("load", exc)
            return _Read.CORRUPT if _is_corrupt(exc) else _Read.UNREADABLE
        if self._read_table(connection, loaded, "load_meta", partial(self._read_meta, connection)):
            loaded.suppression_read = True
        # Without the last-seen time, a backwards clock cannot be ruled out.
        prune = loaded.suppression_read and not (
            loaded.last_seen is not None and now < loaded.last_seen
        )
        readers: tuple[tuple[str, Callable[[_Loaded], None]], ...] = (
            ("load_deliveries", partial(self._read_deliveries, connection, now)),
            ("load_rule_states", partial(self._read_rule_states, connection)),
            ("load_attempts", partial(self._read_attempts, connection, now, prune=prune)),
        )
        for action, reader in readers:
            self._read_table(connection, loaded, action, reader)
        if not loaded.failures:
            return _Read.OK
        self._close_connection()
        if any(_is_corrupt(exc) for exc in loaded.failures):
            return _Read.CORRUPT
        return _Read.UNREADABLE

    def _read_table(
        self,
        connection: sqlite3.Connection,
        loaded: _Loaded,
        action: str,
        reader: Callable[[_Loaded], None],
    ) -> bool:
        try:
            with _transaction(connection, "BEGIN"):
                reader(loaded)
        except sqlite3.Error as exc:
            loaded.failures.append(exc)
            self._note_failure(action, exc)
            return False
        return True

    def _read_journal(self, loaded: _Loaded, now: datetime) -> None:
        try:
            contents = self._journal.read()
        except (OSError, UnsafeStateError) as exc:
            # Attempts may be recorded only there: the history is incomplete.
            self._journal_read = False
            self._fail("journal_read", exc)
            return
        self._journal_read = True
        adjust = not self._journal_adjusted
        self._journal_adjusted = True
        self._merge_journal_into(loaded, contents, now, adjust_suppression=adjust)
        self._journal_pending = bool(contents.entries or contents.unreadable)

    @staticmethod
    def _clamped(loaded: _Loaded, now: datetime) -> tuple[AttemptMark, ...]:
        marks = (
            mark if mark.at <= now else AttemptMark(*mark.key, at=now)
            for mark in loaded.marks.values()
        )
        return tuple(sorted(marks, key=lambda mark: (mark.at, mark.key)))

    @staticmethod
    def _read_meta(connection: sqlite3.Connection, loaded: _Loaded) -> None:
        meta: dict[object, object] = {}
        for key, value, oversize in connection.execute(
            f"SELECT {_META_SELECT} FROM meta LIMIT 100"  # noqa: S608  # constant expressions
        ):
            if oversize:
                loaded.problems += 1
                value = ""  # noqa: PLW2901  # an unreadable value, never the stored one
            meta[key] = value

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
            summary_event_id=None if summary_id is None else str(summary_id),
            summary_count=count_of(_META_SUMMARY_COUNT, 0),
        )

    def _read_deliveries(
        self, connection: sqlite3.Connection, now: datetime, loaded: _Loaded
    ) -> None:
        # Unfinished records first, so the row limit can only ever cut finished ones.
        select = f"SELECT rowid, {_DELIVERY_SELECT} FROM delivery "  # noqa: S608  # constant columns
        queries = (
            f"{select}WHERE status NOT IN ({_TERMINAL_IN}) ORDER BY rowid LIMIT ?",
            f"{select}WHERE status IN ({_TERMINAL_IN}) ORDER BY updated_at DESC LIMIT ?",
        )
        for query in queries:
            for row in connection.execute(query, (*_TERMINAL, self._max_records * 2)):
                rowid, *columns, oversize = row
                try:
                    if oversize:
                        raise InvalidRecordError("a cell is larger than its bound")  # noqa: TRY003  # handled below like any corrupt row
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
        created_at, _, _, last_attempt_at, provider_message_id, covers = columns[7:]
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
                covers=covers if isinstance(covers, int) and is_counter(covers) else 0,
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
            loaded.rule_states.pop(str(rule), None)
        else:
            loaded.unrecoverable += 1

    @staticmethod
    def _read_rule_states(connection: sqlite3.Connection, loaded: _Loaded) -> None:
        rows = connection.execute(
            f"SELECT {_RULE_STATE_SELECT} FROM rule_state ORDER BY updated_at DESC LIMIT ?",  # noqa: S608  # constant expressions
            (MAX_RULE_STATES,),
        )
        for rule_id, raw, oversize in rows:
            try:
                if oversize:
                    raise InvalidRecordError("a cell is larger than its bound")  # noqa: TRY003  # handled below like any corrupt row
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
            f"SELECT id, {_ATTEMPT_SELECT} FROM send_attempt ORDER BY id DESC LIMIT ?",  # noqa: S608  # constant expressions
            (MAX_ATTEMPT_ROWS,),
        )
        for rowid, *columns, oversize in rows:
            try:
                if oversize:
                    raise InvalidRecordError("a cell is larger than its bound")  # noqa: TRY003  # handled below like any corrupt row
                mark = _decode_mark(tuple(columns))
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
        loaded: _Loaded, contents: JournalContents, now: datetime, *, adjust_suppression: bool
    ) -> None:
        """Merge journal lines into what the database held.

        With ``adjust_suppression``, suppression changes that only the journal
        holds are applied once each, keyed by delivery identity: a delivery
        held back adds one unless the database already shows it held back,
        and a delivered summary subtracts what it reported unless the
        database already shows it delivered.
        """
        base = dict(loaded.deliveries)
        held: dict[tuple[str, str], datetime] = {}
        reported: dict[str, int] = {}
        for entry in contents.entries:
            record = entry.record
            if _newer(record, loaded.deliveries.get(record.key)):
                loaded.deliveries[record.key] = record
            mark = entry.mark()
            if mark is not None:
                loaded.marks.setdefault(mark.key, mark)
            if record.kind is DeliveryKind.EVENT and record.status is DeliveryStatus.SUPPRESSED:
                stored = base.get(record.key)
                if stored is None or stored.status is not DeliveryStatus.SUPPRESSED:
                    held.setdefault(record.key, record.updated_at)
            elif record.kind is DeliveryKind.SUMMARY and record.status is DeliveryStatus.DELIVERED:
                reported.setdefault(record.event_id, record.covers)
        for index, at in enumerate(contents.unreadable):
            mark = _unreadable_mark("journal", index, at or now)
            loaded.marks[mark.key] = mark
        loaded.problems += contents.corrupt
        if not adjust_suppression or not (held or reported):
            return
        already = {
            record.event_id
            for record in base.values()
            if record.kind is DeliveryKind.SUMMARY and record.status is DeliveryStatus.DELIVERED
        }
        acknowledged = {event: n for event, n in reported.items() if event not in already}
        state = loaded.suppression
        count = min(max(state.count + len(held) - sum(acknowledged.values()), 0), MAX_COUNTER)
        settled = state.summary_event_id in acknowledged
        earliest = min(held.values(), default=now)
        loaded.suppression = SuppressionState(
            count=count,
            since=None if count == 0 else state.since or min(earliest, now),
            last_summary_at=state.last_summary_at,
            summary_event_id=None if settled else state.summary_event_id,
            summary_count=0 if settled else state.summary_count,
        )

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

    def _quarantine(self, now: datetime) -> bool:
        """Move a corrupt database and its sidecars aside, keeping them; True if done."""
        self._close_connection()
        stamp = now.astimezone(UTC).strftime("%Y%m%dT%H%M%S%fZ")
        target = self._path.with_name(f"{DB_FILENAME}{QUARANTINE_INFIX}{stamp}")
        suffix = 0
        while target.exists() or target.is_symlink():
            suffix += 1
            target = self._path.with_name(f"{DB_FILENAME}{QUARANTINE_INFIX}{stamp}-{suffix}")
        try:
            self._acquire()
            secure_existing(self._path)
            for extra in SIDECAR_SUFFIXES:
                source = self._path.with_name(DB_FILENAME + extra)
                secure_existing(source)
                if source.exists():
                    source.replace(target.with_name(target.name + extra))
            self._path.replace(target)
            self._sync_directory()
        except _RUNTIME_FAILURES as exc:
            self._fail("quarantine", exc)
            return False
        self._reset = True
        logger.error(
            "the database was corrupt; it was moved aside and state started afresh",
            extra={"event": "state.quarantined", "file": target.name},
        )
        return True

    # Writes -------------------------------------------------------------------

    def flush(self, changes: Changes, now: datetime) -> bool:
        """Write ``changes``, merge any journal, and prune old rows in one transaction.

        Returns False, without touching the database, while it could not be read.
        """
        if self._deferred:
            return False
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

    def journal(self, entries: tuple[JournalEntry, ...], now: datetime) -> bool:
        """Durably append ``entries`` to the fallback journal; False if impossible."""
        try:
            self._acquire()
            self._journal.append(entries, now)
        except _RUNTIME_FAILURES as exc:
            self._fail("journal", exc)
            return False
        self._journal_pending = True
        return True

    def close(self) -> None:
        """Close the database and release the state-directory lock."""
        self._close_connection()
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
            f"INSERT OR REPLACE INTO delivery ({_DELIVERY_NAMES}) "  # noqa: S608  # constant column list
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [_encode_delivery(record) for record in records],
        )

    @staticmethod
    def _insert_marks(
        connection: sqlite3.Connection, marks: list[AttemptMark] | tuple[AttemptMark, ...]
    ) -> None:
        # Dry-run sends are never stored, so they cannot displace real ones.
        connection.executemany(
            "INSERT OR IGNORE INTO send_attempt (event_id, recipient, attempt, at) "
            "VALUES (?, ?, ?, ?)",
            [(*mark.key, encode_time(mark.at)) for mark in marks if mark.live],
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
        contents = self._journal.read()
        loaded = _Loaded()
        self._merge_journal_into(loaded, contents, now, adjust_suppression=False)
        newer: list[DeliveryRecord] = []
        for record in loaded.deliveries.values():
            row = connection.execute(
                f"SELECT {_DELIVERY_SELECT} FROM delivery "  # noqa: S608  # constant column list
                "WHERE event_id = ? AND recipient = ?",
                record.key,
            ).fetchone()
            try:
                existing = None if row is None or row[-1] else _decode_delivery(tuple(row[:-1]))
            except (ValueError, TypeError):
                existing = None
            if _newer(record, existing):
                newer.append(record)
        self._upsert_deliveries(connection, newer)
        self._insert_marks(connection, list(loaded.marks.values()))

    def _prune(self, connection: sqlite3.Connection, now: datetime) -> None:
        reference = now if self._last_seen is None else max(now, self._last_seen)
        cutoff = encode_time(reference - self._retention)
        connection.execute(
            f"DELETE FROM delivery WHERE status IN ({_TERMINAL_IN}) AND updated_at < ?",  # noqa: S608  # placeholders only
            (*_TERMINAL, cutoff),
        )
        # A notice is history only, whatever its status: it is never sent again.
        connection.execute(
            "DELETE FROM delivery WHERE kind = ? AND updated_at < ?",
            (DeliveryKind.NOTICE.value, cutoff),
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
            check_identity(self._lock_path, identity_of(self._lock))
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
            check_identity(self._lock_path, identity_of(descriptor))
        except BlockingIOError as exc:
            os.close(descriptor)
            raise StateLockedError(  # noqa: TRY003  # per-check validation message
                "another relay process is using the state directory"
            ) from exc
        except BaseException:
            os.close(descriptor)
            raise
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
        try:
            expected = identity_of(descriptor)
            self._secure_sidecars()
            before = open_descriptors()
            connection = self._connect_fn(self._path)
            try:
                self._check_opened(expected, before)
                migrate(connection)
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("PRAGMA synchronous = FULL")
                self._secure_sidecars()
            except BaseException:
                connection.close()
                raise
        finally:
            os.close(descriptor)
        self._connection = connection
        return connection

    def _check_opened(self, expected: FileIdentity, before: dict[int, FileIdentity] | None) -> None:
        """Make sure SQLite opened the file that was validated, not a swapped-in one."""
        check_identity(self._path, expected)
        after = open_descriptors()
        if before is None or after is None:
            return
        opened = [ident for fd, ident in after.items() if before.get(fd) != ident]
        if any(ident != expected for ident in opened):
            raise UnsafeStateError("the database path was replaced while it was opened")  # noqa: TRY003  # per-check validation message

    def _secure_sidecars(self) -> None:
        for suffix in SIDECAR_SUFFIXES:
            secure_existing(self._path.with_name(self._path.name + suffix))

    def _sync_directory(self) -> None:
        descriptor = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _note_failure(self, action: str, exc: BaseException) -> None:
        self._failing = True
        self._error = _describe(exc)
        logger.error(
            "state persistence failed",
            extra={"event": "state.persistence_failed", "action": action, "error": self._error},
        )

    def _fail(self, action: str, exc: BaseException) -> None:
        self._note_failure(action, exc)
        self._close_connection()

    def _close_connection(self) -> None:
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

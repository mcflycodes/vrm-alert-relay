"""An append-only fallback record of deliveries and send attempts, for when SQLite fails.

Each line is one JSON object ``{"v": 1, "attempt": bool, "record": {...}}``.
An attempt line is appended and ``fsync``-ed before the provider call it
records, so every complete attempt line is evidence of a real send that may
have happened. A torn final line (a crash mid-write) was never followed by a
send and is ignored.

The file never rotates evidence away. When it would grow past its size bound
it is compacted: rewritten, atomically, to the latest line for each delivery
plus every attempt line younger than the 24-hour rate window. A line that
cannot be read becomes a ``{"v": 1, "unreadable": "<time>"}`` placeholder
that keeps its rate-window slot until that window has passed. The compacted
size is bounded by :data:`MAX_COMPACTED_BYTES`, which holds the attempt lines
of the largest valid daily cap many times over; if a failure mode ever
produces more, the newest evidence is kept and the loss is logged.
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Final

from .models import DeliveryRecord, InvalidRecordError, JournalEntry, decode_time, encode_time
from .paths import open_private

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import datetime
    from pathlib import Path

__all__ = [
    "JOURNAL_FILENAME",
    "MAX_COMPACTED_BYTES",
    "MAX_JOURNAL_BYTES",
    "MAX_LINE_BYTES",
    "AttemptJournal",
    "JournalContents",
    "decode_line",
    "encode_entry",
]

logger = logging.getLogger(__name__)

JOURNAL_FILENAME: Final = "relay-state.journal"
JOURNAL_VERSION: Final = 1
MAX_JOURNAL_BYTES: Final = 4 * 1024 * 1024
MAX_LINE_BYTES: Final = 16 * 1024
EVIDENCE_WINDOW: Final = timedelta(days=1)
MAX_LIVE_SENDS_PER_DAY: Final = 1000
"""The largest valid ``rate_limits.global_per_day``; see the configuration models."""
MAX_COMPACTED_BYTES: Final = 4 * MAX_LIVE_SENDS_PER_DAY * MAX_LINE_BYTES
"""Room for four full days of attempt lines at the largest valid cap and line size."""


def encode_entry(entry: JournalEntry) -> bytes:
    line = json.dumps(
        {"v": JOURNAL_VERSION, "attempt": entry.attempt, "record": entry.record.to_json()},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return line + b"\n"


def _encode_unreadable(at: datetime) -> bytes:
    return (
        json.dumps({"v": JOURNAL_VERSION, "unreadable": encode_time(at)}, separators=(",", ":"))
        + "\n"
    ).encode("ascii")


def decode_line(line: bytes) -> JournalEntry:
    """Validate one journal line; raises ``ValueError`` when it is malformed."""
    if len(line) > MAX_LINE_BYTES:
        raise InvalidRecordError("journal line is too long")  # noqa: TRY003  # per-check validation message
    data = json.loads(line)
    if (
        not isinstance(data, dict)
        or set(data) != {"v", "attempt", "record"}
        or data["v"] != JOURNAL_VERSION
        or not isinstance(data["attempt"], bool)
    ):
        raise InvalidRecordError("journal line has the wrong shape")  # noqa: TRY003  # per-check validation message
    return JournalEntry(record=DeliveryRecord.from_json(data["record"]), attempt=data["attempt"])


def _decode_unreadable(line: bytes) -> datetime | None:
    """The time of an unreadable-line placeholder, or None if ``line`` is not one."""
    try:
        data = json.loads(line)
        if isinstance(data, dict) and set(data) == {"v", "unreadable"} and data["v"] == 1:
            return decode_time(data["unreadable"])
    except (ValueError, TypeError, RecursionError):
        pass
    return None


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]


@dataclass(slots=True)
class JournalContents:
    """What a read found, oldest first."""

    entries: list[JournalEntry] = field(default_factory=list)
    unreadable: list[datetime | None] = field(default_factory=list)
    """One item per unreadable line: the placeholder's time, or None for a newly found one."""

    @property
    def corrupt(self) -> int:
        """Unreadable lines found by this read (placeholders were counted before)."""
        return sum(1 for at in self.unreadable if at is None)


@dataclass(slots=True)
class _Line:
    raw: bytes
    entry: JournalEntry | None
    unreadable_at: datetime | None = None


class AttemptJournal:
    """The journal file in one state directory."""

    def __init__(
        self,
        directory: Path,
        *,
        max_bytes: int = MAX_JOURNAL_BYTES,
        max_compacted_bytes: int = MAX_COMPACTED_BYTES,
    ) -> None:
        self._directory = directory
        self._path = directory / JOURNAL_FILENAME
        self._temporary = directory / f"{JOURNAL_FILENAME}.tmp"
        self._max_bytes = max_bytes
        self._max_compacted = max_compacted_bytes
        self._floor = 0

    @property
    def path(self) -> Path:
        return self._path

    @property
    def _read_limit(self) -> int:
        return 2 * max(self._max_bytes, self._max_compacted) + MAX_LINE_BYTES

    def append(self, entries: Sequence[JournalEntry], now: datetime) -> None:
        """Append ``entries`` durably; raises ``OSError`` when that is impossible."""
        data = b"".join(encode_entry(entry) for entry in entries)
        if self._needs_compaction(len(data)):
            self._compact(now)
        descriptor = open_private(self._path, os.O_RDWR | os.O_APPEND | os.O_CREAT)
        try:
            size = os.fstat(descriptor).st_size
            if size and os.pread(descriptor, 1, size - 1) != b"\n":
                data = b"\n" + data  # Never glue a line onto a torn one.
            _write_all(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if size == 0:
            self._sync_directory()

    def _needs_compaction(self, extra: int) -> bool:
        try:
            descriptor = open_private(self._path, os.O_RDONLY)
        except FileNotFoundError:
            return False
        try:
            size = os.fstat(descriptor).st_size
        finally:
            os.close(descriptor)
        # Compact at the size bound, but not again until the file has doubled,
        # so a journal full of evidence that must be kept is not rewritten on
        # every append.
        trigger = min(max(self._max_bytes, 2 * self._floor), self._read_limit - MAX_LINE_BYTES)
        return size > 0 and size + extra > trigger

    def _compact(self, now: datetime) -> None:
        """Rewrite the journal to what still matters, atomically."""
        lines = self._lines()
        latest = _latest_lines(lines)
        evidence: list[int] = []
        others: list[int] = []
        for index, line in enumerate(lines):
            at = _evidence_time(line, now)
            if at is not None and at > now - EVIDENCE_WINDOW:
                evidence.append(index)
            elif index in latest:
                others.append(index)
        kept: set[int] = set()
        budget = self._max_compacted
        dropped = 0
        # Newest first: evidence of sends, then the latest state of each delivery.
        for group in (evidence, others):
            for index in reversed(group):
                size = len(_encoded(lines[index], now))
                if size <= budget:
                    kept.add(index)
                    budget -= size
                elif group is evidence:
                    dropped += 1
        if dropped:
            logger.error(
                "the journal cannot hold every recent send; the oldest evidence was dropped",
                extra={"event": "state.journal_evidence_dropped", "count": dropped},
            )
        data = b"".join(_encoded(lines[index], now) for index in sorted(kept))
        self._replace(data)
        self._floor = len(data)

    def _replace(self, data: bytes) -> None:
        with suppress(FileNotFoundError):
            self._temporary.unlink()
        descriptor = open_private(self._temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            _write_all(descriptor, data)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._temporary.replace(self._path)
        self._sync_directory()

    def read(self) -> JournalContents:
        """Return the valid entries and the unreadable lines, oldest first."""
        contents = JournalContents()
        for line in self._lines():
            if line.entry is not None:
                contents.entries.append(line.entry)
            else:
                contents.unreadable.append(line.unreadable_at)
        return contents

    def _lines(self) -> list[_Line]:
        try:
            descriptor = open_private(self._path, os.O_RDONLY)
        except FileNotFoundError:
            return []
        lines: list[_Line] = []
        with os.fdopen(descriptor, "rb") as handle:
            data = handle.read(self._read_limit)
            if handle.read(1):
                # Oversized: what is beyond the bound is not trusted.
                lines.append(_Line(b"", None))
        raw_lines = data.split(b"\n")
        if raw_lines.pop():
            logger.warning(
                "ignoring a torn final journal line; no send followed it",
                extra={"event": "state.journal_torn"},
            )
        for raw in raw_lines:
            if not raw:
                continue
            try:
                lines.append(_Line(raw, decode_line(raw)))
            except (ValueError, TypeError, RecursionError):
                lines.append(_Line(raw, None, _decode_unreadable(raw)))
        return lines

    def clear(self) -> None:
        try:
            self._path.unlink()
        except FileNotFoundError:
            return
        self._floor = 0
        self._sync_directory()

    def _sync_directory(self) -> None:
        descriptor = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _latest_lines(lines: list[_Line]) -> set[int]:
    """The index of the newest version of each delivery."""
    latest: dict[tuple[str, str], tuple[tuple[int, int, datetime], int]] = {}
    for index, line in enumerate(lines):
        if line.entry is None:
            continue
        progress = line.entry.record.progress()
        previous = latest.get(line.entry.record.key)
        if previous is None or progress >= previous[0]:
            latest[line.entry.record.key] = (progress, index)
    return {index for _, index in latest.values()}


def _evidence_time(line: _Line, now: datetime) -> datetime | None:
    """When a line's rate-window slot started, if it holds one."""
    if line.entry is None:
        # A newly found unreadable line holds a slot from now.
        return line.unreadable_at or now
    mark = line.entry.mark()
    return None if mark is None else mark.at


def _encoded(line: _Line, now: datetime) -> bytes:
    if line.entry is not None:
        return line.raw + b"\n"
    return _encode_unreadable(line.unreadable_at or now)

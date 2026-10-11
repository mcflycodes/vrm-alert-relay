"""An append-only fallback record of send attempts, for when SQLite cannot be written.

Each line is one JSON object ``{"v": 1, "attempt": bool, "record": {...}}``.
A line is appended and ``fsync``-ed before the provider call it records, so
every complete line is evidence of an attempt that may have been sent. A
torn final line (a crash mid-write) was never followed by a send and is
ignored. When the current file would grow past its size bound it is rotated
to ``<name>.1``, replacing the previous rotation; both files are read back.
"""

from __future__ import annotations

import json
import logging
import os
from typing import TYPE_CHECKING, Final

from .models import DeliveryRecord, InvalidRecordError, JournalEntry
from .paths import open_private, secure_existing

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

__all__ = [
    "JOURNAL_FILENAME",
    "MAX_JOURNAL_BYTES",
    "MAX_LINE_BYTES",
    "AttemptJournal",
    "decode_line",
    "encode_entry",
]

logger = logging.getLogger(__name__)

JOURNAL_FILENAME: Final = "relay-state.journal"
JOURNAL_VERSION: Final = 1
MAX_JOURNAL_BYTES: Final = 4 * 1024 * 1024
MAX_LINE_BYTES: Final = 16 * 1024


def encode_entry(entry: JournalEntry) -> bytes:
    line = json.dumps(
        {"v": JOURNAL_VERSION, "attempt": entry.attempt, "record": entry.record.to_json()},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return line + b"\n"


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


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]


class AttemptJournal:
    """The journal files in one state directory."""

    def __init__(self, directory: Path, *, max_bytes: int = MAX_JOURNAL_BYTES) -> None:
        self._directory = directory
        self._current = directory / JOURNAL_FILENAME
        self._rotated = directory / f"{JOURNAL_FILENAME}.1"
        self._max_bytes = max_bytes

    @property
    def paths(self) -> tuple[Path, Path]:
        return (self._rotated, self._current)

    def exists(self) -> bool:
        return any(path.exists() or path.is_symlink() for path in self.paths)

    def append(self, entries: Sequence[JournalEntry]) -> None:
        """Append ``entries`` durably; raises ``OSError`` when that is impossible."""
        data = b"".join(encode_entry(entry) for entry in entries)
        if self._needs_rotation(len(data)):
            secure_existing(self._rotated)
            self._current.replace(self._rotated)
            self._sync_directory()
        descriptor = open_private(self._current, os.O_RDWR | os.O_APPEND | os.O_CREAT)
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

    def _needs_rotation(self, extra: int) -> bool:
        try:
            descriptor = open_private(self._current, os.O_RDONLY)
        except FileNotFoundError:
            return False
        try:
            size = os.fstat(descriptor).st_size
        finally:
            os.close(descriptor)
        return size > 0 and size + extra > self._max_bytes

    def read(self) -> tuple[list[JournalEntry], int]:
        """Return the valid entries, oldest first, and the number of corrupt lines."""
        entries: list[JournalEntry] = []
        corrupt = 0
        for path in self.paths:
            try:
                descriptor = open_private(path, os.O_RDONLY)
            except FileNotFoundError:
                continue
            with os.fdopen(descriptor, "rb") as handle:
                data = handle.read(self._max_bytes + MAX_LINE_BYTES + 1)
                if handle.read(1):
                    corrupt += 1  # Oversized: what is beyond the bound is not trusted.
            lines = data.split(b"\n")
            if lines.pop():
                logger.warning(
                    "ignoring a torn final journal line; no send followed it",
                    extra={"event": "state.journal_torn"},
                )
            for line in lines:
                if not line:
                    continue
                try:
                    entries.append(decode_line(line))
                except (ValueError, TypeError, RecursionError):
                    corrupt += 1
        return entries, corrupt

    def clear(self) -> None:
        for path in self.paths:
            try:
                path.unlink()
            except FileNotFoundError:
                continue
        self._sync_directory()

    def _sync_directory(self) -> None:
        descriptor = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

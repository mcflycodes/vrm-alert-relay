"""The fallback attempt journal. Every value here is fictitious."""

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from vrm_alert_relay.state import (
    JOURNAL_FILENAME,
    AttemptJournal,
    DeliveryKind,
    DeliveryRecord,
    DeliveryStatus,
    InvalidRecordError,
    JournalEntry,
    UnsafeStateError,
)
from vrm_alert_relay.state.journal import MAX_LINE_BYTES, decode_line, encode_entry

if TYPE_CHECKING:
    from pathlib import Path

BASE = datetime(2035, 1, 1, tzinfo=UTC)


def entry(n: int, *, attempt: bool = True) -> JournalEntry:
    record = DeliveryRecord(
        event_id=f"evt_{n}",
        recipient="owner_sms",
        kind=DeliveryKind.EVENT,
        status=DeliveryStatus.IN_FLIGHT,
        text="Freezer warming ❄",
        attempts=1,
        created_at=BASE,
        updated_at=BASE,
        last_attempt_at=BASE,
    )
    return JournalEntry(record, attempt=attempt)


def test_entries_round_trip_in_order_in_a_private_file(tmp_path: Path) -> None:
    journal = AttemptJournal(tmp_path)
    assert not journal.exists()
    journal.append((entry(1), entry(2, attempt=False)))
    journal.append((entry(3),))
    assert journal.exists()
    assert journal.read() == ([entry(1), entry(2, attempt=False), entry(3)], 0)
    assert stat.S_IMODE((tmp_path / JOURNAL_FILENAME).stat().st_mode) == 0o600
    journal.clear()
    journal.clear()
    assert not journal.exists()
    assert journal.read() == ([], 0)


def test_rotation_keeps_the_previous_file(tmp_path: Path) -> None:
    size = len(encode_entry(entry(1)))
    journal = AttemptJournal(tmp_path, max_bytes=2 * size)
    for n in range(5):
        journal.append((entry(n),))
    entries, corrupt = journal.read()
    assert [e.record.event_id for e in entries] == ["evt_2", "evt_3", "evt_4"]
    assert corrupt == 0


def test_failed_rotation_closes_cleanly(tmp_path: Path) -> None:
    journal = AttemptJournal(tmp_path, max_bytes=1)
    journal.append((entry(1),))
    (tmp_path / f"{JOURNAL_FILENAME}.1").mkdir()
    with pytest.raises(UnsafeStateError):
        journal.append((entry(2),))
    assert (tmp_path / JOURNAL_FILENAME).read_bytes() == encode_entry(entry(1))


def test_a_torn_final_line_is_ignored_and_not_glued_to(tmp_path: Path) -> None:
    journal = AttemptJournal(tmp_path)
    journal.append((entry(1),))
    with (tmp_path / JOURNAL_FILENAME).open("ab") as handle:
        handle.write(b'{"v":1,"attempt":tr')
    assert journal.read() == ([entry(1)], 0)
    journal.append((entry(2),))
    assert journal.read() == ([entry(1), entry(2)], 1)


@pytest.mark.parametrize(
    "line",
    [
        b"not json",
        b"[" * 10_000,
        b"[]",
        json.dumps({"v": 2, "attempt": True, "record": {}}).encode(),
        json.dumps({"v": 1, "attempt": 1, "record": {}}).encode(),
        json.dumps({"v": 1, "attempt": True, "record": {}}).encode(),
        b" " * (MAX_LINE_BYTES + 1),
    ],
)
def test_malformed_lines_are_rejected(line: bytes) -> None:
    with pytest.raises((ValueError, RecursionError)):
        decode_line(line)


def test_corrupt_and_oversized_files_are_counted(tmp_path: Path) -> None:
    journal = AttemptJournal(tmp_path, max_bytes=64)
    (tmp_path / JOURNAL_FILENAME).write_bytes(b"garbage\n\n" + b"x" * (MAX_LINE_BYTES + 200))
    entries, corrupt = journal.read()
    assert entries == []
    assert corrupt == 2  # one bad line, and the unread excess


def test_symlinked_or_irregular_journals_are_refused(tmp_path: Path) -> None:
    (tmp_path / "elsewhere").write_text("")
    (tmp_path / JOURNAL_FILENAME).symlink_to(tmp_path / "elsewhere")
    journal = AttemptJournal(tmp_path)
    with pytest.raises(UnsafeStateError):
        journal.append((entry(1),))
    with pytest.raises(UnsafeStateError):
        journal.read()
    (tmp_path / JOURNAL_FILENAME).unlink()
    os.mkfifo(tmp_path / f"{JOURNAL_FILENAME}.1")
    with pytest.raises(UnsafeStateError):
        journal.read()


def test_lines_are_validated_records(tmp_path: Path) -> None:
    data = json.loads(encode_entry(entry(1)))
    data["record"]["attempts"] = -1
    with pytest.raises(InvalidRecordError):
        decode_line(json.dumps(data).encode())

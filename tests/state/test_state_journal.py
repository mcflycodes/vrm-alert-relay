"""The fallback journal and its compaction. Every value here is fictitious."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import settings
from hypothesis import strategies as st
from hypothesis.stateful import RuleBasedStateMachine, invariant, rule

from vrm_alert_relay.config import MAX_GLOBAL_PER_DAY
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
from vrm_alert_relay.state.journal import (
    MAX_COMPACTED_BYTES,
    MAX_LINE_BYTES,
    MAX_LIVE_SENDS_PER_DAY,
    decode_line,
    encode_entry,
)

BASE = datetime(2035, 1, 1, tzinfo=UTC)


def entry(
    n: int,
    *,
    attempt: bool = True,
    attempts: int = 1,
    at: datetime = BASE,
    status: DeliveryStatus = DeliveryStatus.IN_FLIGHT,
    text: str = "Freezer warming ❄",
) -> JournalEntry:
    record = DeliveryRecord(
        event_id=f"evt_{n}",
        recipient="owner_sms",
        kind=DeliveryKind.EVENT,
        status=status,
        text=text,
        attempts=attempts,
        created_at=BASE,
        updated_at=at,
        last_attempt_at=at,
    )
    return JournalEntry(record, attempt=attempt)


def marks(journal: AttemptJournal) -> set[tuple[str, int]]:
    return {
        (e.record.event_id, e.record.attempts)
        for e in journal.read().entries
        if e.mark() is not None
    }


def test_entries_round_trip_in_order_in_a_private_file(tmp_path: Path) -> None:
    journal = AttemptJournal(tmp_path)
    assert journal.path == tmp_path / JOURNAL_FILENAME
    journal.append((entry(1), entry(2, attempt=False)), BASE)
    journal.append((entry(3),), BASE)
    contents = journal.read()
    assert contents.entries == [entry(1), entry(2, attempt=False), entry(3)]
    assert contents.unreadable == []
    assert stat.S_IMODE((tmp_path / JOURNAL_FILENAME).stat().st_mode) == 0o600
    journal.clear()
    journal.clear()
    assert not journal.path.exists()
    assert journal.read().entries == []


def test_compaction_keeps_recent_sends_and_the_latest_state_of_each_delivery(
    tmp_path: Path,
) -> None:
    size = len(encode_entry(entry(1)))
    journal = AttemptJournal(tmp_path, max_bytes=3 * size)
    now = BASE + timedelta(days=2)
    old = now - timedelta(days=1, seconds=1)
    journal.append((entry(1, at=old),), now)  # an old send: only its latest state matters
    journal.append((entry(1, attempt=False, at=old, status=DeliveryStatus.DELIVERED),), now)
    journal.append((entry(2, at=now - timedelta(hours=23)),), now)
    journal.append((entry(2, attempts=2, at=now - timedelta(hours=1)),), now)
    journal.append((entry(3, at=now),), now)  # compacts first
    assert marks(journal) == {("evt_2", 1), ("evt_2", 2), ("evt_3", 1)}
    latest = {e.record.event_id: e.record for e in journal.read().entries}
    assert latest["evt_1"].status is DeliveryStatus.DELIVERED
    assert stat.S_IMODE(journal.path.stat().st_mode) == 0o600
    assert not (tmp_path / f"{JOURNAL_FILENAME}.tmp").exists()


def test_compaction_keeps_every_send_at_the_largest_valid_daily_cap(tmp_path: Path) -> None:
    """B2: the journal holds a full day at the largest valid cap, even with long lines."""
    assert MAX_LIVE_SENDS_PER_DAY == MAX_GLOBAL_PER_DAY
    long_text = "❄" * 1000
    line = len(encode_entry(entry(0, text=long_text)))
    journal = AttemptJournal(tmp_path, max_bytes=50 * line)
    now = BASE + timedelta(days=1)
    sent = MAX_GLOBAL_PER_DAY
    for n in range(sent):
        at = now - timedelta(hours=23) + timedelta(seconds=n * 80)
        journal.append(
            (entry(n, at=at, text=long_text), entry(n, attempt=False, at=at, text=long_text)),
            at,
        )
    assert len(marks(journal)) == sent
    assert journal.path.stat().st_size <= 2 * MAX_COMPACTED_BYTES


def test_compaction_past_its_bound_keeps_the_newest_sends_and_logs(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    line = len(encode_entry(entry(10)))
    journal = AttemptJournal(tmp_path, max_bytes=line, max_compacted_bytes=2 * line)
    for n in range(10, 16):
        journal.append((entry(n),), BASE)
    # The oldest two went at the last compaction; the file then grew to twice its floor.
    assert marks(journal) == {("evt_12", 1), ("evt_13", 1), ("evt_14", 1), ("evt_15", 1)}
    assert "state.journal_evidence_dropped" in [r.__dict__.get("event") for r in caplog.records]


def test_unreadable_lines_keep_a_slot_until_their_window_passes(tmp_path: Path) -> None:
    journal = AttemptJournal(tmp_path, max_bytes=64)
    journal.path.write_bytes(b"garbage\n")
    assert journal.read().unreadable == [None]
    assert journal.read().corrupt == 1
    journal.append((entry(1),), BASE)  # compacts: the bad line becomes a dated placeholder
    contents = journal.read()
    assert contents.unreadable == [BASE]
    assert contents.corrupt == 0
    later = BASE + timedelta(days=1, seconds=1)
    journal.append((entry(2, at=later),), later)
    assert journal.read().unreadable == []


def test_compaction_keeps_the_newest_version_and_drops_old_states_past_its_bound(
    tmp_path: Path,
) -> None:
    now = BASE + timedelta(days=2)
    finished = [entry(n, attempt=False, status=DeliveryStatus.FAILED) for n in range(4)]
    line = len(encode_entry(finished[0]))
    journal = AttemptJournal(tmp_path, max_bytes=line, max_compacted_bytes=2 * line)
    newer = entry(9, attempt=False, attempts=2, status=DeliveryStatus.FAILED)
    older = entry(9, attempt=False, attempts=1, status=DeliveryStatus.PENDING)
    journal.path.write_bytes(b"".join(encode_entry(e) for e in (*finished, newer, older)))
    journal.append((entry(20, attempt=False, status=DeliveryStatus.FAILED),), now)
    kept = [(e.record.event_id, e.record.attempts) for e in journal.read().entries]
    assert kept == [("evt_3", 1), ("evt_9", 2), ("evt_20", 1)]


def test_failed_compaction_leaves_the_journal_intact(tmp_path: Path) -> None:
    journal = AttemptJournal(tmp_path, max_bytes=1)
    journal.append((entry(1),), BASE)
    (tmp_path / f"{JOURNAL_FILENAME}.tmp").mkdir()
    with pytest.raises(OSError):  # noqa: PT011  # whichever error the platform gives
        journal.append((entry(2),), BASE)
    assert journal.path.read_bytes() == encode_entry(entry(1))


def test_a_torn_final_line_is_ignored_and_not_glued_to(tmp_path: Path) -> None:
    journal = AttemptJournal(tmp_path)
    journal.append((entry(1),), BASE)
    with journal.path.open("ab") as handle:
        handle.write(b'{"v":1,"attempt":tr')
    assert journal.read().entries == [entry(1)]
    assert journal.read().corrupt == 0
    journal.append((entry(2),), BASE)
    contents = journal.read()
    assert contents.entries == [entry(1), entry(2)]
    assert contents.corrupt == 1


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


@pytest.mark.parametrize(
    "line",
    [
        b'{"v":1,"unreadable":"garbage"}',
        b'{"v":2,"unreadable":"2035-01-01T00:00:00+00:00"}',
        b"[" * 10_000,
    ],
)
def test_bad_placeholders_count_as_newly_unreadable(tmp_path: Path, line: bytes) -> None:
    journal = AttemptJournal(tmp_path)
    journal.path.write_bytes(line + b"\n")
    assert journal.read().unreadable == [None]


def test_oversized_files_count_their_unread_excess(tmp_path: Path) -> None:
    journal = AttemptJournal(tmp_path, max_bytes=16, max_compacted_bytes=16)
    journal.path.write_bytes(b"garbage\n\n" + b"x" * (MAX_LINE_BYTES + 200))
    contents = journal.read()
    assert contents.entries == []
    assert contents.corrupt == 2  # the unread excess, and one bad line


def test_symlinked_or_irregular_journals_are_refused(tmp_path: Path) -> None:
    (tmp_path / "elsewhere").write_text("")
    (tmp_path / JOURNAL_FILENAME).symlink_to(tmp_path / "elsewhere")
    journal = AttemptJournal(tmp_path)
    with pytest.raises(UnsafeStateError):
        journal.append((entry(1),), BASE)
    with pytest.raises(UnsafeStateError):
        journal.read()
    (tmp_path / JOURNAL_FILENAME).unlink()
    os.mkfifo(tmp_path / JOURNAL_FILENAME)
    with pytest.raises(UnsafeStateError):
        journal.read()


def test_lines_are_validated_records(tmp_path: Path) -> None:
    data = json.loads(encode_entry(entry(1)))
    data["record"]["attempts"] = -1
    with pytest.raises(InvalidRecordError):
        decode_line(json.dumps(data).encode())


class JournalMachine(RuleBasedStateMachine):
    """B2 boundary: compaction never loses a send younger than 24 hours, or a latest state."""

    def __init__(self) -> None:
        super().__init__()
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name)
        size = len(encode_entry(entry(0)))
        self.journal = AttemptJournal(self.path, max_bytes=4 * size)
        self.now = BASE
        self.sends: dict[tuple[str, int], datetime] = {}
        self.latest: dict[str, DeliveryRecord] = {}
        self.attempts: dict[int, int] = {}

    @rule(n=st.integers(0, 5), finish=st.booleans())
    def send(self, n: int, finish: bool) -> None:  # hypothesis rule argument
        attempts = self.attempts.get(n, 0) + 1
        self.attempts[n] = attempts
        sent = entry(n, attempts=attempts, at=self.now)
        lines: list[JournalEntry] = [sent]
        if finish:
            lines.append(
                entry(
                    n, attempt=False, attempts=attempts, at=self.now, status=DeliveryStatus.FAILED
                )
            )
        self.journal.append(tuple(lines), self.now)
        self.sends[(f"evt_{n}", attempts)] = self.now
        self.latest[f"evt_{n}"] = lines[-1].record

    @rule(minutes=st.integers(1, 6 * 60))
    def wait(self, minutes: int) -> None:
        self.now += timedelta(minutes=minutes)

    @invariant()
    def recent_sends_and_latest_states_survive(self) -> None:
        kept = marks(self.journal)
        recent = {key for key, at in self.sends.items() if at > self.now - timedelta(days=1)}
        assert recent <= kept
        newest: dict[str, Any] = {}
        for found in self.journal.read().entries:
            record = found.record
            if (
                record.event_id not in newest
                or record.progress() >= newest[record.event_id].progress()
            ):
                newest[record.event_id] = record
        assert newest == self.latest

    def teardown(self) -> None:
        self._tmp.cleanup()


TestJournalMachine = JournalMachine.TestCase
TestJournalMachine.settings = settings(max_examples=60, stateful_step_count=40, deadline=None)

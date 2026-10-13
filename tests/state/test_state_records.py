"""Validation of persisted delivery records. Every value here is fictitious."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from vrm_alert_relay.state import (
    AttemptMark,
    DeliveryKind,
    DeliveryOrigin,
    DeliveryRecord,
    DeliveryStatus,
    InvalidRecordError,
    JournalEntry,
    is_identifier,
)

BASE = datetime(2035, 1, 1, tzinfo=UTC)
VALID: dict[str, Any] = {
    "event_id": "evt_0001",
    "recipient": "owner_sms",
    "kind": DeliveryKind.EVENT,
    "status": DeliveryStatus.PENDING,
    "text": "Freezer warming",
    "attempts": 0,
    "created_at": BASE,
    "updated_at": BASE,
    "next_attempt_at": BASE,
    "last_attempt_at": None,
    "provider_message_id": "provider-id-1",
}


def test_valid_record_has_a_key() -> None:
    assert DeliveryRecord(**VALID).key == ("evt_0001", "owner_sms")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_id", ""),
        ("event_id", "evt 1"),
        ("event_id", "e" * 129),
        ("event_id", 1),
        ("recipient", "owner\nsms"),
        ("kind", "event"),
        ("status", "pending"),
        ("text", "x" * 1001),
        ("text", None),
        ("attempts", -1),
        ("attempts", 101),
        ("attempts", True),
        ("attempts", 1.0),
        ("created_at", datetime(2035, 1, 1)),  # naive on purpose
        ("updated_at", "2035-01-01T00:00:00+00:00"),
        ("next_attempt_at", datetime(2035, 1, 1)),  # naive on purpose
        ("last_attempt_at", 0),
        ("provider_message_id", ""),
        ("provider_message_id", "x" * 129),
        ("provider_message_id", "id\x1b[0m"),
        ("provider_message_id", 7),
        ("covers", -1),
        ("recovered", 1),
        ("covers", True),
        ("origin", "stale"),
    ],
)
def test_invalid_records_are_rejected(field: str, value: Any) -> None:
    with pytest.raises(InvalidRecordError):
        DeliveryRecord(**{**VALID, field: value})


def test_terminal_statuses() -> None:
    assert {status for status in DeliveryStatus if status.terminal} == {
        DeliveryStatus.DELIVERED,
        DeliveryStatus.FAILED,
        DeliveryStatus.SUPPRESSED,
    }


@pytest.mark.parametrize(
    ("value", "expected"),
    [("evt_1:a.b-c", True), ("", False), ("a b", False), (None, False), ("x" * 128, True)],
)
def test_is_identifier(value: object, expected: bool) -> None:
    assert is_identifier(value) is expected


def test_rule_id_is_validated() -> None:
    assert DeliveryRecord(**{**VALID, "rule_id": "freezer"}).rule_id == "freezer"
    with pytest.raises(InvalidRecordError):
        DeliveryRecord(**{**VALID, "rule_id": "bad id"})


def test_progress_orders_versions_of_one_record() -> None:
    def version(status: DeliveryStatus, attempts: int) -> tuple[int, int, datetime]:
        return DeliveryRecord(**{**VALID, "status": status, "attempts": attempts}).progress()

    chain = [
        version(DeliveryStatus.PENDING, 0),
        version(DeliveryStatus.IN_FLIGHT, 1),
        version(DeliveryStatus.AMBIGUOUS, 1),
        version(DeliveryStatus.IN_FLIGHT, 2),
        version(DeliveryStatus.DELIVERED, 2),
    ]
    assert chain == sorted(chain)
    assert len(set(chain)) == len(chain)


def test_records_round_trip_through_json() -> None:
    original = DeliveryRecord(**{**VALID, "rule_id": "freezer", "last_attempt_at": BASE})
    assert DeliveryRecord.from_json(original.to_json()) == original


def test_origin_round_trips_through_json() -> None:
    original = DeliveryRecord(**{**VALID, "rule_id": "freezer", "origin": DeliveryOrigin.STALE})
    data = original.to_json()
    assert data["origin"] == "stale"
    assert DeliveryRecord.from_json(data) == original


def test_a_journal_line_written_before_origin_existed_is_read() -> None:
    data = DeliveryRecord(**VALID).to_json()
    del data["origin"]
    assert DeliveryRecord.from_json(data).origin is None


@pytest.mark.parametrize("raw", ["nonsense", 3, ["stale"]])
def test_an_unknown_origin_is_read_as_unknown_and_is_still_sent(raw: object) -> None:
    data = {**DeliveryRecord(**VALID).to_json(), "origin": raw}
    assert DeliveryRecord.from_json(data).origin is None


@pytest.mark.parametrize(
    "data",
    [
        None,
        {"event_id": "evt_1"},
        {**DeliveryRecord(**VALID).to_json(), "kind": "nonsense"},
        {**DeliveryRecord(**VALID).to_json(), "created_at": "2035-01-01T00:00:00"},
        {**DeliveryRecord(**VALID).to_json(), "created_at": 5},
        {**DeliveryRecord(**VALID).to_json(), "updated_at": "x" * 65},
    ],
)
def test_malformed_json_records_are_rejected(data: object) -> None:
    with pytest.raises(ValueError):  # noqa: PT011  # each case fails a different check
        DeliveryRecord.from_json(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_id", "bad id"),
        ("attempt", -1),
        ("attempt", 101),
        ("at", datetime(2035, 1, 1)),  # naive on purpose
        ("live", 1),
    ],
)
def test_invalid_attempt_marks_are_rejected(field: str, value: Any) -> None:
    fields: dict[str, Any] = {
        "event_id": "evt_1",
        "recipient": "owner_sms",
        "attempt": 1,
        "at": BASE,
        "live": True,
    }
    with pytest.raises(InvalidRecordError):
        AttemptMark(**{**fields, field: value})


def test_journal_entry_marks_only_attempts_with_a_time() -> None:
    record = DeliveryRecord(**{**VALID, "attempts": 2, "last_attempt_at": BASE})
    assert JournalEntry(record, attempt=True).mark() == AttemptMark(
        "evt_0001", "owner_sms", 2, BASE
    )
    assert JournalEntry(record, attempt=False).mark() is None
    assert JournalEntry(DeliveryRecord(**VALID), attempt=True).mark() is None

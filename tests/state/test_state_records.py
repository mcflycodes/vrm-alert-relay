"""Validation of persisted delivery records. Every value here is fictitious."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from vrm_alert_relay.state import (
    DeliveryKind,
    DeliveryRecord,
    DeliveryStatus,
    InvalidRecordError,
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

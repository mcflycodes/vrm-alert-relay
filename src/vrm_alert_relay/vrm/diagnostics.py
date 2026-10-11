"""Pure normalisation of a VRM Diagnostics response into engine samples.

A Diagnostics response is ``{"success": true, "records": [...]}``. Each record
describes one value the GX device last logged, with ``code`` (the attribute
code), ``instance`` (the device instance), ``dbusServiceType``, ``dbusPath``,
``rawValue``, ``formattedValue``, ``timestamp`` (epoch seconds) and a
``description`` label. VRM's OpenAPI schema calls ``records`` an object, but
real responses carry a list; only a list is accepted.

A configured measurement is identified by attribute code and device instance,
plus ``dbusServiceType`` when the operator sets one. Record position and the
numeric attribute id are never used. When more than one record matches, the
result is :attr:`ReadingProblem.AMBIGUOUS` rather than a guess.

Everything taken from the response is bounded. Labels are untrusted and only
for display: control, format and separator characters become spaces,
whitespace is collapsed and the result is truncated. Labels are never used to
match, route or address anything.
"""

from __future__ import annotations

import math
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Final

from vrm_alert_relay.engine.models import Sample
from vrm_alert_relay.vrm.errors import VrmResponseError

if TYPE_CHECKING:
    from vrm_alert_relay.config.models import Measurement

MAX_RECORDS: Final = 1000
"""Records accepted in one response; matches the ``count`` the adapter requests."""

MAX_LABEL_LENGTH: Final = 80
_LABEL_SCAN_LIMIT: Final = MAX_LABEL_LENGTH * 4
_REPLACED_CATEGORIES: Final = frozenset({"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"})


class ReadingProblem(StrEnum):
    """Why a configured measurement produced no sample in this response."""

    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    NON_NUMERIC = "non_numeric"
    NON_FINITE = "non_finite"
    BAD_TIMESTAMP = "bad_timestamp"
    FUTURE_TIMESTAMP = "future_timestamp"
    OLD_TIMESTAMP = "old_timestamp"


@dataclass(frozen=True, slots=True)
class TimestampPolicy:
    """Bounds on record timestamps relative to the poll's wall-clock time.

    ``max_future_skew`` tolerates clock differences between the GX device, VRM
    and this host. ``max_age`` rejects only implausibly old values; ordinary
    staleness is left to the rules engine, which receives those samples and
    raises its stale-data event.
    """

    max_future_skew: timedelta = timedelta(minutes=5)
    max_age: timedelta = timedelta(days=30)

    def __post_init__(self) -> None:
        for name in ("max_future_skew", "max_age"):
            value = getattr(self, name)
            if not isinstance(value, timedelta) or value <= timedelta(0):
                raise ValueError(f"{name} must be a positive timedelta")  # noqa: TRY003  # message is specific to this check


@dataclass(frozen=True, slots=True)
class MeasurementResult:
    """The outcome for one configured measurement: a sample or a problem."""

    measurement: Measurement
    sample: Sample | None = None
    problem: ReadingProblem | None = None
    label: str | None = None

    def __post_init__(self) -> None:
        if (self.sample is None) == (self.problem is None):
            raise ValueError("exactly one of sample and problem must be set")  # noqa: TRY003  # message is specific to this check

    @property
    def ok(self) -> bool:
        return self.sample is not None


def sanitize_label(value: object) -> str | None:
    """Return a bounded, single-line display label, or ``None`` if there is none."""
    if not isinstance(value, str):
        return None
    chars = (
        " " if unicodedata.category(char) in _REPLACED_CATEGORIES else char
        for char in value[:_LABEL_SCAN_LIMIT]
    )
    label = " ".join("".join(chars).split())[:MAX_LABEL_LENGTH].rstrip()
    return label or None


def parse_diagnostics(
    payload: object,
    measurements: Sequence[Measurement],
    *,
    installation: str,
    now: datetime,
    policy: TimestampPolicy | None = None,
) -> tuple[MeasurementResult, ...]:
    """Normalise one Diagnostics payload into one result per measurement.

    Raises :class:`VrmResponseError` when the payload as a whole is unusable.
    Problems with individual records become per-measurement results.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("now must be timezone-aware")  # noqa: TRY003  # message is specific to this check
    policy = policy if policy is not None else TimestampPolicy()
    records = _records(payload, installation)
    index = _index(records, {m.code for m in measurements})
    return tuple(_result(m, index, now, policy) for m in measurements)


def _records(payload: object, installation: str) -> list[object]:
    if not isinstance(payload, dict):
        raise VrmResponseError(installation, "response is not a JSON object")
    if "success" in payload and payload["success"] is not True:
        raise VrmResponseError(installation, "response does not report success")
    records = payload.get("records")
    if not isinstance(records, list):
        raise VrmResponseError(installation, "response records are not a list")
    if len(records) > MAX_RECORDS:
        raise VrmResponseError(installation, f"response has more than {MAX_RECORDS} records")
    return records


type _Index = Mapping[tuple[str, int], list[dict[str, object]]]


def _index(records: list[object], codes: set[str]) -> _Index:
    index: dict[tuple[str, int], list[dict[str, object]]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        code = record.get("code")
        instance = record.get("instance")
        if not isinstance(code, str) or code not in codes:
            continue
        if isinstance(instance, bool) or not isinstance(instance, int):
            continue
        index.setdefault((code, instance), []).append(record)
    return index


def _result(
    measurement: Measurement, index: _Index, now: datetime, policy: TimestampPolicy
) -> MeasurementResult:
    candidates = index.get((measurement.code, measurement.instance), [])
    if measurement.service_type is not None:
        candidates = [r for r in candidates if r.get("dbusServiceType") == measurement.service_type]
    if not candidates:
        return MeasurementResult(measurement, problem=ReadingProblem.MISSING)
    if len(candidates) > 1:
        return MeasurementResult(measurement, problem=ReadingProblem.AMBIGUOUS)
    record = candidates[0]
    label = sanitize_label(record.get("description"))
    value = _value(record.get("rawValue"))
    if isinstance(value, ReadingProblem):
        return MeasurementResult(measurement, problem=value, label=label)
    timestamp = _timestamp(record.get("timestamp"), now, policy)
    if isinstance(timestamp, ReadingProblem):
        return MeasurementResult(measurement, problem=timestamp, label=label)
    return MeasurementResult(measurement, sample=Sample(value, timestamp), label=label)


def _number(raw: object) -> float | None:
    """Return ``raw`` as a float, ``nan`` if it overflows, or ``None`` if not a number."""
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        return None
    try:
        return float(raw)
    except OverflowError:
        return math.nan


def _value(raw: object) -> float | ReadingProblem:
    value = _number(raw)
    if value is None:
        return ReadingProblem.NON_NUMERIC
    if not math.isfinite(value):
        return ReadingProblem.NON_FINITE
    return value


def _timestamp(raw: object, now: datetime, policy: TimestampPolicy) -> datetime | ReadingProblem:
    seconds = _number(raw)
    if seconds is None or not math.isfinite(seconds) or seconds <= 0:
        return ReadingProblem.BAD_TIMESTAMP
    try:
        when = datetime.fromtimestamp(seconds, UTC)
    except (OverflowError, OSError, ValueError):
        return ReadingProblem.BAD_TIMESTAMP
    if when > now + policy.max_future_skew:
        return ReadingProblem.FUTURE_TIMESTAMP
    if when < now - policy.max_age:
        return ReadingProblem.OLD_TIMESTAMP
    return when

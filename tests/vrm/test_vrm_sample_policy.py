"""The VRM parser and the rules engine share one sample-usability bound."""

from __future__ import annotations

from datetime import timedelta

from vrm_helpers import NOW, NOW_TS, diagnostics, measurement, record

from vrm_alert_relay.engine import FUTURE_TOLERANCE, Sample, sample_is_usable
from vrm_alert_relay.engine import evaluator as evaluator_module
from vrm_alert_relay.vrm import ReadingProblem, TimestampPolicy, parse_diagnostics

TOLERANCE = int(FUTURE_TOLERANCE.total_seconds())


def parse(offset: int) -> tuple[Sample | None, ReadingProblem | None]:
    payload = diagnostics(record("V", 0, 12.5, timestamp=NOW_TS + offset))
    (result,) = parse_diagnostics(payload, [measurement("V", 0)], installation="home", now=NOW)
    return result.sample, result.problem


def test_the_parser_default_is_the_engine_bound() -> None:
    assert TimestampPolicy().max_future_skew == FUTURE_TOLERANCE
    assert evaluator_module.FUTURE_TOLERANCE is FUTURE_TOLERANCE


def test_parser_and_engine_agree_at_the_bound() -> None:
    at_bound, problem = parse(TOLERANCE)
    assert problem is None
    assert at_bound is not None
    assert sample_is_usable(at_bound, NOW)

    beyond, problem = parse(TOLERANCE + 1)
    assert beyond is None
    assert problem is ReadingProblem.FUTURE_TIMESTAMP
    assert not sample_is_usable(Sample(12.5, NOW + FUTURE_TOLERANCE + timedelta(seconds=1)), NOW)


def test_sample_is_usable_refuses_what_evaluate_ignores() -> None:
    assert sample_is_usable(Sample(1.0, NOW), NOW)
    assert not sample_is_usable(Sample(float("nan"), NOW), NOW)
    assert not sample_is_usable(Sample(1.0, NOW.replace(tzinfo=None)), NOW)
    assert not sample_is_usable("not a sample", NOW)

"""The pure backoff policy and per-installation retry state."""

from __future__ import annotations

import math

import pytest

from vrm_alert_relay.vrm.backoff import Backoff, BackoffPolicy, BackoffState
from vrm_alert_relay.vrm.errors import (
    VrmAuthError,
    VrmRateLimitedError,
    VrmRejectedError,
    VrmResponseError,
    VrmUnavailableError,
)

UNAVAILABLE = VrmUnavailableError("home", "HTTP 503", status=503)
BAD = VrmResponseError("home", "response is not valid JSON")
AUTH = VrmAuthError("home", status=401)
REJECTED = VrmRejectedError("home", "HTTP 404", status=404)


def limited(retry_after: float | None) -> VrmRateLimitedError:
    return VrmRateLimitedError("home", retry_after=retry_after)


NO_JITTER = BackoffPolicy(jitter=0.0)


@pytest.mark.parametrize(
    "field",
    ["base_delay", "max_delay", "rate_limit_delay", "max_retry_after", "non_transient_delay"],
)
@pytest.mark.parametrize("value", [0, -1.0, math.inf, math.nan, True, "30"])
def test_policy_rejects_non_positive_delays(field: str, value: object) -> None:
    with pytest.raises(ValueError, match=f"{field} must be a positive finite number"):
        BackoffPolicy(**{field: value})  # type: ignore[arg-type]


def test_policy_rejects_cap_below_base() -> None:
    with pytest.raises(ValueError, match="max_delay must not be less"):
        BackoffPolicy(base_delay=60.0, max_delay=30.0)


@pytest.mark.parametrize("jitter", [-0.1, 1.0, 2, True, math.nan, "0.1"])
def test_policy_rejects_bad_jitter(jitter: object) -> None:
    with pytest.raises(ValueError, match="jitter"):
        BackoffPolicy(jitter=jitter)  # type: ignore[arg-type]


def test_transient_delay_grows_exponentially_then_caps() -> None:
    policy = BackoffPolicy(base_delay=30.0, max_delay=900.0, jitter=0.0)
    delays = [policy.transient_delay(n, 0.5) for n in range(1, 9)]
    assert delays == [30.0, 60.0, 120.0, 240.0, 480.0, 900.0, 900.0, 900.0]
    assert policy.transient_delay(0, 0.5) == 30.0
    assert policy.transient_delay(10**9, 0.5) == 900.0


def test_jitter_only_shortens_within_bounds() -> None:
    policy = BackoffPolicy(base_delay=100.0, max_delay=100.0, jitter=0.2)
    assert policy.transient_delay(1, 0.0) == 100.0
    assert policy.transient_delay(1, 0.5) == pytest.approx(90.0)
    assert policy.transient_delay(1, 0.999999) == pytest.approx(80.0, abs=1e-3)


@pytest.mark.parametrize(("unit", "expected"), [(-3.0, 100.0), (7.0, 80.0), (math.nan, 100.0)])
def test_jitter_draw_is_clamped(unit: float, expected: float) -> None:
    policy = BackoffPolicy(base_delay=100.0, max_delay=100.0, jitter=0.2)
    assert policy.transient_delay(1, unit) == pytest.approx(expected)


def test_bad_response_backs_off_like_transient() -> None:
    assert NO_JITTER.delay_for(BAD, 3, 0.0) == NO_JITTER.transient_delay(3, 0.0)


def test_retry_after_is_honoured_and_bounded() -> None:
    policy = BackoffPolicy(max_retry_after=3600.0, rate_limit_delay=10.0)
    assert policy.delay_for(limited(42.0), 1, 0.9) == 42.0
    assert policy.delay_for(limited(0.0), 1, 0.9) == 10.0
    assert policy.delay_for(limited(-5.0), 1, 0.9) == 10.0
    assert policy.delay_for(limited(3.0), 1, 0.9) == 10.0
    assert policy.delay_for(limited(86400.0), 1, 0.9) == 3600.0
    assert policy.delay_for(limited(1e300), 1, 0.9) == 3600.0


@pytest.mark.parametrize("retry_after", [0.0, -1e9, 59.9])
def test_every_429_waits_a_positive_minimum(retry_after: float) -> None:
    backoff = Backoff(BackoffPolicy(rate_limit_delay=60.0))
    until = backoff.record_failure("123456", limited(retry_after), 500.0)
    assert until == 560.0
    assert backoff.blocking_error("234567", 500.0) is not None


def test_rate_limit_without_retry_after_waits_at_least_minimum() -> None:
    policy = BackoffPolicy(base_delay=10.0, max_delay=900.0, jitter=0.0, rate_limit_delay=60.0)
    assert policy.delay_for(limited(None), 1, 0.0) == 60.0
    assert policy.delay_for(limited(None), 5, 0.0) == 160.0


@pytest.mark.parametrize("error", [AUTH, VrmAuthError("home", status=403), REJECTED])
def test_non_transient_failures_wait_fixed_delay(error: VrmAuthError) -> None:
    policy = BackoffPolicy(non_transient_delay=3600.0)
    assert not error.transient
    assert [policy.delay_for(error, n, 0.5) for n in (1, 2, 10)] == [3600.0] * 3


def test_fresh_tracker_has_no_state() -> None:
    backoff = Backoff()
    assert backoff.state("home") == BackoffState()
    assert backoff.retry_at("home") is None
    assert backoff.rate_limited_until is None
    assert backoff.blocking_error("home", 0.0) is None
    assert isinstance(backoff.policy, BackoffPolicy)


def test_default_rng_produces_delay_within_jitter_bounds() -> None:
    backoff = Backoff(BackoffPolicy(base_delay=100.0, max_delay=100.0, jitter=0.5))
    retry_at = backoff.record_failure("home", UNAVAILABLE, 0.0)
    assert 50.0 <= retry_at <= 100.0


def test_failures_accumulate_and_block_until_retry_time() -> None:
    backoff = Backoff(NO_JITTER, rng=lambda: 0.0)
    assert backoff.record_failure("home", UNAVAILABLE, 1000.0) == 1030.0
    assert backoff.blocking_error("home", 1029.9) is UNAVAILABLE
    assert backoff.blocking_error("home", 1030.0) is None
    assert backoff.record_failure("home", UNAVAILABLE, 1030.0) == 1090.0
    assert backoff.state("home") == BackoffState(2, 1090.0, UNAVAILABLE)
    assert backoff.blocking_error("cabin", 1031.0) is None


def test_success_clears_state() -> None:
    backoff = Backoff(NO_JITTER)
    backoff.record_failure("home", UNAVAILABLE, 0.0)
    backoff.record_success("home")
    assert backoff.state("home") == BackoffState()
    assert backoff.blocking_error("home", 0.0) is None
    backoff.record_success("never-failed")


def test_rate_limit_gates_every_installation() -> None:
    backoff = Backoff(NO_JITTER)
    error = limited(120.0)
    assert backoff.record_failure("home", error, 100.0) == 220.0
    assert backoff.rate_limited_until == 220.0
    assert backoff.blocking_error("cabin", 219.0) is error
    assert backoff.retry_at("cabin") == 220.0
    assert backoff.blocking_error("cabin", 220.0) is None


def test_rate_limit_extends_a_shorter_own_delay() -> None:
    backoff = Backoff(NO_JITTER)
    backoff.record_failure("home", limited(600.0), 0.0)
    assert backoff.record_failure("cabin", UNAVAILABLE, 10.0) == 600.0
    assert backoff.retry_at("cabin") == 600.0
    assert backoff.blocking_error("cabin", 100.0).transient  # type: ignore[union-attr]


def test_own_delay_beyond_rate_limit_still_blocks() -> None:
    backoff = Backoff(NO_JITTER)
    backoff.record_failure("cabin", AUTH, 0.0)
    backoff.record_failure("home", limited(60.0), 0.0)
    assert backoff.blocking_error("cabin", 100.0) is AUTH
    assert backoff.retry_at("cabin") == 3600.0


def test_success_ends_rate_limit_gate() -> None:
    backoff = Backoff(NO_JITTER)
    backoff.record_failure("home", limited(60.0), 0.0)
    backoff.record_success("cabin")
    assert backoff.rate_limited_until is None
    assert backoff.blocking_error("cabin", 1.0) is None

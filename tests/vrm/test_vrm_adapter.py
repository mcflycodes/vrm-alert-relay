"""The VRM adapter against a stubbed transport. No test reaches the network."""

from __future__ import annotations

import io
import json
import logging
import pickle
import traceback
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx
import pytest
from vrm_helpers import (
    BASE_URL,
    FAKE_TOKEN,
    NOW,
    NOW_TS,
    diagnostics,
    installation,
    json_response,
    measurement,
    record,
)

from vrm_alert_relay.config.models import DEFAULT_VRM_BASE_URL, Installation, VrmConfig
from vrm_alert_relay.config.secret import Secret
from vrm_alert_relay.engine.models import Sample
from vrm_alert_relay.logs.config import JsonFormatter
from vrm_alert_relay.logs.redaction import SecretRegistry
from vrm_alert_relay.net.errors import (
    HttpStatusError,
    HttpTransportError,
    InvalidHeaderError,
    InvalidRequestError,
)
from vrm_alert_relay.vrm import adapter as adapter_module
from vrm_alert_relay.vrm.adapter import (
    AUTH_HEADER,
    DIAGNOSTICS_COUNT,
    InstallationOutcome,
    InstallationReading,
    PollResult,
    VrmAdapter,
    _translate,
)
from vrm_alert_relay.vrm.backoff import Backoff, BackoffPolicy
from vrm_alert_relay.vrm.diagnostics import MeasurementResult, ReadingProblem
from vrm_alert_relay.vrm.errors import (
    FailureKind,
    VrmAuthError,
    VrmError,
    VrmRateLimitedError,
    VrmRejectedError,
    VrmResponseError,
    VrmUnavailableError,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from vrm_helpers import FakeClock, StubTransport

    from vrm_alert_relay.net.client import SafeHttpClient

    MakeAdapter = Callable[..., VrmAdapter]

HOME = installation("home", 123456)
CABIN = installation("cabin", 234567)
VOLTAGE = measurement("bv", 0)
SOC = measurement("bs", 0)
PV = measurement("V", 0, "solarcharger")


def site_of(request: httpx.Request) -> int:
    return int(request.url.path.split("/")[-2])


def ok_handler(request: httpx.Request) -> httpx.Response:
    site = site_of(request)
    base = 50.0 if site == HOME.site_id else 25.0
    return json_response(
        diagnostics(
            record("bv", 0, base, description="Voltage"),
            record("bs", 0, 90.0, description="State of charge"),
            record("V", 0, 13.0, service_type="solarcharger", description="PV voltage"),
            record("V", 0, base, service_type="battery"),
        )
    )


def respond_status(transport: StubTransport, status: int, **headers: str) -> None:
    transport.respond(lambda _r: httpx.Response(status, content=b"secret body", headers=headers))


# Requests


def test_one_request_per_installation_with_expected_shape(
    make_adapter: MakeAdapter, transport: StubTransport
) -> None:
    transport.respond(ok_handler)
    result = make_adapter().poll([(HOME, (VOLTAGE, SOC)), (CABIN, (VOLTAGE, PV))])

    assert len(transport.requests) == 2
    for request, site in zip(transport.requests, (123456, 234567), strict=True):
        assert request.method == "GET"
        assert request.url.scheme == "https"
        assert request.url.host == "vrm.example.invalid"
        assert request.url.path == f"/v2/installations/{site}/diagnostics"
        assert dict(request.url.params) == {"count": str(DIAGNOSTICS_COUNT)}
        assert request.headers[AUTH_HEADER] == f"Token {FAKE_TOKEN}"
        assert "authorization" not in request.headers

    assert not result.degraded
    assert result.failures == ()
    assert result.next_attempt_at is None
    home, cabin = result.outcomes
    assert home.ok
    assert home.installation == HOME
    assert home.reading is not None
    assert home.retry_at is None
    assert not home.deferred
    when = datetime.fromtimestamp(NOW_TS, UTC)
    assert [r.sample for r in home.reading.results] == [Sample(50.0, when), Sample(90.0, when)]
    assert home.reading.fetched_at == NOW
    assert cabin.reading is not None
    assert cabin.reading.result_for(PV) == MeasurementResult(
        PV, sample=Sample(13.0, when), label="PV voltage"
    )
    assert cabin.reading.result_for(SOC) is None
    assert cabin.reading.problems == ()


def test_default_base_url(http: SafeHttpClient, registry: SecretRegistry) -> None:
    adapter = VrmAdapter(http, Secret(FAKE_TOKEN), registry=registry)
    assert repr(adapter) == f"VrmAdapter({DEFAULT_VRM_BASE_URL!r})"


def test_from_config_uses_configured_base_url(
    http: SafeHttpClient, transport: StubTransport, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = SecretRegistry()
    monkeypatch.setattr(adapter_module, "register_secret", registry.register)
    monkeypatch.setattr(adapter_module, "register_derived_secret", registry.register)
    config = VrmConfig(
        base_url="https://vrm-proxy.example.invalid:8443/api/v2",
        token_file="/run/secrets/fake-vrm-token",  # noqa: S106  # a fictitious path, not a secret
        installations=(HOME,),
    )
    backoff = Backoff()
    adapter = VrmAdapter.from_config(config, Secret(FAKE_TOKEN), http, backoff=backoff)
    assert adapter.backoff is backoff
    assert registry.contains(FAKE_TOKEN)
    assert registry.contains(f"Token {FAKE_TOKEN}")

    transport.respond(ok_handler)
    adapter.fetch(HOME, (VOLTAGE,))
    url = transport.requests[0].url
    assert (url.host, url.port) == ("vrm-proxy.example.invalid", 8443)
    assert url.path == "/api/v2/installations/123456/diagnostics"


def test_from_config_default_backoff(http: SafeHttpClient, monkeypatch: pytest.MonkeyPatch) -> None:
    registry = SecretRegistry()
    monkeypatch.setattr(adapter_module, "register_secret", registry.register)
    monkeypatch.setattr(adapter_module, "register_derived_secret", registry.register)
    config = VrmConfig(
        token_file="/run/secrets/fake-vrm-token",  # noqa: S106  # a fictitious path, not a secret
        installations=(HOME,),
    )
    adapter = VrmAdapter.from_config(config, Secret(FAKE_TOKEN), http)
    assert isinstance(adapter.backoff, Backoff)


def test_plain_http_base_url_refused(http: SafeHttpClient, registry: SecretRegistry) -> None:
    with pytest.raises(ValueError, match="https"):
        VrmAdapter(
            http, Secret(FAKE_TOKEN), base_url="http://vrm.example.invalid/v2", registry=registry
        )


@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_invalid_response_limit_refused(make_adapter: MakeAdapter, limit: object) -> None:
    with pytest.raises(ValueError, match="max_response_bytes"):
        make_adapter(max_response_bytes=limit)


def test_installation_with_problems_marks_poll_degraded(
    make_adapter: MakeAdapter, transport: StubTransport
) -> None:
    transport.respond(lambda _r: json_response(diagnostics(record("bv", 0, "n/a"))))
    result = make_adapter().poll([(HOME, (VOLTAGE, SOC))])
    (outcome,) = result.outcomes
    assert outcome.ok
    assert result.failures == ()
    assert result.degraded
    assert outcome.reading is not None
    assert [p.problem for p in outcome.reading.problems] == [
        ReadingProblem.NON_NUMERIC,
        ReadingProblem.MISSING,
    ]


def test_no_measurements_still_fetches_and_is_healthy(
    make_adapter: MakeAdapter, transport: StubTransport
) -> None:
    transport.respond(ok_handler)
    result = make_adapter().poll([(HOME, ())])
    assert len(transport.requests) == 1
    assert not result.degraded


def test_empty_poll(make_adapter: MakeAdapter, transport: StubTransport) -> None:
    result = make_adapter().poll([])
    assert result == PollResult(())
    assert not result.degraded
    assert transport.requests == []


# Error mapping


@pytest.mark.parametrize("status", [401, 403])
def test_auth_errors_are_not_retried_as_transient(
    make_adapter: MakeAdapter, transport: StubTransport, clock: FakeClock, status: int
) -> None:
    respond_status(transport, status)
    adapter = make_adapter()
    first = adapter.poll([(HOME, (VOLTAGE,))])
    (outcome,) = first.outcomes
    assert isinstance(outcome.error, VrmAuthError)
    assert outcome.error.status == status
    assert outcome.error.kind is FailureKind.AUTH
    assert not outcome.error.transient
    assert outcome.retry_at == clock.now + BackoffPolicy().non_transient_delay

    clock.now += 900
    second = adapter.poll([(HOME, (VOLTAGE,))])
    assert len(transport.requests) == 1
    assert second.outcomes[0].deferred
    assert repr(second.outcomes[0].error) == repr(outcome.error)
    assert second.outcomes[0].error is not outcome.error

    clock.now = outcome.retry_at  # type: ignore[assignment]
    adapter.poll([(HOME, (VOLTAGE,))])
    assert len(transport.requests) == 2
    assert adapter.backoff.state("123456").next_attempt_at == clock.now + 3600.0


def test_429_with_retry_after_defers_remaining_installations(
    make_adapter: MakeAdapter, transport: StubTransport, clock: FakeClock
) -> None:
    respond_status(transport, 429, **{"Retry-After": "120"})
    adapter = make_adapter()
    result = adapter.poll([(HOME, (VOLTAGE,)), (CABIN, (VOLTAGE,))])
    assert len(transport.requests) == 1
    home, cabin = result.outcomes
    assert isinstance(home.error, VrmRateLimitedError)
    assert home.error.retry_after == 120.0
    assert home.error.transient
    assert not home.deferred
    assert cabin.deferred
    assert repr(cabin.error) == repr(home.error)
    assert home.retry_at == cabin.retry_at == clock.now + 120.0
    assert result.next_attempt_at == clock.now + 120.0
    assert result.degraded
    assert [o.installation for o in result.failures] == [HOME, CABIN]

    clock.now += 119
    adapter.poll([(HOME, (VOLTAGE,)), (CABIN, (VOLTAGE,))])
    assert len(transport.requests) == 1

    clock.now += 1
    transport.respond(ok_handler)
    recovered = adapter.poll([(HOME, (VOLTAGE,)), (CABIN, (VOLTAGE,))])
    assert len(transport.requests) == 3
    assert all(o.ok for o in recovered.outcomes)
    assert adapter.backoff.rate_limited_until is None


def test_429_without_retry_after(
    make_adapter: MakeAdapter, transport: StubTransport, clock: FakeClock
) -> None:
    respond_status(transport, 429)
    (outcome,) = make_adapter().poll([(HOME, (VOLTAGE,))]).outcomes
    assert isinstance(outcome.error, VrmRateLimitedError)
    assert outcome.error.retry_after is None
    assert "no Retry-After" in str(outcome.error)
    assert outcome.retry_at == clock.now + BackoffPolicy().rate_limit_delay


@pytest.mark.parametrize("retry_after", ["0", "Wed, 21 Oct 2015 07:28:00 GMT", "5"])
def test_zero_or_past_retry_after_still_defers_the_poll(
    make_adapter: MakeAdapter, transport: StubTransport, clock: FakeClock, retry_after: str
) -> None:
    respond_status(transport, 429, **{"Retry-After": retry_after})
    adapter = make_adapter()
    result = adapter.poll([(HOME, (VOLTAGE,)), (CABIN, (VOLTAGE,))])
    assert len(transport.requests) == 1
    assert [o.deferred for o in result.outcomes] == [False, True]
    assert result.next_attempt_at is not None
    assert result.next_attempt_at > clock.now
    assert result.next_attempt_at == clock.now + BackoffPolicy().rate_limit_delay

    adapter.poll([(HOME, (VOLTAGE,)), (CABIN, (VOLTAGE,))])
    assert len(transport.requests) == 1


def test_429_latches_rest_of_poll_even_if_gate_expires_mid_poll(
    make_adapter: MakeAdapter, transport: StubTransport
) -> None:
    class JumpingClock:
        """Advances a day per reading, so any time-based gate has expired."""

        def __init__(self) -> None:
            self.now = 0.0

        def __call__(self) -> float:
            self.now += 86400.0
            return self.now

    respond_status(transport, 429, **{"Retry-After": "0"})
    third = installation("barn", 345678)
    result = make_adapter(clock=JumpingClock()).poll(
        [(HOME, (VOLTAGE,)), (CABIN, (VOLTAGE,)), (third, (VOLTAGE,))]
    )
    assert len(transport.requests) == 1
    assert [o.deferred for o in result.outcomes] == [False, True, True]
    assert all(isinstance(o.error, VrmRateLimitedError) for o in result.outcomes)


@pytest.mark.parametrize("retry_after", ["999999999", "Wed, 21 Oct 2099 07:28:00 GMT", "  86400  "])
def test_huge_retry_after_is_capped(
    make_adapter: MakeAdapter, transport: StubTransport, clock: FakeClock, retry_after: str
) -> None:
    respond_status(transport, 429, **{"Retry-After": retry_after})
    (outcome,) = make_adapter().poll([(HOME, (VOLTAGE,))]).outcomes
    assert outcome.retry_at == clock.now + BackoffPolicy().max_retry_after


@pytest.mark.parametrize("retry_after", ["soon", "-5", "1e9", ""])
def test_unparseable_retry_after_treated_as_absent(
    make_adapter: MakeAdapter, transport: StubTransport, retry_after: str
) -> None:
    respond_status(transport, 429, **{"Retry-After": retry_after})
    (outcome,) = make_adapter().poll([(HOME, (VOLTAGE,))]).outcomes
    assert isinstance(outcome.error, VrmRateLimitedError)
    assert outcome.error.retry_after is None


def test_5xx_backoff_grows_and_caps(
    make_adapter: MakeAdapter, transport: StubTransport, clock: FakeClock
) -> None:
    respond_status(transport, 503)
    adapter = make_adapter(backoff=Backoff(BackoffPolicy(base_delay=30, max_delay=200, jitter=0)))
    delays = []
    for _ in range(6):
        (outcome,) = adapter.poll([(HOME, (VOLTAGE,))]).outcomes
        assert isinstance(outcome.error, VrmUnavailableError)
        assert outcome.error.status == 503
        assert outcome.retry_at is not None
        delays.append(outcome.retry_at - clock.now)
        clock.now = outcome.retry_at
    assert delays == [30, 60, 120, 200, 200, 200]
    assert len(transport.requests) == 6
    assert adapter.backoff.state("123456").failures == 6

    transport.respond(ok_handler)
    (outcome,) = adapter.poll([(HOME, (VOLTAGE,))]).outcomes
    assert outcome.ok
    assert adapter.backoff.state("123456").failures == 0


def test_jittered_backoff_stays_within_bounds(
    make_adapter: MakeAdapter, transport: StubTransport, clock: FakeClock
) -> None:
    respond_status(transport, 500)
    draws = iter([0.0, 0.999, 0.5])
    policy = BackoffPolicy(base_delay=100, max_delay=1000, jitter=0.25)
    adapter = make_adapter(backoff=Backoff(policy, rng=lambda: next(draws)))
    delays = []
    for _ in range(3):
        (outcome,) = adapter.poll([(HOME, (VOLTAGE,))]).outcomes
        assert outcome.retry_at is not None
        delays.append(outcome.retry_at - clock.now)
        clock.now = outcome.retry_at
    assert delays == pytest.approx([100.0, 150.05, 350.0])


def test_repeated_installation_is_fetched_once(
    make_adapter: MakeAdapter, transport: StubTransport
) -> None:
    transport.respond(ok_handler)
    result = make_adapter().poll(
        [(HOME, (VOLTAGE,)), (CABIN, (SOC,)), (HOME, (SOC, VOLTAGE)), (HOME, (VOLTAGE,))]
    )
    assert [site_of(r) for r in transport.requests] == [HOME.site_id, CABIN.site_id]
    assert [o.installation for o in result.outcomes] == [HOME, CABIN, HOME, HOME]
    readings = [o.reading for o in result.outcomes]
    assert all(r is not None for r in readings)
    assert [[x.measurement for x in r.results] for r in readings] == [  # type: ignore[union-attr]
        [VOLTAGE],
        [SOC],
        [SOC, VOLTAGE],
        [VOLTAGE],
    ]
    assert readings[0].results[0].sample.value == 50.0  # type: ignore[union-attr]
    assert readings[1].results[0].sample.value == 90.0  # type: ignore[union-attr]


def test_distinct_installations_sharing_a_site_are_fetched_once(
    make_adapter: MakeAdapter, transport: StubTransport, clock: FakeClock
) -> None:
    alias = Installation(id="home-alias", site_id=HOME.site_id)
    transport.respond(ok_handler)
    adapter = make_adapter()
    result = adapter.poll([(HOME, (VOLTAGE,)), (alias, (SOC, PV))])
    assert len(transport.requests) == 1
    home, other = result.outcomes
    assert home.installation == HOME
    assert other.installation == alias
    assert other.reading is not None
    assert other.reading.installation == alias
    assert [r.measurement for r in other.reading.results] == [SOC, PV]
    assert other.reading.result_for(PV).problem is None  # type: ignore[union-attr]

    respond_status(transport, 503)
    failed = adapter.poll([(HOME, (VOLTAGE,)), (alias, (SOC,))])
    assert len(transport.requests) == 2
    assert failed.outcomes[0].error is not failed.outcomes[1].error
    assert [o.error.installation for o in failed.outcomes] == ["home", "home-alias"]  # type: ignore[union-attr]
    assert failed.outcomes[0].retry_at == failed.outcomes[1].retry_at
    assert adapter.backoff.state(str(HOME.site_id)).failures == 1

    deferred = adapter.poll([(alias, (SOC,)), (HOME, (VOLTAGE,))])
    assert len(transport.requests) == 2
    assert all(o.deferred for o in deferred.outcomes)
    assert clock.now < failed.outcomes[0].retry_at  # type: ignore[operator]


@pytest.mark.parametrize(
    ("status", "headers", "error_type"),
    [
        (503, {}, VrmUnavailableError),
        (401, {}, VrmAuthError),
        (404, {}, VrmRejectedError),
        (429, {"Retry-After": "300"}, VrmRateLimitedError),
    ],
)
def test_aliases_sharing_a_failing_site_get_their_own_errors(
    make_adapter: MakeAdapter,
    transport: StubTransport,
    status: int,
    headers: dict[str, str],
    error_type: type[VrmError],
) -> None:
    alias = Installation(id="home-alias", site_id=HOME.site_id)
    transport.respond(
        lambda r: httpx.Response(
            status,
            content=f"body {FAKE_TOKEN}".encode(),
            headers={"x-echo": r.headers[AUTH_HEADER], **headers},
        )
    )
    adapter = make_adapter()
    result = adapter.poll([(HOME, (VOLTAGE,)), (alias, (SOC,)), (CABIN, (VOLTAGE,))])
    assert [site_of(r) for r in transport.requests] == [HOME.site_id] + (
        [] if status == 429 else [CABIN.site_id]
    )
    home, other, _cabin = result.outcomes
    assert isinstance(home.error, error_type)
    assert isinstance(other.error, error_type)
    assert home.error is not other.error
    assert home.error.installation == "home"
    assert other.error.installation == "home-alias"
    for outcome in (home, other):
        error = outcome.error
        assert error is not None
        name = outcome.installation.id
        assert error.kind is home.error.kind
        assert error.detail == home.error.detail
        assert error.transient is home.error.transient
        assert str(error) == f"VRM {error.kind.value} for installation {name!r}: {error.detail}"
        assert repr(error) == f"{error_type.__name__}({str(error)!r})"
        assert error.args == (str(error),)
        assert getattr(error, "status", None) == status
        assert getattr(error, "retry_after", None) == getattr(home.error, "retry_after", None)
        assert error.__cause__ is None
        assert error.__context__ is None
        text = "".join(traceback.format_exception(error)) + repr(vars(error))
        assert FAKE_TOKEN not in text
        assert "123456" not in text
    assert home.retry_at == other.retry_at
    assert home.retry_at is not None
    assert not home.deferred
    assert not other.deferred

    deferred = adapter.poll([(alias, (SOC,)), (HOME, (VOLTAGE,))])
    assert all(o.deferred for o in deferred.outcomes)
    assert [o.error.installation for o in deferred.outcomes] == ["home-alias", "home"]  # type: ignore[union-attr]
    assert deferred.outcomes[0].error is not deferred.outcomes[1].error


def test_rate_limit_from_another_site_keeps_its_attribution(
    make_adapter: MakeAdapter, transport: StubTransport
) -> None:
    respond_status(transport, 429, **{"Retry-After": "300"})
    result = make_adapter().poll([(HOME, (VOLTAGE,)), (CABIN, (VOLTAGE,))])
    home, cabin = result.outcomes
    assert cabin.deferred
    assert repr(cabin.error) == repr(home.error)
    assert cabin.error.installation == "home"  # type: ignore[union-attr]


def test_error_copy_is_independent() -> None:
    original = VrmRateLimitedError("home", retry_after=12.0)
    copy = original.for_installation("cabin")
    assert type(copy) is VrmRateLimitedError
    assert (copy.installation, copy.retry_after, copy.status) == ("cabin", 12.0, 429)
    assert original.installation == "home"
    assert str(original) == "VRM rate_limited for installation 'home': HTTP 429 (Retry-After 12s)"
    assert str(copy) == "VRM rate_limited for installation 'cabin': HTTP 429 (Retry-After 12s)"
    assert copy.__traceback__ is None


def test_failure_in_one_installation_does_not_defer_others(
    make_adapter: MakeAdapter, transport: StubTransport
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if site_of(request) == HOME.site_id:
            return httpx.Response(502)
        return ok_handler(request)

    transport.respond(handler)
    result = make_adapter().poll([(HOME, (VOLTAGE,)), (CABIN, (VOLTAGE,))])
    home, cabin = result.outcomes
    assert isinstance(home.error, VrmUnavailableError)
    assert cabin.ok
    assert result.failures == (home,)
    assert result.next_attempt_at == home.retry_at


@pytest.mark.parametrize(
    ("status", "error_type", "kind"),
    [
        (500, VrmUnavailableError, FailureKind.UNAVAILABLE),
        (502, VrmUnavailableError, FailureKind.UNAVAILABLE),
        (504, VrmUnavailableError, FailureKind.UNAVAILABLE),
        (408, VrmUnavailableError, FailureKind.UNAVAILABLE),
        (400, VrmRejectedError, FailureKind.REJECTED),
        (404, VrmRejectedError, FailureKind.REJECTED),
        (418, VrmRejectedError, FailureKind.REJECTED),
    ],
)
def test_status_mapping(
    make_adapter: MakeAdapter,
    transport: StubTransport,
    status: int,
    error_type: type[VrmError],
    kind: FailureKind,
) -> None:
    respond_status(transport, status)
    with pytest.raises(error_type) as info:
        make_adapter().fetch(HOME, (VOLTAGE,))
    assert info.value.kind is kind
    assert info.value.status == status  # type: ignore[attr-defined]
    assert str(info.value) == f"VRM {kind.value} for installation 'home': HTTP {status}"


def test_redirect_is_a_bad_response(make_adapter: MakeAdapter, transport: StubTransport) -> None:
    transport.respond(
        lambda _r: httpx.Response(302, headers={"location": "https://elsewhere.example.invalid/"})
    )
    with pytest.raises(VrmResponseError, match=r"unexpected redirect \(HTTP 302\)"):
        make_adapter().fetch(HOME, (VOLTAGE,))
    assert len(transport.requests) == 1


def test_timeout_is_unavailable(make_adapter: MakeAdapter, transport: StubTransport) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("read timed out", request=request)

    transport.respond(handler)
    with pytest.raises(VrmUnavailableError, match=r"timeout \(read\)") as info:
        make_adapter().fetch(HOME, (VOLTAGE,))
    assert info.value.transient
    assert info.value.status is None


def test_connection_error_is_unavailable(
    make_adapter: MakeAdapter, transport: StubTransport
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"cannot connect to {request.url}", request=request)

    transport.respond(handler)
    with pytest.raises(VrmUnavailableError, match=r"connection failed \(ConnectError\)"):
        make_adapter().fetch(HOME, (VOLTAGE,))


def test_oversize_body_is_a_bad_response(
    make_adapter: MakeAdapter, transport: StubTransport
) -> None:
    big = diagnostics(*(record("zz", i, 1.0, description="x" * 200) for i in range(50)))
    transport.respond(lambda _r: json_response(big))
    with pytest.raises(VrmResponseError, match="response exceeded 4096 bytes"):
        make_adapter(max_response_bytes=4096).fetch(HOME, (VOLTAGE,))


def test_compressed_body_is_refused(make_adapter: MakeAdapter, transport: StubTransport) -> None:
    transport.respond(
        lambda _r: httpx.Response(200, content=b"\x1f\x8b", headers={"content-encoding": "gzip"})
    )
    with pytest.raises(VrmResponseError, match="compressed response refused"):
        make_adapter().fetch(HOME, (VOLTAGE,))


@pytest.mark.parametrize("body", [b"", b"{not json", b"\xff\xfe", b"[" * 100_000])
def test_malformed_json_is_a_bad_response(
    make_adapter: MakeAdapter, transport: StubTransport, body: bytes
) -> None:
    transport.respond(lambda _r: httpx.Response(200, content=body))
    with pytest.raises(VrmResponseError, match="response is not valid JSON"):
        make_adapter().fetch(HOME, (VOLTAGE,))


def test_records_as_object_is_a_bad_response_and_backs_off(
    make_adapter: MakeAdapter, transport: StubTransport, clock: FakeClock
) -> None:
    transport.respond(lambda _r: json_response({"success": True, "records": {"0": {}}}))
    adapter = make_adapter()
    (outcome,) = adapter.poll([(HOME, (VOLTAGE,))]).outcomes
    assert isinstance(outcome.error, VrmResponseError)
    assert outcome.error.kind is FailureKind.BAD_RESPONSE
    assert outcome.retry_at == clock.now + BackoffPolicy().base_delay


@pytest.mark.parametrize("status", [100, 101, 103])
def test_informational_status_is_a_transient_bad_response(
    make_adapter: MakeAdapter, transport: StubTransport, clock: FakeClock, status: int
) -> None:
    respond_status(transport, status)
    (outcome,) = make_adapter().poll([(HOME, (VOLTAGE,))]).outcomes
    assert isinstance(outcome.error, VrmResponseError)
    assert outcome.error.transient
    assert outcome.error.detail == f"unexpected status (HTTP {status})"
    assert outcome.retry_at == clock.now + BackoffPolicy().base_delay


@pytest.mark.parametrize(
    ("status", "error_type"),
    [
        (304, VrmResponseError),
        (399, VrmResponseError),
        (600, VrmResponseError),
        (999, VrmResponseError),
        (599, VrmUnavailableError),
        (499, VrmRejectedError),
        (400, VrmRejectedError),
    ],
)
def test_status_classes_that_slip_past_the_client(status: int, error_type: type[VrmError]) -> None:
    exc = HttpStatusError("GET", "https://vrm.example.invalid/v2", status=status)
    error = _translate(exc, "home")
    assert type(error) is error_type
    assert error.transient is (error_type is not VrmRejectedError)


@pytest.mark.parametrize(
    "exc",
    [
        InvalidRequestError("request body or parameters could not be encoded"),
        InvalidHeaderError("value of header 'X-Authorization' is too long"),
    ],
)
def test_unbuildable_request_is_rejected(exc: Exception) -> None:
    error = _translate(exc, "home")  # type: ignore[arg-type]
    assert isinstance(error, VrmRejectedError)
    assert error.detail == "request could not be built"
    assert not error.transient


# Result types


def test_outcome_requires_exactly_one_of_reading_and_error() -> None:
    reading = InstallationReading(HOME, (), NOW)
    with pytest.raises(ValueError, match="exactly one"):
        InstallationOutcome(HOME)
    with pytest.raises(ValueError, match="exactly one"):
        InstallationOutcome(HOME, reading=reading, error=VrmAuthError("home", status=401))


# Secrets never leak


SECRET_BODY = f'{{"error": "bad token {FAKE_TOKEN}"}}'


@pytest.mark.parametrize("status", [401, 403, 429, 500, 404])
def test_token_absent_from_errors_and_tracebacks(
    make_adapter: MakeAdapter, transport: StubTransport, status: int
) -> None:
    transport.respond(
        lambda r: httpx.Response(
            status,
            content=SECRET_BODY.encode(),
            headers={"x-echo": r.headers[AUTH_HEADER], "retry-after": "5"},
        )
    )
    with pytest.raises(VrmError) as info:
        make_adapter().fetch(HOME, (VOLTAGE,))
    error = info.value
    assert error.__cause__ is None
    assert error.__context__ is None
    rendered = [
        str(error),
        repr(error),
        repr(error.args),
        "".join(traceback.format_exception(error)),
        repr(vars(error)),
    ]
    for text in rendered:
        assert FAKE_TOKEN not in text
        assert "vrm.example.invalid" not in text
        assert "123456" not in text
        assert "count=" not in text
        assert "bad token" not in text


def test_token_absent_from_transport_error_text(
    make_adapter: MakeAdapter, transport: StubTransport
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"{request.url} {request.headers[AUTH_HEADER]}", request=request)

    transport.respond(handler)
    with pytest.raises(VrmUnavailableError) as info:
        make_adapter().fetch(HOME, (VOLTAGE,))
    text = "".join(traceback.format_exception(info.value))
    assert FAKE_TOKEN not in text
    assert "vrm.example.invalid" not in text
    assert not isinstance(info.value, HttpTransportError)


def test_token_registered_with_redaction_registry(
    make_adapter: MakeAdapter, registry: SecretRegistry
) -> None:
    make_adapter()
    assert registry.contains(FAKE_TOKEN)
    assert registry.contains(f"X-Authorization: Token {FAKE_TOKEN}")
    assert FAKE_TOKEN not in registry.redact(f"header was Token {FAKE_TOKEN}")


def test_default_registration_uses_process_registry(
    http: SafeHttpClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    monkeypatch.setattr(adapter_module, "register_secret", calls.append)
    monkeypatch.setattr(adapter_module, "register_derived_secret", calls.append)
    VrmAdapter(http, Secret(FAKE_TOKEN))
    assert calls == [FAKE_TOKEN, f"Token {FAKE_TOKEN}"]


def test_adapter_repr_and_pickle_do_not_reveal_token(make_adapter: MakeAdapter) -> None:
    adapter = make_adapter()
    assert FAKE_TOKEN not in repr(adapter)
    assert FAKE_TOKEN not in str(adapter)
    with pytest.raises(TypeError):
        pickle.dumps(adapter)


def test_failure_logs_are_redacted(
    make_adapter: MakeAdapter,
    transport: StubTransport,
    registry: SecretRegistry,
    caplog: pytest.LogCaptureFixture,
) -> None:
    transport.respond(
        lambda r: httpx.Response(
            401, content=SECRET_BODY.encode(), headers={"x-echo": r.headers[AUTH_HEADER]}
        )
    )
    adapter = make_adapter()
    with caplog.at_level(logging.DEBUG):
        adapter.poll([(HOME, (VOLTAGE,))])
    assert FAKE_TOKEN not in caplog.text
    (warning,) = [r for r in caplog.records if r.name == "vrm_alert_relay.vrm.adapter"]
    assert warning.levelno == logging.WARNING
    assert warning.vrm_installation == "home"  # type: ignore[attr-defined]
    assert warning.vrm_failure == "auth"  # type: ignore[attr-defined]
    assert warning.vrm_detail == "HTTP 401"  # type: ignore[attr-defined]

    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter(registry=registry))
    for log_record in caplog.records:
        handler.handle(log_record)
    # A record that did carry the token is still redacted by the formatter.
    leaked = logging.LogRecord("t", logging.ERROR, __file__, 1, "token %s", (FAKE_TOKEN,), None)
    handler.handle(leaked)
    output = stream.getvalue()
    assert FAKE_TOKEN not in output
    assert json.loads(output.splitlines()[-1])["msg"] == "token [REDACTED]"


def test_malicious_labels_cannot_redirect_or_inject(
    make_adapter: MakeAdapter, transport: StubTransport
) -> None:
    hostile = (
        "https://attacker.example.invalid/\r\nX-Authorization: Token stolen\n"
        '{"recipients": ["attacker"]} \u202e' + "\x00" * 100 + "Q" * 100_000
    )
    transport.respond(
        lambda _r: json_response(diagnostics(record("bv", 0, 50.0, description=hostile)))
    )
    adapter = make_adapter()
    result = adapter.poll([(HOME, (VOLTAGE,))])
    result = adapter.poll([(HOME, (VOLTAGE,))])
    (outcome,) = result.outcomes
    assert outcome.reading is not None
    (reading,) = outcome.reading.results
    assert reading.sample is not None
    assert reading.sample.value == 50.0
    assert reading.label is not None
    assert "\n" not in reading.label
    assert "\r" not in reading.label
    assert "\u202e" not in reading.label
    assert len(reading.label) <= 80
    assert {r.url.host for r in transport.requests} == {"vrm.example.invalid"}
    assert all(r.url.path == "/v2/installations/123456/diagnostics" for r in transport.requests)
    assert BASE_URL.startswith("https://")

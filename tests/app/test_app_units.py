"""Unit tests for the scheduler, monitoring, rule bindings and failure containment."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import pytest
from app_helpers import START, freezer_rule

from vrm_alert_relay.app import (
    DEGRADED_AFTER_CYCLES,
    MonitoringTracker,
    PollHealth,
    Scheduler,
    StartupError,
    assess,
    open_runtime,
)
from vrm_alert_relay.app import relay as relay_module
from vrm_alert_relay.app import service as service_module
from vrm_alert_relay.app.monitoring import monitor_id
from vrm_alert_relay.app.rules import poll_targets
from vrm_alert_relay.app.scheduler import JITTER
from vrm_alert_relay.config import Installation, Measurement, RelaySecrets, parse_config
from vrm_alert_relay.engine import RuleState, Sample
from vrm_alert_relay.net import InvalidCaFileError
from vrm_alert_relay.providers import ProviderSetupError
from vrm_alert_relay.vrm import (
    InstallationOutcome,
    InstallationReading,
    MeasurementResult,
    ReadingProblem,
    VrmAuthError,
    VrmRateLimitedError,
    VrmRejectedError,
    VrmUnavailableError,
)

if TYPE_CHECKING:
    from app_helpers import Harness

CABIN = Installation(id="cabin", site_id=123456)
FREEZER = Measurement(code="tsT", instance=20)


# Scheduler -------------------------------------------------------------------


@dataclass
class FakeStop:
    """Stops after ``limit`` waits; records how long each wait was."""

    limit: int = 1_000
    waits: list[float] = field(default_factory=list)
    stopped: bool = False

    def is_set(self) -> bool:
        return self.stopped

    def wait(self, timeout: float | None = None) -> bool:
        assert timeout is not None
        self.waits.append(timeout)
        if len(self.waits) >= self.limit:
            self.stopped = True
        return self.stopped


def test_scheduler_waits_the_interval_plus_jitter_between_cycle_starts() -> None:
    now = [100.0]
    calls: list[float] = []

    def cycle() -> None:
        calls.append(now[0])
        now[0] += 5.0  # the cycle takes five seconds

    stop = FakeStop(limit=3)
    scheduler = Scheduler(cycle, interval=60.0, stop=stop, clock=lambda: now[0], rng=lambda: 0.5)

    assert scheduler.run() == 3
    assert stop.waits == [pytest.approx(58.0)] * 3  # 60 * 1.05 - 5


@pytest.mark.parametrize(
    ("draw", "expected"), [(-1.0, 60.0), (0.0, 60.0), (2.0, 60.0 * (1 + JITTER))]
)
def test_jitter_never_shortens_the_interval(draw: float, expected: float) -> None:
    scheduler = Scheduler(lambda: None, interval=60.0, stop=FakeStop(), rng=lambda: draw)

    assert scheduler.next_delay() == pytest.approx(expected)


def test_default_jitter_stays_within_bounds() -> None:
    scheduler = Scheduler(lambda: None, interval=30.0, stop=FakeStop())

    for _ in range(50):
        assert 30.0 <= scheduler.next_delay() <= 33.0


def test_a_slow_cycle_starts_the_next_one_at_once() -> None:
    now = [0.0]

    def slow() -> None:
        now[0] += 500.0

    stop = FakeStop(limit=1)
    Scheduler(slow, interval=60.0, stop=stop, clock=lambda: now[0], rng=lambda: 0.0).run()

    assert stop.waits == [0.0]


def test_max_cycles_ends_the_loop_without_waiting() -> None:
    stop = FakeStop()
    count = Scheduler(lambda: None, interval=60.0, stop=stop).run(max_cycles=1)

    assert count == 1
    assert stop.waits == []


def test_a_stop_set_before_the_first_cycle_runs_nothing() -> None:
    stop = FakeStop(stopped=True)
    calls: list[int] = []

    assert Scheduler(lambda: calls.append(1), interval=60.0, stop=stop).run() == 0
    assert calls == []


def test_a_failing_cycle_is_logged_and_the_loop_continues(
    caplog: pytest.LogCaptureFixture,
) -> None:
    after: list[int] = []

    def broken() -> None:
        raise RuntimeError("boom")

    def after_cycle() -> None:
        after.append(1)
        raise ValueError("health update failed")

    stop = FakeStop(limit=2)
    with caplog.at_level(logging.ERROR):
        count = Scheduler(broken, interval=60.0, stop=stop, after_cycle=after_cycle).run()

    assert count == 2
    assert after == [1, 1]
    names = [getattr(r, "event", None) for r in caplog.records]
    assert names.count("relay.cycle_error") == 2
    assert names.count("relay.after_cycle_error") == 2


def test_the_interval_must_be_positive() -> None:
    with pytest.raises(ValueError, match="interval must be positive"):
        Scheduler(lambda: None, interval=0, stop=FakeStop())


def test_service_run_uses_injected_clock_and_rng(harness: Harness) -> None:
    harness.write_config()
    stop = FakeStop(limit=2)
    with harness.service() as service:
        cycles = service.run(stop, clock=harness.clock.monotonic, rng=lambda: 1.0)

    assert cycles == 2
    assert stop.waits == [pytest.approx(66.0)] * 2


# Monitoring --------------------------------------------------------------------


def reading(*results: MeasurementResult) -> InstallationOutcome:
    return InstallationOutcome(CABIN, reading=InstallationReading(CABIN, results, START))


def test_assess_classifies_outcomes() -> None:
    ok = MeasurementResult(FREEZER, sample=Sample(1.0, START))
    missing = MeasurementResult(FREEZER, problem=ReadingProblem.MISSING)

    assert assess(reading(ok)) == PollHealth(failed=False)
    assert assess(reading()) == PollHealth(failed=False)
    assert assess(reading(missing)) == PollHealth(failed=True, reason="measurement_missing")
    assert assess(None) == PollHealth(failed=True, reason="poll_error")
    for error, immediate in (
        (VrmAuthError("cabin", status=401), True),
        (VrmRejectedError("cabin", "HTTP 404", status=404), True),
        (VrmUnavailableError("cabin", "HTTP 503", status=503), False),
        (VrmRateLimitedError("cabin", retry_after=600.0), False),
    ):
        health = assess(InstallationOutcome(CABIN, error=error, deferred=True))
        assert health == PollHealth(failed=True, immediate=immediate, reason=error.kind.value)


def run_monitor(tracker: MonitoringTracker, polls: list[PollHealth]) -> tuple[RuleState, list[str]]:
    state = RuleState()
    texts: list[str] = []
    now = START
    for poll in polls:
        states, notifications = tracker.observe({"cabin": poll}, {"cabin": state}, now)
        state = states["cabin"]
        texts.extend(n.text for n in notifications)
        now += timedelta(minutes=1)
    return state, texts


FAIL = PollHealth(failed=True, reason="unavailable")
OK = PollHealth(failed=False)


def test_one_failed_poll_is_not_an_outage() -> None:
    _, texts = run_monitor(MonitoringTracker(["cabin"]), [FAIL, OK, FAIL, OK])

    assert texts == []


def test_a_streak_degrades_once_and_restores_once() -> None:
    tracker = MonitoringTracker(["cabin"])
    polls = [FAIL] * (DEGRADED_AFTER_CYCLES + 3) + [OK, OK]

    state, texts = run_monitor(tracker, polls)

    assert len(texts) == 2
    assert "degraded since 2035-01-01 00:00 UTC" in texts[0]
    assert texts[1] == "VRM Alert Relay: monitoring of cabin is restored (2035-01-01 00:05 UTC)"
    assert state.active_level is None
    assert tracker.degraded == frozenset()
    assert tracker.failing == frozenset()


def test_an_immediate_failure_degrades_at_once() -> None:
    tracker = MonitoringTracker(["cabin"])
    _, texts = run_monitor(tracker, [PollHealth(failed=True, immediate=True, reason="auth")])

    assert len(texts) == 1
    assert tracker.degraded == frozenset({"cabin"})
    assert tracker.failing == frozenset({"cabin"})


def test_an_open_outage_is_kept_after_a_restart() -> None:
    state, texts = run_monitor(MonitoringTracker(["cabin"]), [FAIL, FAIL])
    assert len(texts) == 1

    restarted = MonitoringTracker(["cabin"])
    states, notifications = restarted.observe(
        {"cabin": FAIL}, {"cabin": state}, START + timedelta(hours=1)
    )

    assert notifications == []
    assert states["cabin"].active_level == "degraded"


def test_a_missing_poll_outcome_counts_as_failed() -> None:
    tracker = MonitoringTracker(["cabin"])
    state = RuleState()
    for minute in range(DEGRADED_AFTER_CYCLES):
        states, notifications = tracker.observe(
            {}, {"cabin": state}, START + timedelta(minutes=minute)
        )
        state = states["cabin"]

    assert len(notifications) == 1
    assert tracker.installations == ("cabin",)


def test_monitor_events_other_than_escalation_and_recovery_send_nothing() -> None:
    tracker = MonitoringTracker(["cabin"])
    # A stored monitor state marked stale makes the engine report "data restored".
    states, notifications = tracker.observe({"cabin": OK}, {"cabin": RuleState(stale=True)}, START)

    assert notifications == []
    assert states["cabin"].stale is False


# Rule bindings -------------------------------------------------------------------


def test_every_installation_is_polled_with_its_rules_measurements() -> None:
    config = parse_config(
        """
version: 1
vrm:
  token_file: /run/secrets/fictitious-token
  installations: [{id: cabin, site_id: 123456}, {id: barn, site_id: 234567}]
recipients: {audit: {provider: log}}
rules:
  - {id: a, installation: cabin, measurement: {code: tsT, instance: 20}, direction: rising,
     levels: [{name: warning, threshold: 1}], recipients: [audit]}
  - {id: b, installation: cabin, measurement: {code: tsT, instance: 20}, direction: falling,
     levels: [{name: warning, threshold: 1}], recipients: [audit]}
  - {id: c, installation: cabin, measurement: {code: bs, instance: 512}, direction: falling,
     levels: [{name: warning, threshold: 1}], recipients: [audit]}
"""
    )

    targets = poll_targets(config)

    assert [(inst.id, [m.code for m in ms]) for inst, ms in targets] == [
        ("cabin", ["tsT", "bs"]),
        ("barn", []),
    ]


# Failure containment in the cycle -------------------------------------------------


def test_a_poll_that_raises_counts_as_a_failure_of_every_installation(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    harness.write_config()
    with harness.service() as service:

        def broken(_self: Any, _targets: Any) -> Any:
            raise RuntimeError("adapter bug")

        monkeypatch.setattr(type(service.adapter), "poll", broken)
        with caplog.at_level(logging.ERROR):
            harness.cycle(service, DEGRADED_AFTER_CYCLES)
        status = service.relay.status

    assert status.degraded == 1
    assert any(getattr(r, "event", None) == "relay.poll_error" for r in caplog.records)
    assert any("monitoring of cabin is degraded" in t for t in harness.voipms.texts())


def test_rule_evaluation_failure_retries_from_fresh_state(
    harness: Harness, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -10)
    real = relay_module.evaluate
    seen: list[RuleState] = []

    def flaky(spec: Any, state: RuleState, sample: Any, now: Any) -> Any:
        seen.append(state)
        if spec.rule_id == "freezer" and len(seen) == 1:
            raise RuntimeError("corrupt state")
        return real(spec, state, sample, now)

    monkeypatch.setattr(relay_module, "evaluate", flaky)
    with caplog.at_level(logging.ERROR), harness.service() as service:
        harness.cycle(service)

    assert harness.voipms.texts()[0].startswith("warning: freezer at cabin")
    assert seen[1] == RuleState()
    assert any(getattr(r, "event", None) == "relay.evaluation_error" for r in caplog.records)


def test_a_rule_that_cannot_be_evaluated_is_skipped_and_others_continue(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.write_config(
        rules=[
            freezer_rule(),
            freezer_rule(id="fridge", measurement={"code": "tsT", "instance": 21}),
        ]
    )
    harness.vrm.set("tsT", 20, -10)
    harness.vrm.set("tsT", 21, -10)
    real = relay_module.evaluate

    def broken_freezer(spec: Any, state: RuleState, sample: Any, now: Any) -> Any:
        if spec.rule_id == "freezer":
            raise RuntimeError("always fails")
        return real(spec, state, sample, now)

    monkeypatch.setattr(relay_module, "evaluate", broken_freezer)
    with harness.service() as service:
        harness.cycle(service)

    assert [t.split(":")[1].strip().split()[0] for t in harness.voipms.texts()] == ["fridge"]


def test_a_failing_level_message_falls_back_to_the_default_text(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.write_config()
    harness.vrm.set("tsT", 20, -10)
    with harness.service() as service:
        binding = service.relay._bindings[0]

        def broken(*_args: Any) -> str:
            raise RuntimeError("template bug")

        monkeypatch.setattr(type(binding), "render", broken)
        harness.cycle(service)

    assert harness.voipms.texts() == [
        "warning: freezer at cabin: Fictitious tsT is -10 (2035-01-01 00:00 UTC)"
    ]


def test_monitor_state_is_stored_under_its_own_key(harness: Harness) -> None:
    harness.write_config()
    harness.vrm.fail(401)
    with harness.service() as service:
        harness.cycle(service)
        state = service.runtime.delivery.rule_state(monitor_id("cabin"))

    assert state.active_level == "degraded"


# Service startup failures ------------------------------------------------------------


def test_a_provider_that_cannot_be_built_is_a_configuration_error(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.write_config()

    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise ProviderSetupError("providers.voipms.did: is required for a live provider")

    monkeypatch.setattr(service_module, "build_providers", refuse)
    with pytest.raises(StartupError) as excinfo:
        open_runtime(harness.config_path, harness.state_dir)

    assert excinfo.value.code == 3
    assert excinfo.value.problems == ("providers.voipms.did: is required for a live provider",)


def test_an_unloadable_ca_file_is_a_configuration_error(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.write_config()

    def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise InvalidCaFileError("the CA file is not PEM")

    monkeypatch.setattr(service_module, "build_providers", refuse)
    with pytest.raises(StartupError) as excinfo:
        open_runtime(harness.config_path, harness.state_dir)

    assert excinfo.value.code == 3


def test_a_missing_vrm_token_is_a_configuration_error(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.write_config()
    monkeypatch.setattr(service_module, "load_secrets", lambda _config: (RelaySecrets(), []))

    with pytest.raises(StartupError) as excinfo:
        open_runtime(harness.config_path, harness.state_dir)

    assert excinfo.value.problems == ("vrm.token_file: the token was not loaded",)


def test_an_unexpected_startup_failure_releases_the_state_directory(
    harness: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness.write_config()

    def broken(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("engine bug")

    monkeypatch.setattr(service_module.DeliveryEngine, "from_config", broken)
    with pytest.raises(RuntimeError, match="engine bug"):
        open_runtime(harness.config_path, harness.state_dir)
    monkeypatch.undo()

    open_runtime(harness.config_path, harness.state_dir).close()


def test_secret_file_warnings_are_logged(
    harness: Harness, caplog: pytest.LogCaptureFixture
) -> None:
    harness.write_config()
    (harness.root / "secrets" / "vrm_token").chmod(0o644)

    with caplog.at_level(logging.WARNING):
        open_runtime(harness.config_path, harness.state_dir).close()

    warnings = [r for r in caplog.records if getattr(r, "event", None) == "config.warning"]
    assert [r.getMessage() for r in warnings] == [
        (
            "vrm.token_file: secret file is readable by group or others; "
            "restrict it to mode 0600 or 0400"
        )
    ]

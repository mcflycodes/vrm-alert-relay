"""Behaviour tests for deterministic rule evaluation."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from vrm_alert_relay.engine import (
    Direction,
    EventKind,
    InvalidRuleStateError,
    LevelSpec,
    RuleSpec,
    RuleState,
    Sample,
    evaluate,
)

BASE = datetime(2030, 1, 1, tzinfo=UTC)


def rising_rule(**changes: object) -> RuleSpec:
    values: dict[str, object] = {
        "rule_id": "fictitious-temperature",
        "direction": Direction.RISING,
        "levels": (
            LevelSpec("warning", 10.0),
            LevelSpec("alert", 20.0),
            LevelSpec("critical", 30.0),
        ),
        "stale_after": timedelta(hours=12),
    }
    values.update(changes)
    return RuleSpec(**values)  # type: ignore[arg-type]


def step(
    rule: RuleSpec,
    state: RuleState,
    minute: int,
    value: float,
) -> tuple[RuleState, list[EventKind]]:
    moment = BASE + timedelta(minutes=minute)
    new_state, events = evaluate(rule, state, Sample(value, moment), moment)
    return new_state, [event.kind for event in events]


def test_rising_ladder_and_multilevel_jump_emit_highest_only() -> None:
    rule = rising_rule()
    initial = RuleState()

    state, events = evaluate(rule, initial, Sample(9.0, BASE), BASE)
    assert state.active_level is None
    assert events == []
    assert initial == RuleState()

    state, events = evaluate(
        rule,
        state,
        Sample(35.0, BASE + timedelta(minutes=1)),
        BASE + timedelta(minutes=1),
    )
    assert state.active_level == 2
    assert state.episode == 1
    assert [(event.kind, event.level) for event in events] == [
        (EventKind.ESCALATED, "critical")
    ]

    unchanged, events = evaluate(
        rule,
        state,
        Sample(36.0, BASE + timedelta(minutes=2)),
        BASE + timedelta(minutes=2),
    )
    assert unchanged.active_level == 2
    assert events == []


def test_falling_ladder_crosses_inclusive_thresholds() -> None:
    rule = RuleSpec(
        "fictitious-charge",
        Direction.FALLING,
        (
            LevelSpec("warning", 50.0),
            LevelSpec("alert", 30.0),
            LevelSpec("critical", 10.0),
        ),
        stale_after=timedelta(hours=1),
    )

    state, events = evaluate(rule, RuleState(), Sample(30.0, BASE), BASE)
    assert state.active_level == 1
    assert [(event.kind, event.level) for event in events] == [
        (EventKind.ESCALATED, "alert")
    ]

    state, events = evaluate(
        rule,
        state,
        Sample(10.0, BASE + timedelta(minutes=1)),
        BASE + timedelta(minutes=1),
    )
    assert state.active_level == 2
    assert events[0].level == "critical"


def test_rising_hysteresis_consecutive_clears_and_partial_deescalation() -> None:
    rule = rising_rule(hysteresis=2.0, clear_after_samples=2)
    state, _ = step(rule, RuleState(), 0, 35.0)

    state, kinds = step(rule, state, 1, 28.0)
    assert state.active_level == 2
    assert state.clear_count == 0
    assert kinds == []

    state, _ = step(rule, state, 2, 27.0)
    assert state.clear_count == 1
    state, kinds = step(rule, state, 3, 27.0)
    assert state.active_level == 1
    assert state.clear_count == 0
    assert kinds == []

    state, _ = step(rule, state, 4, 17.0)
    state, kinds = step(rule, state, 5, 17.0)
    assert state.active_level == 0
    assert kinds == []

    state, _ = step(rule, state, 6, 7.0)
    state, kinds = step(rule, state, 7, 7.0)
    assert state.active_level is None
    assert kinds == [EventKind.RECOVERED]


def test_falling_hysteresis_requires_retreat_above_boundary() -> None:
    rule = RuleSpec(
        "fictitious-level",
        Direction.FALLING,
        (LevelSpec("warning", 50.0), LevelSpec("critical", 20.0)),
        hysteresis=5.0,
        clear_after_samples=2,
        stale_after=timedelta(hours=1),
    )
    state, _ = evaluate(rule, RuleState(), Sample(10.0, BASE), BASE)
    state, events = evaluate(
        rule,
        state,
        Sample(25.0, BASE + timedelta(minutes=1)),
        BASE + timedelta(minutes=1),
    )
    assert state.clear_count == 0
    assert events == []
    state, _ = evaluate(
        rule,
        state,
        Sample(26.0, BASE + timedelta(minutes=2)),
        BASE + timedelta(minutes=2),
    )
    state, events = evaluate(
        rule,
        state,
        Sample(26.0, BASE + timedelta(minutes=3)),
        BASE + timedelta(minutes=3),
    )
    assert state.active_level == 0
    assert events == []


def test_duplicate_and_older_samples_do_not_count_toward_clear() -> None:
    rule = rising_rule(hysteresis=1.0, clear_after_samples=2)
    state, _ = step(rule, RuleState(), 10, 11.0)
    state, _ = step(rule, state, 11, 8.0)
    assert state.clear_count == 1

    duplicate, events = evaluate(
        rule,
        state,
        Sample(8.0, BASE + timedelta(minutes=11)),
        BASE + timedelta(minutes=12),
    )
    assert duplicate.clear_count == 1
    assert events == []
    older, events = evaluate(
        rule,
        duplicate,
        Sample(8.0, BASE + timedelta(minutes=9)),
        BASE + timedelta(minutes=12),
    )
    assert older.clear_count == 1
    assert older.newest_sample_time == BASE + timedelta(minutes=11)
    assert events == []

    state, kinds = step(rule, older, 13, 8.0)
    assert state.active_level is None
    assert kinds == [EventKind.RECOVERED]


def test_reentry_cooldown_suppresses_then_allows_unique_escalation() -> None:
    rule = rising_rule(
        levels=(LevelSpec("warning", 10.0), LevelSpec("critical", 20.0)),
        cooldown=timedelta(minutes=15),
        clear_after_samples=1,
    )
    state, first = evaluate(rule, RuleState(), Sample(25.0, BASE), BASE)
    first_id = first[0].event_id
    state, _ = step(rule, state, 1, 15.0)
    assert state.active_level == 0

    state, events = evaluate(
        rule,
        state,
        Sample(25.0, BASE + timedelta(minutes=2)),
        BASE + timedelta(minutes=2),
    )
    assert state.active_level == 1
    assert state.suppressed_escalations == 1
    assert events == []

    state, _ = step(rule, state, 3, 15.0)
    state, events = evaluate(
        rule,
        state,
        Sample(25.0, BASE + timedelta(minutes=16)),
        BASE + timedelta(minutes=16),
    )
    assert len(events) == 1
    assert events[0].kind is EventKind.ESCALATED
    assert events[0].event_id != first_id


@pytest.mark.parametrize("notify", [True, False])
def test_recovery_notification_can_be_enabled_or_disabled(notify: bool) -> None:
    rule = rising_rule(levels=(LevelSpec("warning", 10.0),), recovery_notify=notify)
    state, _ = step(rule, RuleState(), 0, 10.0)
    state, kinds = step(rule, state, 1, 9.0)
    assert state.active_level is None
    assert kinds == ([EventKind.RECOVERED] if notify else [])


def test_reminders_obey_interval_count_and_top_level_only() -> None:
    rule = rising_rule(
        reminder_interval=timedelta(minutes=60),
        reminder_max=2,
        stale_after=timedelta(days=1),
    )
    state, _ = step(rule, RuleState(), 0, 20.0)
    state, events = evaluate(rule, state, None, BASE + timedelta(minutes=60))
    assert events == []

    state, _ = step(rule, state, 61, 30.0)
    state, events = evaluate(rule, state, None, BASE + timedelta(minutes=120))
    assert events == []
    state, events = evaluate(rule, state, None, BASE + timedelta(minutes=121))
    assert [event.kind for event in events] == [EventKind.REMINDER]
    first_id = events[0].event_id
    state, events = evaluate(rule, state, None, BASE + timedelta(minutes=181))
    assert [event.kind for event in events] == [EventKind.REMINDER]
    assert events[0].event_id != first_id
    state, events = evaluate(rule, state, None, BASE + timedelta(minutes=500))
    assert events == []
    assert state.reminder_count == 2


def test_zero_reminder_max_disables_reminders() -> None:
    rule = rising_rule(
        levels=(LevelSpec("critical", 10.0),),
        reminder_max=0,
        stale_after=timedelta(days=1),
    )
    state, _ = step(rule, RuleState(), 0, 11.0)
    state, events = evaluate(rule, state, None, BASE + timedelta(hours=10))
    assert events == []
    assert state.reminder_count == 0


def test_stale_and_restored_emit_once_and_thresholds_pause() -> None:
    rule = rising_rule(stale_after=timedelta(minutes=35))
    state, events = evaluate(rule, RuleState(), None, BASE)
    assert [event.kind for event in events] == [EventKind.STALE]
    stale_id = events[0].event_id
    state, events = evaluate(rule, state, None, BASE + timedelta(minutes=1))
    assert events == []

    state, events = evaluate(rule, state, Sample(35.0, BASE), BASE)
    assert [event.kind for event in events] == [
        EventKind.RESTORED,
        EventKind.ESCALATED,
    ]
    assert state.active_level == 2

    state, events = evaluate(rule, state, None, BASE + timedelta(minutes=36))
    assert EventKind.STALE in [event.kind for event in events]
    assert (
        next(event.event_id for event in events if event.kind is EventKind.STALE)
        != stale_id
    )
    state, events = evaluate(
        rule,
        state,
        Sample(0.0, BASE),
        BASE + timedelta(minutes=36),
    )
    assert events == []
    assert state.active_level == 2

    restored_at = BASE + timedelta(minutes=37)
    state, events = evaluate(rule, state, Sample(0.0, restored_at), restored_at)
    assert [event.kind for event in events] == [
        EventKind.RESTORED,
        EventKind.RECOVERED,
    ]
    assert state.active_level is None


def test_reminder_is_evaluated_while_stale() -> None:
    rule = rising_rule(
        levels=(LevelSpec("critical", 10.0),),
        stale_after=timedelta(minutes=5),
        reminder_interval=timedelta(minutes=10),
        reminder_max=1,
    )
    state, _ = step(rule, RuleState(), 0, 11.0)
    state, events = evaluate(rule, state, None, BASE + timedelta(minutes=10))
    assert [event.kind for event in events] == [
        EventKind.STALE,
        EventKind.REMINDER,
    ]


@pytest.mark.parametrize("bad_value", [float("nan"), float("inf"), float("-inf")])
def test_nonfinite_samples_are_treated_as_absent(bad_value: float) -> None:
    rule = rising_rule()
    state, events = evaluate(rule, RuleState(), Sample(bad_value, BASE), BASE)
    assert state.stale
    assert [event.kind for event in events] == [EventKind.STALE]
    assert state.newest_sample_time is None


def test_far_future_and_naive_samples_are_treated_as_absent() -> None:
    rule = rising_rule()
    future = Sample(40.0, BASE + timedelta(seconds=61))
    state, events = evaluate(rule, RuleState(), future, BASE)
    assert state.stale
    assert [event.kind for event in events] == [EventKind.STALE]

    naive = Sample(40.0, datetime(2030, 1, 1))
    state, events = evaluate(rule, RuleState(), naive, BASE)
    assert state.stale
    assert [event.kind for event in events] == [EventKind.STALE]


def test_sixty_second_future_sample_is_accepted() -> None:
    rule = rising_rule()
    sample = Sample(40.0, BASE + timedelta(seconds=60))
    state, events = evaluate(rule, RuleState(), sample, BASE)
    assert state.active_level == 2
    assert [event.kind for event in events] == [EventKind.ESCALATED]


def test_invalid_sample_object_is_treated_as_absent() -> None:
    rule = rising_rule()
    state, events = evaluate(rule, RuleState(), object(), BASE)  # type: ignore[arg-type]
    assert state.stale
    assert [event.kind for event in events] == [EventKind.STALE]


def test_naive_clock_is_rejected_explicitly() -> None:
    with pytest.raises(ValueError, match="aware"):
        evaluate(rising_rule(), RuleState(), None, datetime(2030, 1, 1))


def test_events_are_stable_when_same_prior_state_is_replayed() -> None:
    rule = rising_rule()
    sample = Sample(35.0, BASE)
    first_state, first_events = evaluate(rule, RuleState(), sample, BASE)
    second_state, second_events = evaluate(rule, RuleState(), sample, BASE)
    assert first_state == second_state
    assert first_events == second_events


def test_newer_stale_sample_is_remembered_but_not_evaluated() -> None:
    rule = rising_rule(stale_after=timedelta(minutes=5))
    now = BASE + timedelta(hours=1)
    stale_sample = Sample(35.0, BASE + timedelta(minutes=30))
    state, events = evaluate(rule, RuleState(), stale_sample, now)
    assert state.newest_sample_time == stale_sample.timestamp
    assert state.last_evaluated_sample_time is None
    assert state.active_level is None
    assert [event.kind for event in events] == [EventKind.STALE]


def test_state_inputs_are_not_mutated() -> None:
    rule = rising_rule()
    state = RuleState(
        level_notification_times=(("warning", BASE),),
        level_escalation_counts=(("warning", 1),),
    )
    original = replace(state)
    evaluate(rule, state, Sample(35.0, BASE), BASE)
    assert state == original


def test_bounded_escalation_ordinal_saturates() -> None:
    rule = rising_rule(levels=(LevelSpec("critical", 10.0),))
    state = RuleState(level_escalation_counts=(("critical", 2**63 - 1),))
    state, events = evaluate(rule, state, Sample(11.0, BASE), BASE)
    assert state.level_escalation_counts == (("critical", 2**63 - 1),)
    assert [event.kind for event in events] == [EventKind.ESCALATED]


def test_state_active_level_must_exist_in_rule() -> None:
    rule = rising_rule(levels=(LevelSpec("critical", 10.0),))
    with pytest.raises(InvalidRuleStateError, match="active_level"):
        evaluate(rule, RuleState(active_level=1), None, BASE)

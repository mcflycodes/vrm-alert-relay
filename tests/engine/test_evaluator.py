"""Behaviour tests for deterministic rule evaluation."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone

import pytest

from vrm_alert_relay.engine import (
    Direction,
    EventKind,
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
    assert state.active_level == "critical"
    assert state.episode == 1
    assert [(event.kind, event.level) for event in events] == [(EventKind.ESCALATED, "critical")]

    unchanged, events = evaluate(
        rule,
        state,
        Sample(36.0, BASE + timedelta(minutes=2)),
        BASE + timedelta(minutes=2),
    )
    assert unchanged.active_level == "critical"
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
    assert state.active_level == "alert"
    assert [(event.kind, event.level) for event in events] == [(EventKind.ESCALATED, "alert")]

    state, events = evaluate(
        rule,
        state,
        Sample(10.0, BASE + timedelta(minutes=1)),
        BASE + timedelta(minutes=1),
    )
    assert state.active_level == "critical"
    assert events[0].level == "critical"


def test_rising_hysteresis_consecutive_clears_and_partial_deescalation() -> None:
    rule = rising_rule(hysteresis=2.0, clear_after_samples=2)
    state, _ = step(rule, RuleState(), 0, 35.0)

    state, kinds = step(rule, state, 1, 28.0)
    assert state.active_level == "critical"
    assert state.clear_count == 0
    assert kinds == []

    state, _ = step(rule, state, 2, 27.0)
    assert state.clear_count == 1
    state, kinds = step(rule, state, 3, 27.0)
    assert state.active_level == "alert"
    assert state.clear_count == 0
    assert kinds == []

    state, _ = step(rule, state, 4, 17.0)
    state, kinds = step(rule, state, 5, 17.0)
    assert state.active_level == "warning"
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
    assert state.active_level == "warning"
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
    assert state.active_level == "warning"

    state, events = evaluate(
        rule,
        state,
        Sample(25.0, BASE + timedelta(minutes=2)),
        BASE + timedelta(minutes=2),
    )
    assert state.active_level == "critical"
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
    assert state.active_level == "critical"

    state, events = evaluate(rule, state, None, BASE + timedelta(minutes=36))
    assert EventKind.STALE in [event.kind for event in events]
    assert next(event.event_id for event in events if event.kind is EventKind.STALE) != stale_id
    state, events = evaluate(
        rule,
        state,
        Sample(0.0, BASE),
        BASE + timedelta(minutes=36),
    )
    assert events == []
    assert state.active_level == "critical"

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
    assert state.active_level == "critical"
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


def test_newer_stale_sample_can_escalate() -> None:
    rule = rising_rule(stale_after=timedelta(minutes=5))
    now = BASE + timedelta(hours=1)
    stale_sample = Sample(35.0, BASE + timedelta(minutes=30))
    state, events = evaluate(rule, RuleState(), stale_sample, now)
    assert state.newest_sample_time == stale_sample.timestamp
    assert state.last_evaluated_sample_time == stale_sample.timestamp
    assert state.active_level == "critical"
    assert [event.kind for event in events] == [
        EventKind.STALE,
        EventKind.ESCALATED,
    ]


def test_state_inputs_are_not_mutated() -> None:
    rule = rising_rule()
    state = RuleState(
        level_notification_times=(("warning", BASE),),
    )
    original = replace(state)
    evaluate(rule, state, Sample(35.0, BASE), BASE)
    assert state == original


def test_bounded_escalation_ordinal_saturates() -> None:
    rule = rising_rule(levels=(LevelSpec("warning", 10.0), LevelSpec("critical", 20.0)))
    state = RuleState(
        active_level="warning",
        episode=1,
        newest_sample_time=BASE,
        newest_value=11.0,
        last_evaluated_sample_time=BASE,
        episode_started_at=BASE,
        episode_announced=True,
        episode_notified_levels=("warning",),
        escalation_ordinal=2**63 - 1,
        rule_direction=Direction.RISING,
        level_order=("warning", "critical"),
        level_notification_times=(("warning", BASE),),
    )
    later = BASE + timedelta(minutes=1)
    state, events = evaluate(rule, state, Sample(25.0, later), later)
    assert state.escalation_ordinal == 2**63 - 1
    assert [event.kind for event in events] == [EventKind.ESCALATED]


def test_recovery_after_reminder_clears_episode_state_atomically() -> None:
    rule = rising_rule(
        levels=(LevelSpec("critical", 10.0),),
        reminder_interval=timedelta(minutes=10),
        stale_after=timedelta(days=1),
    )
    state, _ = step(rule, RuleState(), 0, 11.0)
    state, events = evaluate(rule, state, None, BASE + timedelta(minutes=10))
    assert [event.kind for event in events] == [EventKind.REMINDER]
    assert state.reminder_count == 1

    state, kinds = step(rule, state, 11, 5.0)
    assert kinds == [EventKind.RECOVERED]
    assert state.active_level is None
    assert state.reminder_count == 0
    assert state.last_episode_notification_time is None
    assert state.episode_started_at is None
    assert state.level_notification_times == (("critical", BASE),)


def test_suppressed_new_episode_escalates_when_cooldown_expires() -> None:
    rule = rising_rule(
        levels=(LevelSpec("critical", 10.0),),
        cooldown=timedelta(minutes=15),
        reminder_interval=timedelta(minutes=10),
        stale_after=timedelta(days=1),
    )
    state, first = evaluate(rule, RuleState(), Sample(11.0, BASE), BASE)
    state, recovered = evaluate(
        rule,
        state,
        Sample(5.0, BASE + timedelta(minutes=2)),
        BASE + timedelta(minutes=2),
    )
    state, suppressed = evaluate(
        rule,
        state,
        Sample(11.0, BASE + timedelta(minutes=5)),
        BASE + timedelta(minutes=5),
    )
    assert [event.kind for event in recovered] == [EventKind.RECOVERED]
    assert suppressed == []
    assert state.pending_escalation == "critical"
    state, second = evaluate(rule, state, None, BASE + timedelta(minutes=15))
    assert [event.kind for event in second] == [EventKind.ESCALATED]
    assert second[0].event_id != first[0].event_id
    assert state.episode == 2

    state, reminded = evaluate(rule, state, None, BASE + timedelta(minutes=25))
    assert [event.kind for event in reminded] == [EventKind.REMINDER]
    state, recovered_again = evaluate(
        rule,
        state,
        Sample(5.0, BASE + timedelta(minutes=26)),
        BASE + timedelta(minutes=26),
    )
    assert [event.kind for event in recovered_again] == [EventKind.RECOVERED]


def test_removed_and_readded_level_keeps_cooldown_history() -> None:
    original = rising_rule(
        levels=(LevelSpec("warning", 10.0), LevelSpec("alert", 20.0)),
        cooldown=timedelta(minutes=15),
        stale_after=timedelta(days=1),
    )
    without_alert = rising_rule(
        levels=(LevelSpec("warning", 10.0),),
        cooldown=timedelta(minutes=15),
        stale_after=timedelta(days=1),
    )
    state, first = step(original, RuleState(), 0, 25.0)
    state, removed_events = evaluate(without_alert, state, None, BASE + timedelta(minutes=1))
    state, readded_events = step(original, state, 12, 25.0)

    assert first == [EventKind.ESCALATED]
    assert removed_events == []
    assert readded_events == []
    assert state.pending_escalation == "alert"
    assert dict(state.level_notification_times)["alert"] == BASE

    state, released = evaluate(original, state, None, BASE + timedelta(minutes=15))
    assert [event.kind for event in released] == [EventKind.ESCALATED]
    assert released[0].level == "alert"
    assert state.pending_escalation is None


def test_threshold_oscillation_is_bounded_by_cross_episode_cooldown() -> None:
    rule = rising_rule(
        levels=(LevelSpec("critical", 10.0),),
        cooldown=timedelta(minutes=15),
        stale_after=timedelta(days=1),
    )
    state = RuleState()
    emitted: list[tuple[int, EventKind]] = []
    for minute in range(60):
        value = 10.0 if minute % 2 == 0 else 9.0
        now = BASE + timedelta(minutes=minute)
        state, events = evaluate(rule, state, Sample(value, now), now)
        emitted.extend((minute, event.kind) for event in events)

    assert emitted == [
        (0, EventKind.ESCALATED),
        (1, EventKind.RECOVERED),
        (16, EventKind.ESCALATED),
        (17, EventKind.RECOVERED),
        (32, EventKind.ESCALATED),
        (33, EventKind.RECOVERED),
        (48, EventKind.ESCALATED),
        (49, EventKind.RECOVERED),
    ]


def test_every_announced_episode_recovers_immediately() -> None:
    rule = rising_rule(
        levels=(LevelSpec("warning", 10.0), LevelSpec("alert", 20.0)),
        cooldown=timedelta(minutes=15),
        stale_after=timedelta(days=1),
    )
    sequence = ((0, 15.0), (10, 25.0), (11, 5.0), (16, 15.0), (17, 5.0))
    state = RuleState()
    kinds: dict[int, list[EventKind]] = {}
    for minute, value in sequence:
        state, events = step(rule, state, minute, value)
        kinds[minute] = events

    assert kinds == {
        0: [EventKind.ESCALATED],
        10: [EventKind.ESCALATED],
        11: [EventKind.RECOVERED],
        16: [EventKind.ESCALATED],
        17: [EventKind.RECOVERED],
    }

    state, events = step(rule, state, 18, 15.0)
    assert events == []
    assert state.pending_escalation == "warning"
    state, events = step(rule, state, 19, 5.0)
    assert events == []
    assert state.active_level is None
    assert state.pending_escalation is None


def test_future_persisted_sample_times_are_treated_as_unset() -> None:
    future = datetime(9999, 1, 1, tzinfo=UTC)
    encoded = RuleState(
        newest_sample_time=future,
        newest_value=5.0,
        last_evaluated_sample_time=future,
    ).to_dict()
    state = RuleState.from_dict(encoded)
    rule = rising_rule()

    state, events = evaluate(rule, state, Sample(35.0, BASE), BASE)
    assert state.active_level == "critical"
    assert state.newest_sample_time == BASE
    assert state.last_evaluated_sample_time == BASE
    assert [event.kind for event in events] == [EventKind.ESCALATED]


def test_future_notification_and_reminder_anchors_do_not_silence_events() -> None:
    rule = rising_rule(
        levels=(LevelSpec("warning", 10.0), LevelSpec("critical", 20.0)),
        reminder_interval=timedelta(minutes=10),
        stale_after=timedelta(days=1),
    )
    state, _ = step(rule, RuleState(), 0, 25.0)
    state, _ = step(rule, state, 1, 15.0)
    future = BASE + timedelta(days=30)
    state = replace(
        state,
        level_notification_times=(("critical", future),),
        last_episode_notification_time=future,
    )
    state, events = evaluate(
        rule,
        state,
        Sample(25.0, BASE + timedelta(minutes=2)),
        BASE + timedelta(minutes=2),
    )
    assert [event.kind for event in events] == [EventKind.ESCALATED]

    state = replace(
        state,
        last_episode_notification_time=None,
        episode_started_at=future,
    )
    state, events = evaluate(rule, state, None, BASE + timedelta(minutes=3))
    assert events == []
    assert state.last_episode_notification_time == BASE + timedelta(minutes=3)
    state, events = evaluate(rule, state, None, BASE + timedelta(minutes=13))
    assert [event.kind for event in events] == [EventKind.REMINDER]


def test_fresh_state_runs_at_different_times_have_different_event_ids() -> None:
    rule = rising_rule(levels=(LevelSpec("critical", 10.0),))
    _, first = evaluate(rule, RuleState(), Sample(11.0, BASE), BASE)
    later = BASE + timedelta(minutes=1)
    _, second = evaluate(rule, RuleState(), Sample(11.0, later), later)
    assert first[0].event_id != second[0].event_id


def test_event_ids_are_data_derived_across_clock_drift_and_round_trip() -> None:
    rule = rising_rule(
        levels=(LevelSpec("critical", 10.0),),
        cooldown=timedelta(0),
        reminder_interval=timedelta(minutes=10),
        stale_after=timedelta(days=1),
    )

    seeded_at = BASE - timedelta(minutes=1)
    prior, _ = evaluate(rule, RuleState(), Sample(5.0, seeded_at), seeded_at)
    prior = RuleState.from_dict(prior.to_dict())
    alert_sample = Sample(11.0, BASE)
    _, first = evaluate(rule, prior, alert_sample, BASE)
    _, replayed = evaluate(rule, prior, alert_sample, BASE + timedelta(seconds=30))
    assert first[0].event_id == replayed[0].event_id

    alerted, _ = evaluate(rule, RuleState(), alert_sample, BASE)
    replay_state = RuleState.from_dict(alerted.to_dict())
    clear_sample = Sample(5.0, BASE + timedelta(minutes=1))
    _, first = evaluate(rule, replay_state, clear_sample, clear_sample.timestamp)
    _, replayed = evaluate(
        rule,
        replay_state,
        clear_sample,
        clear_sample.timestamp + timedelta(seconds=30),
    )
    assert first[0].kind is EventKind.RECOVERED
    assert first[0].event_id == replayed[0].event_id

    _, first = evaluate(rule, replay_state, None, BASE + timedelta(minutes=10))
    _, replayed = evaluate(rule, replay_state, None, BASE + timedelta(minutes=10, seconds=30))
    assert first[0].kind is EventKind.REMINDER
    assert first[0].event_id == replayed[0].event_id

    stale_rule = rising_rule(stale_after=timedelta(minutes=5))
    prior, _ = evaluate(stale_rule, RuleState(), Sample(5.0, BASE), BASE)
    prior = RuleState.from_dict(prior.to_dict())
    _, first = evaluate(stale_rule, prior, None, BASE + timedelta(minutes=6))
    _, replayed = evaluate(stale_rule, prior, None, BASE + timedelta(minutes=6, seconds=30))
    assert first[0].kind is EventKind.STALE
    assert first[0].event_id == replayed[0].event_id

    stale, _ = evaluate(stale_rule, RuleState(), None, BASE)
    stale = RuleState.from_dict(stale.to_dict())
    restoring = Sample(5.0, BASE + timedelta(minutes=1))
    _, first = evaluate(stale_rule, stale, restoring, restoring.timestamp)
    _, replayed = evaluate(
        stale_rule,
        stale,
        restoring,
        restoring.timestamp + timedelta(seconds=30),
    )
    assert first[0].kind is EventKind.RESTORED
    assert first[0].event_id == replayed[0].event_id


@pytest.mark.parametrize(
    ("old_rule", "new_rule", "old_value", "new_value", "expected_level"),
    [
        (
            rising_rule(levels=(LevelSpec("warning", 10.0), LevelSpec("critical", 20.0))),
            rising_rule(levels=(LevelSpec("warning", 10.0),)),
            25.0,
            15.0,
            "warning",
        ),
        (
            rising_rule(levels=(LevelSpec("warning", 10.0),)),
            rising_rule(levels=(LevelSpec("caution", 10.0),)),
            15.0,
            15.0,
            "caution",
        ),
        (
            rising_rule(levels=(LevelSpec("warning", 10.0), LevelSpec("critical", 20.0))),
            RuleSpec(
                "fictitious-temperature",
                Direction.FALLING,
                (LevelSpec("warning", 20.0), LevelSpec("critical", 10.0)),
                stale_after=timedelta(hours=12),
            ),
            15.0,
            5.0,
            "critical",
        ),
    ],
    ids=("removed", "renamed", "direction-flipped"),
)
def test_rule_changes_rederive_by_name_without_starting_a_new_episode(
    old_rule: RuleSpec,
    new_rule: RuleSpec,
    old_value: float,
    new_value: float,
    expected_level: str,
) -> None:
    state, _ = evaluate(old_rule, RuleState(), Sample(old_value, BASE), BASE)
    changed_at = BASE + timedelta(minutes=1)
    state, events = evaluate(
        new_rule,
        state,
        Sample(new_value, changed_at),
        changed_at,
    )
    assert state.active_level == expected_level
    assert state.episode == 1
    assert [event.kind for event in events] == [EventKind.ESCALATED]
    assert events[0].level == expected_level


def test_direction_change_while_normal_starts_a_new_episode() -> None:
    rising = rising_rule(levels=(LevelSpec("critical", 10.0),))
    falling = RuleSpec(
        rising.rule_id,
        Direction.FALLING,
        (LevelSpec("critical", 10.0),),
        stale_after=timedelta(hours=12),
    )
    state, events = evaluate(rising, RuleState(), Sample(5.0, BASE), BASE)
    assert events == []

    later = BASE + timedelta(minutes=1)
    state, events = evaluate(falling, state, Sample(5.0, later), later)
    assert state.episode == 1
    assert state.active_level == "critical"
    assert [event.kind for event in events] == [EventKind.ESCALATED]


def test_top_level_rename_does_not_interrupt_stale_reminders() -> None:
    old_rule = rising_rule(
        levels=(LevelSpec("critical", 10.0),),
        reminder_interval=timedelta(minutes=60),
        stale_after=timedelta(minutes=35),
    )
    renamed_rule = rising_rule(
        levels=(LevelSpec("danger", 10.0),),
        reminder_interval=timedelta(minutes=60),
        stale_after=timedelta(minutes=35),
    )
    state, _ = evaluate(old_rule, RuleState(), Sample(11.0, BASE), BASE)
    reminder_minutes: list[int] = []
    for minute in (61, 121, 181):
        state, events = evaluate(renamed_rule, state, None, BASE + timedelta(minutes=minute))
        reminder_minutes.extend(minute for event in events if event.kind is EventKind.REMINDER)
    assert reminder_minutes == [61, 121, 181]
    assert state.active_level == "critical"
    assert state.needs_rederive


def test_missing_active_level_without_old_index_fails_toward_top_level() -> None:
    rule = rising_rule(levels=(LevelSpec("critical", 10.0),))
    state = RuleState(
        active_level="removed",
        episode=1,
        rule_direction=Direction.RISING,
    )
    state, events = evaluate(rule, state, None, BASE)
    assert [event.kind for event in events] == [
        EventKind.STALE,
        EventKind.ESCALATED,
    ]
    assert [event.level for event in events] == ["critical", "critical"]
    assert state.pending_escalation is None


def test_removed_pending_level_clamps_to_top_remaining_level_while_stale() -> None:
    rule = rising_rule(
        levels=(LevelSpec("warning", 10.0),),
        stale_after=timedelta(minutes=1),
    )
    state = RuleState(
        active_level="removed",
        episode=1,
        newest_sample_time=BASE,
        newest_value=25.0,
        last_evaluated_sample_time=BASE,
        episode_started_at=BASE,
        pending_escalation="removed",
        rule_direction=Direction.RISING,
        level_order=("old-warning", "old-alert", "removed"),
        level_notification_times=(("warning", BASE),),
    )
    state, events = evaluate(rule, state, None, BASE + timedelta(minutes=5))
    assert [event.kind for event in events] == [EventKind.STALE]
    assert events[0].level == "warning"
    assert state.pending_escalation == "warning"


def test_unannounced_active_state_fails_toward_alerting() -> None:
    rule = rising_rule(levels=(LevelSpec("warning", 10.0),))
    state = RuleState(
        active_level="warning",
        episode=1,
        newest_sample_time=BASE,
        newest_value=15.0,
        last_evaluated_sample_time=BASE,
        episode_started_at=BASE,
        rule_direction=Direction.RISING,
        level_order=("warning",),
    )
    state, events = evaluate(rule, state, None, BASE)
    assert [event.kind for event in events] == [EventKind.ESCALATED]
    assert state.episode_announced
    assert state.pending_escalation is None


def test_rederive_does_not_repeat_level_notified_under_current_name() -> None:
    rule = rising_rule(levels=(LevelSpec("danger", 10.0),))
    state = RuleState(
        active_level="removed",
        episode=1,
        newest_sample_time=BASE,
        newest_value=11.0,
        last_evaluated_sample_time=BASE,
        episode_started_at=BASE,
        episode_announced=True,
        episode_notified_levels=("danger",),
        escalation_ordinal=1,
        rule_direction=Direction.RISING,
        level_order=("removed",),
        level_notification_times=(("danger", BASE),),
    )
    later = BASE + timedelta(minutes=1)
    state, events = evaluate(rule, state, Sample(11.0, later), later)
    assert events == []
    assert state.active_level == "danger"
    assert not state.needs_rederive


def test_adding_level_preserves_partial_clear_streak_by_active_name() -> None:
    old_rule = rising_rule(
        levels=(LevelSpec("warning", 10.0), LevelSpec("critical", 20.0)),
        clear_after_samples=2,
    )
    added_rule = rising_rule(
        levels=(
            LevelSpec("warning", 10.0),
            LevelSpec("alert", 15.0),
            LevelSpec("critical", 20.0),
        ),
        clear_after_samples=2,
    )
    state, _ = evaluate(old_rule, RuleState(), Sample(25.0, BASE), BASE)
    first_clear = BASE + timedelta(minutes=1)
    state, _ = evaluate(old_rule, state, Sample(15.0, first_clear), first_clear)
    assert state.clear_count == 1

    second_clear = BASE + timedelta(minutes=2)
    state, events = evaluate(added_rule, state, Sample(15.0, second_clear), second_clear)
    assert events == []
    assert state.active_level == "alert"
    assert state.clear_count == 0
    assert not state.needs_rederive


def test_adding_level_inside_hysteresis_band_keeps_active_level() -> None:
    old_rule = rising_rule(
        levels=(LevelSpec("warning", 10.0),),
        hysteresis=2.0,
    )
    added_rule = rising_rule(
        levels=(LevelSpec("info", 9.0), LevelSpec("warning", 10.0)),
        hysteresis=2.0,
    )
    state, _ = evaluate(old_rule, RuleState(), Sample(11.0, BASE), BASE)
    later = BASE + timedelta(minutes=1)
    state, events = evaluate(added_rule, state, Sample(8.5, later), later)
    assert events == []
    assert state.active_level == "warning"
    assert state.clear_count == 0
    assert not state.needs_rederive


def test_escalation_ordinal_prevents_id_reuse_across_level_renames() -> None:
    first_rule = rising_rule(levels=(LevelSpec("critical", 10.0),))
    second_rule = rising_rule(levels=(LevelSpec("danger", 10.0),))
    state, first = evaluate(first_rule, RuleState(), Sample(11.0, BASE), BASE)
    second_at = BASE + timedelta(minutes=1)
    state, second = evaluate(second_rule, state, Sample(11.0, second_at), second_at)
    third_at = BASE + timedelta(minutes=16)
    state, third = evaluate(first_rule, state, Sample(11.0, third_at), third_at)

    assert [event.level for event in (*first, *second, *third)] == [
        "critical",
        "danger",
        "critical",
    ]
    assert len({event.event_id for event in (*first, *second, *third)}) == 3
    assert state.escalation_ordinal == 3


def test_stale_newer_sample_resets_clear_streak_without_recovering() -> None:
    rule = rising_rule(
        levels=(LevelSpec("critical", 10.0),),
        clear_after_samples=2,
        stale_after=timedelta(minutes=35),
    )
    state, _ = step(rule, RuleState(), 0, 35.0)
    state, _ = step(rule, state, 1, 5.0)
    assert state.clear_count == 1

    state, events = evaluate(
        rule,
        state,
        Sample(35.0, BASE + timedelta(minutes=2)),
        BASE + timedelta(minutes=40),
    )
    assert state.clear_count == 0
    assert EventKind.STALE in [event.kind for event in events]

    state, events = evaluate(
        rule,
        state,
        Sample(5.0, BASE + timedelta(minutes=41)),
        BASE + timedelta(minutes=41),
    )
    assert state.active_level == "critical"
    assert state.clear_count == 1
    assert EventKind.RECOVERED not in [event.kind for event in events]


def test_huge_integer_sample_is_treated_as_absent() -> None:
    state, events = evaluate(rising_rule(), RuleState(), Sample(10**400, BASE), BASE)
    assert state.newest_sample_time is None
    assert [event.kind for event in events] == [EventKind.STALE]


@pytest.mark.parametrize("bad_value", [True, "11"])
def test_non_numeric_sample_is_treated_as_absent(bad_value: object) -> None:
    state, events = evaluate(
        rising_rule(),
        RuleState(),
        Sample(bad_value, BASE),  # type: ignore[arg-type]
        BASE,
    )
    assert state.newest_sample_time is None
    assert [event.kind for event in events] == [EventKind.STALE]


def test_level_history_capacity_discards_the_oldest_entry() -> None:
    old_names = tuple(f"old-{index}" for index in range(128))
    state = RuleState(
        level_notification_times=tuple(
            (name, BASE + timedelta(seconds=index)) for index, name in enumerate(old_names)
        ),
    )
    rule = rising_rule(
        levels=(LevelSpec("critical", 10.0),),
        cooldown=timedelta(days=365),
    )
    now = BASE + timedelta(seconds=200)
    state, events = evaluate(rule, state, Sample(11.0, now), now)
    retained_names = {name for name, _ in state.level_notification_times}
    assert len(retained_names) == 128
    assert "critical" in retained_names
    assert "old-0" not in retained_names
    assert [event.kind for event in events] == [EventKind.ESCALATED]


def test_level_history_is_pruned_by_age_and_future_tolerance() -> None:
    now = BASE + timedelta(minutes=20)
    state = RuleState(
        level_notification_times=(
            ("expired", BASE),
            ("recent-removed", now - timedelta(minutes=5)),
            ("slightly-future", now + timedelta(seconds=60)),
            ("far-future", now + timedelta(seconds=61)),
        ),
    )
    rule = rising_rule(cooldown=timedelta(minutes=15))
    state, _ = evaluate(rule, state, None, now)
    assert {name for name, _ in state.level_notification_times} == {
        "recent-removed",
        "slightly-future",
    }


def test_config_rederive_can_recover_or_wait_for_a_fresh_sample() -> None:
    old_rule = rising_rule(
        levels=(LevelSpec("critical", 10.0),),
        stale_after=timedelta(minutes=35),
    )
    new_rule = rising_rule(
        levels=(LevelSpec("danger", 100.0),),
        stale_after=timedelta(minutes=35),
    )
    state, _ = evaluate(old_rule, RuleState(), Sample(11.0, BASE), BASE)

    state, events = evaluate(
        new_rule,
        state,
        Sample(5.0, BASE + timedelta(minutes=1)),
        BASE + timedelta(hours=1),
    )
    assert state.active_level == "critical"
    assert state.needs_rederive
    assert EventKind.RECOVERED not in [event.kind for event in events]

    fresh_at = BASE + timedelta(hours=1, minutes=1)
    state, events = evaluate(new_rule, state, Sample(5.0, fresh_at), fresh_at)
    assert state.active_level is None
    assert not state.needs_rederive
    assert [event.kind for event in events] == [
        EventKind.RESTORED,
        EventKind.RECOVERED,
    ]


def test_config_rederive_does_not_repeat_an_already_notified_level() -> None:
    old_rule = rising_rule(levels=(LevelSpec("warning", 10.0), LevelSpec("critical", 20.0)))
    reordered = rising_rule(levels=(LevelSpec("critical", 10.0), LevelSpec("warning", 20.0)))
    state, _ = evaluate(old_rule, RuleState(), Sample(25.0, BASE), BASE)
    later = BASE + timedelta(minutes=1)
    state, events = evaluate(reordered, state, Sample(15.0, later), later)
    assert state.active_level == "critical"
    assert events == []


def test_missing_persisted_cycle_anchors_use_explicit_clock() -> None:
    rule = rising_rule(levels=(LevelSpec("critical", 10.0),))
    state = RuleState(stale=True)
    state, events = evaluate(rule, state, Sample(11.0, BASE), BASE)
    assert [event.kind for event in events] == [
        EventKind.RESTORED,
        EventKind.ESCALATED,
    ]

    state = replace(
        state,
        episode_started_at=None,
        last_episode_notification_time=None,
    )
    anchored_at = BASE + timedelta(hours=1)
    state, events = evaluate(rule, state, None, anchored_at)
    assert EventKind.REMINDER not in [event.kind for event in events]
    assert state.episode_started_at == anchored_at
    assert state.last_episode_notification_time == anchored_at

    state, events = evaluate(rule, state, None, anchored_at + rule.reminder_interval)
    assert [event.kind for event in events] == [EventKind.REMINDER]


def test_startup_stale_event_ids_use_persisted_generation() -> None:
    rule = rising_rule()
    first_state, first = evaluate(rule, RuleState(), None, BASE)
    later = BASE + timedelta(minutes=1)
    _, second = evaluate(rule, RuleState(), None, later)
    assert first_state.generation == BASE.isoformat()
    assert first[0].event_id != second[0].event_id

    initialized, _ = evaluate(rule, RuleState(), Sample(5.0, BASE), BASE)
    persisted = RuleState.from_dict(initialized.to_dict())
    stale_at = BASE + timedelta(hours=13)
    _, first_replay = evaluate(rule, persisted, None, stale_at)
    _, second_replay = evaluate(rule, persisted, None, stale_at + timedelta(seconds=30))
    assert first_replay[0].event_id == second_replay[0].event_id


def test_generation_is_canonicalized_to_utc() -> None:
    rule = rising_rule()
    offset = timezone(timedelta(hours=-7))
    same_instant = BASE.astimezone(offset)
    first_state, first = evaluate(rule, RuleState(), None, BASE)
    second_state, second = evaluate(rule, RuleState(), None, same_instant)
    assert first_state.generation == second_state.generation == BASE.isoformat()
    assert first[0].event_id == second[0].event_id

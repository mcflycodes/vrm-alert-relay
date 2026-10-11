"""Property tests for alert event invariants."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import UTC, datetime, timedelta
from itertools import pairwise

from hypothesis import given, settings
from hypothesis import strategies as st

from vrm_alert_relay.engine import (
    Direction,
    Event,
    EventKind,
    LevelSpec,
    RuleSpec,
    RuleState,
    Sample,
    evaluate,
)

BASE = datetime(2035, 1, 1, tzinfo=UTC)

VALUES = st.one_of(
    st.none(),
    st.floats(allow_nan=True, allow_infinity=True, width=64),
)
STEPS = st.lists(
    st.tuples(
        st.integers(min_value=0, max_value=120),
        st.integers(min_value=-120, max_value=120),
        VALUES,
    ),
    min_size=1,
    max_size=80,
)


def property_rule(direction: Direction = Direction.RISING) -> RuleSpec:
    thresholds = (10.0, 20.0, 30.0)
    if direction is Direction.FALLING:
        thresholds = (30.0, 20.0, 10.0)
    return RuleSpec(
        "fictitious-property-rule",
        direction,
        tuple(
            LevelSpec(name, threshold)
            for name, threshold in zip(("warning", "alert", "critical"), thresholds, strict=True)
        ),
        hysteresis=1.5,
        clear_after_samples=2,
        cooldown=timedelta(minutes=15),
        reminder_interval=timedelta(minutes=20),
        reminder_max=3,
        stale_after=timedelta(minutes=35),
    )


def run_steps(
    rule: RuleSpec, steps: list[tuple[int, int, float | None]]
) -> tuple[list[Event], list[RuleState], list[datetime]]:
    state = RuleState()
    now = BASE
    events: list[Event] = []
    states: list[RuleState] = []
    clocks: list[datetime] = []
    for advance, sample_skew, value in steps:
        now += timedelta(seconds=advance)
        sample = None if value is None else Sample(value, now + timedelta(seconds=sample_skew))
        state, emitted = evaluate(rule, state, sample, now)
        events.extend(emitted)
        states.append(state)
        clocks.extend([now] * len(emitted))
    return events, states, clocks


@settings(max_examples=150, deadline=None, derandomize=True)
@given(STEPS, st.sampled_from(list(Direction)))
def test_event_ids_are_unique_and_bounded_invariants_hold(
    steps: list[tuple[int, int, float | None]], direction: Direction
) -> None:
    rule = property_rule(direction)
    events, states, clocks = run_steps(rule, steps)

    event_ids = [event.event_id for event in events]
    assert len(event_ids) == len(set(event_ids))

    reminders = Counter(event.episode for event in events if event.kind is EventKind.REMINDER)
    assert all(count <= rule.reminder_max for count in reminders.values())

    known_episodes: set[int] = set()
    previous_episode = 0
    for state in states:
        if state.episode > previous_episode:
            known_episodes.add(state.episode)
        previous_episode = state.episode
    assert all(
        event.episode in known_episodes for event in events if event.kind is EventKind.RECOVERED
    )

    stale_flow = [
        event.kind for event in events if event.kind in (EventKind.STALE, EventKind.RESTORED)
    ]
    assert all(left is not right for left, right in pairwise(stale_flow))
    if stale_flow:
        assert stale_flow[0] is EventKind.STALE

    escalation_times: dict[str | None, list[datetime]] = defaultdict(list)
    for event, clock in zip(events, clocks, strict=True):
        if event.kind is EventKind.ESCALATED:
            escalation_times[event.level].append(clock)
    for times in escalation_times.values():
        assert all(later - earlier >= rule.cooldown for earlier, later in pairwise(times))


@settings(max_examples=200, deadline=None, derandomize=True)
@given(
    st.lists(
        st.tuples(
            st.integers(min_value=1, max_value=20),
            st.booleans(),
        ),
        min_size=1,
        max_size=80,
    )
)
def test_cooldown_bounds_escalations_in_every_sliding_window(
    steps: list[tuple[int, bool]],
) -> None:
    cooldown = timedelta(minutes=15)
    rule = RuleSpec(
        "fictitious-cooldown-window",
        Direction.RISING,
        (LevelSpec("critical", 10.0),),
        cooldown=cooldown,
        stale_after=timedelta(days=2),
    )
    state = RuleState()
    now = BASE
    escalation_times: list[datetime] = []
    for advance, active in steps:
        now += timedelta(minutes=advance)
        state, events = evaluate(
            rule,
            state,
            Sample(10.0 if active else 9.0, now),
            now,
        )
        escalation_times.extend(now for event in events if event.kind is EventKind.ESCALATED)

    assert all(later - earlier >= cooldown for earlier, later in pairwise(escalation_times))


@settings(max_examples=200, deadline=None, derandomize=True)
@given(
    st.lists(
        st.tuples(
            st.integers(min_value=1, max_value=20),
            st.sampled_from([5.0, 15.0, 25.0]),
        ),
        min_size=1,
        max_size=80,
    )
)
def test_operator_alarm_state_matches_every_announced_recovery(
    steps: list[tuple[int, float]],
) -> None:
    rule = RuleSpec(
        "fictitious-operator-state",
        Direction.RISING,
        (LevelSpec("warning", 10.0), LevelSpec("alert", 20.0)),
        cooldown=timedelta(minutes=15),
        stale_after=timedelta(days=2),
    )
    state = RuleState()
    now = BASE
    operator_heard_alarm = False
    for advance, value in steps:
        previous_announced = state.active_level is not None and state.episode_announced
        now += timedelta(minutes=advance)
        state, events = evaluate(rule, state, Sample(value, now), now)
        recoveries = [event for event in events if event.kind is EventKind.RECOVERED]
        if previous_announced and state.active_level is None:
            assert len(recoveries) == 1
        else:
            assert recoveries == []

        for event in events:
            if event.kind is EventKind.ESCALATED:
                operator_heard_alarm = True
            elif event.kind is EventKind.RECOVERED:
                operator_heard_alarm = False
        assert operator_heard_alarm == (state.active_level is not None and state.episode_announced)


@settings(max_examples=150, deadline=None, derandomize=True)
@given(
    st.lists(
        st.tuples(
            st.floats(allow_nan=True, allow_infinity=True, width=64),
            st.datetimes(
                min_value=datetime(1, 1, 1),
                max_value=datetime(9999, 12, 31, 23, 59, 59, 999999),
                timezones=st.just(UTC),
            ),
            st.datetimes(
                min_value=datetime(1, 1, 1),
                max_value=datetime(9999, 12, 31, 23, 59, 59, 999999),
                timezones=st.just(UTC),
            ),
        ),
        min_size=1,
        max_size=40,
    )
)
def test_evaluate_never_raises_for_arbitrary_floats_and_aware_timestamps(
    inputs: list[tuple[float, datetime, datetime]],
) -> None:
    rule = property_rule()
    state = RuleState()
    for value, timestamp, now in inputs:
        state, _ = evaluate(rule, state, Sample(value, timestamp), now)


@settings(max_examples=200, deadline=None, derandomize=True)
@given(
    st.sampled_from(list(Direction)),
    st.integers(min_value=1, max_value=3),
    st.integers(min_value=1, max_value=3),
    st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=5),
            st.one_of(st.none(), st.sampled_from([0.0, 15.0, 35.0])),
        ),
        min_size=1,
        max_size=100,
    ),
)
def test_evaluate_never_raises_across_reminders_and_multisample_recovery(
    direction: Direction,
    clear_after_samples: int,
    reminder_minutes: int,
    steps: list[tuple[int, float | None]],
) -> None:
    thresholds = (10.0, 20.0, 30.0)
    if direction is Direction.FALLING:
        thresholds = (30.0, 20.0, 10.0)
    rule = RuleSpec(
        "fictitious-state-machine",
        direction,
        tuple(
            LevelSpec(name, threshold)
            for name, threshold in zip(("warning", "alert", "critical"), thresholds, strict=True)
        ),
        hysteresis=1.0,
        clear_after_samples=clear_after_samples,
        cooldown=timedelta(minutes=2),
        reminder_interval=timedelta(minutes=reminder_minutes),
        reminder_max=3,
        stale_after=timedelta(minutes=2),
    )
    state = RuleState()
    now = BASE
    for advance_minutes, value in steps:
        now += timedelta(minutes=advance_minutes)
        sample = None if value is None else Sample(value, now)
        state, _ = evaluate(rule, state, sample, now)
        assert RuleState.from_dict(state.to_dict()) == state

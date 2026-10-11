"""Pure deterministic evaluation for alert rules."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Final, cast

from .models import (
    MAX_COUNTER,
    Direction,
    Event,
    EventKind,
    InvalidRuleStateError,
    LevelCount,
    LevelTime,
    RuleSpec,
    RuleState,
    Sample,
)

FUTURE_TOLERANCE: Final = timedelta(seconds=60)


def _aware(value: object) -> bool:
    return (
        isinstance(value, datetime)
        and value.tzinfo is not None
        and value.utcoffset() is not None
    )


def _elapsed(later: datetime, earlier: datetime) -> timedelta:
    return later - earlier


def _usable_sample(sample: object, now: datetime) -> Sample | None:
    if not isinstance(sample, Sample):
        return None
    value = sample.value
    timestamp = sample.timestamp
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or not _aware(timestamp)
    ):
        return None
    future_by = _elapsed(timestamp, now)
    if future_by > FUTURE_TOLERANCE:
        return None
    return sample


def _mapping_set_time(
    values: tuple[LevelTime, ...], name: str, timestamp: datetime
) -> tuple[LevelTime, ...]:
    updated = {key: value for key, value in values}
    updated[name] = timestamp
    return tuple(sorted(updated.items()))


def _mapping_increment(
    values: tuple[LevelCount, ...], name: str
) -> tuple[tuple[LevelCount, ...], int]:
    updated = {key: value for key, value in values}
    ordinal = updated.get(name, 0) + 1
    if ordinal > MAX_COUNTER:
        ordinal = MAX_COUNTER
    updated[name] = ordinal
    return tuple(sorted(updated.items())), ordinal


def _event_id(
    rule_id: str,
    episode: int,
    kind: EventKind,
    level: str | None,
    ordinal: int,
) -> str:
    identity = json.dumps(
        [rule_id, episode, kind.value, level, ordinal],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode()
    return f"evt_{hashlib.sha256(identity).hexdigest()}"


def _event(
    rule: RuleSpec,
    state: RuleState,
    kind: EventKind,
    *,
    level: str | None,
    ordinal: int,
    value: float | None,
    sample_time: datetime | None,
) -> Event:
    return Event(
        rule_id=rule.rule_id,
        episode=state.episode,
        kind=kind,
        level=level,
        value=value,
        sample_time=sample_time,
        event_id=_event_id(rule.rule_id, state.episode, kind, level, ordinal),
    )


def _entry_level(rule: RuleSpec, value: float) -> int | None:
    result: int | None = None
    for index, level in enumerate(rule.levels):
        crossed = (
            value >= level.threshold
            if rule.direction is Direction.RISING
            else value <= level.threshold
        )
        if crossed:
            result = index
    return result


def _retained_level(rule: RuleSpec, value: float, maximum: int) -> int | None:
    result: int | None = None
    for index, level in enumerate(rule.levels[: maximum + 1]):
        retained = (
            value >= level.threshold - rule.hysteresis
            if rule.direction is Direction.RISING
            else value <= level.threshold + rule.hysteresis
        )
        if retained:
            result = index
    return result


def _emit_escalation(
    rule: RuleSpec, state: RuleState, sample: Sample, now: datetime
) -> tuple[RuleState, Event | None]:
    active_level = cast(int, state.active_level)
    level_name = rule.levels[active_level].name
    last_times = dict(state.level_notification_times)
    last_time = last_times.get(level_name)
    since_last = _elapsed(now, last_time) if last_time is not None else None
    within_cooldown = since_last is not None and since_last < rule.cooldown
    if within_cooldown:
        return replace(
            state,
            suppressed_escalations=min(state.suppressed_escalations + 1, MAX_COUNTER),
        ), None
    counts, ordinal = _mapping_increment(state.level_escalation_counts, level_name)
    state = replace(
        state,
        level_notification_times=_mapping_set_time(
            state.level_notification_times, level_name, now
        ),
        level_escalation_counts=counts,
        last_episode_notification_time=now,
    )
    return state, _event(
        rule,
        state,
        EventKind.ESCALATED,
        level=level_name,
        ordinal=ordinal,
        value=float(sample.value),
        sample_time=sample.timestamp,
    )


def _evaluate_threshold(
    rule: RuleSpec, state: RuleState, sample: Sample, now: datetime
) -> tuple[RuleState, list[Event]]:
    previous_level = state.active_level
    entry_level = _entry_level(rule, float(sample.value))
    events: list[Event] = []
    if previous_level is None:
        if entry_level is None:
            return replace(
                state,
                clear_count=0,
                last_evaluated_sample_time=sample.timestamp,
            ), events
        state = replace(
            state,
            active_level=entry_level,
            episode=min(state.episode + 1, MAX_COUNTER),
            clear_count=0,
            reminder_count=0,
            last_episode_notification_time=None,
            episode_started_at=now,
            last_evaluated_sample_time=sample.timestamp,
        )
        state, event = _emit_escalation(rule, state, sample, now)
        if event is not None:
            events.append(event)
        return state, events

    if entry_level is not None and entry_level > previous_level:
        state = replace(
            state,
            active_level=entry_level,
            clear_count=0,
            last_evaluated_sample_time=sample.timestamp,
        )
        state, event = _emit_escalation(rule, state, sample, now)
        if event is not None:
            events.append(event)
        return state, events

    retained_level = _retained_level(rule, float(sample.value), previous_level)
    if retained_level == previous_level:
        return replace(
            state,
            clear_count=0,
            last_evaluated_sample_time=sample.timestamp,
        ), events

    clear_count = min(state.clear_count + 1, MAX_COUNTER)
    if clear_count < rule.clear_after_samples:
        return replace(
            state,
            clear_count=clear_count,
            last_evaluated_sample_time=sample.timestamp,
        ), events

    state = replace(
        state,
        active_level=retained_level,
        clear_count=0,
        last_evaluated_sample_time=sample.timestamp,
    )
    if retained_level is not None:
        return state, events

    if rule.recovery_notify:
        events.append(
            _event(
                rule,
                state,
                EventKind.RECOVERED,
                level=None,
                ordinal=0,
                value=float(sample.value),
                sample_time=sample.timestamp,
            )
        )
    return replace(
        state,
        reminder_count=0,
        last_episode_notification_time=None,
        episode_started_at=None,
    ), events


def _maybe_remind(
    rule: RuleSpec, state: RuleState, now: datetime
) -> tuple[RuleState, Event | None]:
    active_level = state.active_level
    if (
        rule.reminder_max == 0
        or active_level is None
        or active_level != len(rule.levels) - 1
        or state.reminder_count >= rule.reminder_max
    ):
        return state, None
    anchor = state.last_episode_notification_time or state.episode_started_at
    elapsed = _elapsed(now, anchor) if anchor is not None else None
    if elapsed is None or elapsed < rule.reminder_interval:
        return state, None
    count = state.reminder_count + 1
    state = replace(
        state,
        reminder_count=count,
        last_episode_notification_time=now,
    )
    return state, _event(
        rule,
        state,
        EventKind.REMINDER,
        level=rule.levels[active_level].name,
        ordinal=count,
        value=state.newest_value,
        sample_time=state.newest_sample_time,
    )


def evaluate(
    rule: RuleSpec,
    state: RuleState,
    sample: Sample | None,
    now: datetime,
) -> tuple[RuleState, list[Event]]:
    """Evaluate one rule without I/O, mutation, global state, or wall-clock access."""

    if not _aware(now):
        raise ValueError("now must be an aware datetime")
    if state.active_level is not None and state.active_level >= len(rule.levels):
        raise InvalidRuleStateError("state active_level does not exist in this rule")
    events: list[Event] = []
    usable = _usable_sample(sample, now)

    if usable is not None and (
        state.newest_sample_time is None or usable.timestamp > state.newest_sample_time
    ):
        state = replace(
            state,
            newest_sample_time=usable.timestamp,
            newest_value=float(usable.value),
        )

    sample_age = (
        _elapsed(now, state.newest_sample_time)
        if state.newest_sample_time is not None
        else None
    )
    is_fresh = sample_age is not None and sample_age <= rule.stale_after
    if not is_fresh:
        if not state.stale:
            state = replace(
                state,
                stale=True,
                stale_cycle=min(state.stale_cycle + 1, MAX_COUNTER),
            )
            events.append(
                _event(
                    rule,
                    state,
                    EventKind.STALE,
                    level=(
                        rule.levels[state.active_level].name
                        if state.active_level is not None
                        else None
                    ),
                    ordinal=state.stale_cycle,
                    value=state.newest_value,
                    sample_time=state.newest_sample_time,
                )
            )
    else:
        if state.stale:
            state = replace(state, stale=False)
            events.append(
                _event(
                    rule,
                    state,
                    EventKind.RESTORED,
                    level=(
                        rule.levels[state.active_level].name
                        if state.active_level is not None
                        else None
                    ),
                    ordinal=state.stale_cycle,
                    value=state.newest_value,
                    sample_time=state.newest_sample_time,
                )
            )
        if usable is not None and (
            state.last_evaluated_sample_time is None
            or usable.timestamp > state.last_evaluated_sample_time
        ):
            state, threshold_events = _evaluate_threshold(rule, state, usable, now)
            events.extend(threshold_events)

    state, reminder = _maybe_remind(rule, state, now)
    if reminder is not None:
        events.append(reminder)
    return state, events

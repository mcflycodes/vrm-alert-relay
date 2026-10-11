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
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        finite = math.isfinite(value)
    except OverflowError:
        return None
    if not finite or not _aware(timestamp):
        return None
    if _elapsed(timestamp, now) > FUTURE_TOLERANCE:
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
    ordinal = min(updated.get(name, 0) + 1, MAX_COUNTER)
    updated[name] = ordinal
    return tuple(sorted(updated.items())), ordinal


def _event_id(
    rule_id: str,
    episode: int,
    kind: EventKind,
    level: str | None,
    ordinal: int,
    discriminator: datetime,
) -> str:
    identity = json.dumps(
        [
            rule_id,
            episode,
            kind.value,
            level,
            ordinal,
            discriminator.isoformat(),
        ],
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
    now: datetime,
) -> Event:
    cycle_kind = kind in (EventKind.STALE, EventKind.RESTORED)
    discriminator = state.stale_started_at if cycle_kind else state.episode_started_at
    if discriminator is None:
        discriminator = now
    return Event(
        rule_id=rule.rule_id,
        episode=state.episode,
        kind=kind,
        level=level,
        value=value,
        sample_time=sample_time,
        event_id=_event_id(
            rule.rule_id,
            state.episode,
            kind,
            level,
            ordinal,
            discriminator,
        ),
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


def _active_index(rule: RuleSpec, state: RuleState) -> int | None:
    if state.active_level is None:
        return None
    return next(
        (
            index
            for index, level in enumerate(rule.levels)
            if level.name == state.active_level
        ),
        None,
    )


def _sanitize_state(rule: RuleSpec, state: RuleState, now: datetime) -> RuleState:
    names = tuple(level.name for level in rule.levels)
    allowed = set(names)
    config_changed = (
        (
            state.rule_direction is not None
            and state.rule_direction is not rule.direction
        )
        or (bool(state.level_order) and state.level_order != names)
        or (state.active_level is not None and state.active_level not in allowed)
    )
    notification_times = tuple(
        (name, timestamp)
        for name, timestamp in state.level_notification_times
        if name in allowed and timestamp <= now
    )
    escalation_counts = tuple(
        (name, count)
        for name, count in state.level_escalation_counts
        if name in allowed
    )
    newest_sample_time = state.newest_sample_time
    newest_value = state.newest_value
    if (
        newest_sample_time is not None
        and _elapsed(newest_sample_time, now) > FUTURE_TOLERANCE
    ):
        newest_sample_time = None
        newest_value = None
    last_evaluated = state.last_evaluated_sample_time
    if last_evaluated is not None and _elapsed(last_evaluated, now) > FUTURE_TOLERANCE:
        last_evaluated = None
    last_notification = state.last_episode_notification_time
    if last_notification is not None and last_notification > now:
        last_notification = now
    return replace(
        state,
        newest_sample_time=newest_sample_time,
        newest_value=newest_value,
        last_evaluated_sample_time=last_evaluated,
        last_episode_notification_time=last_notification,
        level_notification_times=notification_times,
        level_escalation_counts=escalation_counts,
        rule_direction=rule.direction,
        level_order=names,
        needs_rederive=state.needs_rederive or config_changed,
    )


def _emit_escalation(
    rule: RuleSpec, state: RuleState, sample: Sample, now: datetime
) -> tuple[RuleState, Event | None]:
    level_name = cast(str, state.active_level)
    last_time = dict(state.level_notification_times).get(level_name)
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
        now=now,
    )


def _recover(
    rule: RuleSpec, state: RuleState, sample: Sample, now: datetime
) -> tuple[RuleState, list[Event]]:
    events: list[Event] = []
    if rule.recovery_notify and state.active_level is not None:
        events.append(
            _event(
                rule,
                state,
                EventKind.RECOVERED,
                level=None,
                ordinal=0,
                value=float(sample.value),
                sample_time=sample.timestamp,
                now=now,
            )
        )
    recovered = replace(
        state,
        active_level=None,
        clear_count=0,
        reminder_count=0,
        last_episode_notification_time=None,
        episode_started_at=None,
        level_notification_times=(),
        needs_rederive=False,
        last_evaluated_sample_time=sample.timestamp,
    )
    return recovered, events


def _rederive(
    rule: RuleSpec,
    state: RuleState,
    sample: Sample,
    now: datetime,
    *,
    allow_clear: bool,
) -> tuple[RuleState, list[Event]]:
    entry_level = _entry_level(rule, float(sample.value))
    if entry_level is None:
        if not allow_clear:
            return replace(state, last_evaluated_sample_time=sample.timestamp), []
        return _recover(rule, state, sample, now)
    level_name = rule.levels[entry_level].name
    already_notified = level_name in dict(state.level_notification_times)
    state = replace(
        state,
        active_level=level_name,
        clear_count=0,
        needs_rederive=False,
        last_evaluated_sample_time=sample.timestamp,
    )
    if already_notified:
        return state, []
    state, event = _emit_escalation(rule, state, sample, now)
    return state, [event] if event is not None else []


def _evaluate_threshold(
    rule: RuleSpec,
    state: RuleState,
    sample: Sample,
    now: datetime,
    *,
    allow_clear: bool,
) -> tuple[RuleState, list[Event]]:
    if state.needs_rederive:
        return _rederive(rule, state, sample, now, allow_clear=allow_clear)

    previous_level = _active_index(rule, state)
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
            active_level=rule.levels[entry_level].name,
            episode=min(state.episode + 1, MAX_COUNTER),
            clear_count=0,
            reminder_count=0,
            last_episode_notification_time=None,
            episode_started_at=now,
            level_notification_times=(),
            needs_rederive=False,
            last_evaluated_sample_time=sample.timestamp,
        )
        state, event = _emit_escalation(rule, state, sample, now)
        if event is not None:
            events.append(event)
        return state, events

    if entry_level is not None and entry_level > previous_level:
        state = replace(
            state,
            active_level=rule.levels[entry_level].name,
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
    if not allow_clear:
        return replace(state, last_evaluated_sample_time=sample.timestamp), events

    clear_count = min(state.clear_count + 1, MAX_COUNTER)
    if clear_count < rule.clear_after_samples:
        return replace(
            state,
            clear_count=clear_count,
            last_evaluated_sample_time=sample.timestamp,
        ), events
    if retained_level is not None:
        return replace(
            state,
            active_level=rule.levels[retained_level].name,
            clear_count=0,
            last_evaluated_sample_time=sample.timestamp,
        ), events
    return _recover(rule, state, sample, now)


def _maybe_remind(
    rule: RuleSpec, state: RuleState, now: datetime
) -> tuple[RuleState, Event | None]:
    active_level = state.active_level
    if (
        rule.reminder_max == 0
        or active_level != rule.levels[-1].name
        or state.reminder_count >= rule.reminder_max
    ):
        return state, None
    anchor = state.last_episode_notification_time or state.episode_started_at
    if anchor is None:
        return state, None
    if anchor > now:
        return replace(state, last_episode_notification_time=now), None
    if _elapsed(now, anchor) < rule.reminder_interval:
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
        level=active_level,
        ordinal=count,
        value=state.newest_value,
        sample_time=state.newest_sample_time,
        now=now,
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
    state = _sanitize_state(rule, state, now)
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
    if not is_fresh and not state.stale:
        state = replace(
            state,
            stale=True,
            stale_cycle=min(state.stale_cycle + 1, MAX_COUNTER),
            stale_started_at=now,
        )
        events.append(
            _event(
                rule,
                state,
                EventKind.STALE,
                level=state.active_level,
                ordinal=state.stale_cycle,
                value=state.newest_value,
                sample_time=state.newest_sample_time,
                now=now,
            )
        )
    elif is_fresh and state.stale:
        events.append(
            _event(
                rule,
                state,
                EventKind.RESTORED,
                level=state.active_level,
                ordinal=state.stale_cycle,
                value=state.newest_value,
                sample_time=state.newest_sample_time,
                now=now,
            )
        )
        state = replace(state, stale=False, stale_started_at=None)

    if usable is not None and (
        state.last_evaluated_sample_time is None
        or usable.timestamp > state.last_evaluated_sample_time
    ):
        sample_is_fresh = _elapsed(now, usable.timestamp) <= rule.stale_after
        state, threshold_events = _evaluate_threshold(
            rule,
            state,
            usable,
            now,
            allow_clear=sample_is_fresh,
        )
        events.extend(threshold_events)

    state, reminder = _maybe_remind(rule, state, now)
    if reminder is not None:
        events.append(reminder)
    return state, events

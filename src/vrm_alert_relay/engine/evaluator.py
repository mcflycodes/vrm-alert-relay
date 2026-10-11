"""Pure deterministic evaluation for alert rules."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Final, cast

from .models import (
    MAX_COUNTER,
    Direction,
    Event,
    EventKind,
    LevelTime,
    RuleSpec,
    RuleState,
    Sample,
)

FUTURE_TOLERANCE: Final = timedelta(seconds=60)
NO_SAMPLE_DISCRIMINATOR: Final = datetime(1970, 1, 1, tzinfo=UTC)


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


def _event_id(
    rule_id: str,
    generation: str,
    episode: int,
    kind: EventKind,
    level: str | None,
    ordinal: int,
    discriminator: datetime,
) -> str:
    identity = json.dumps(
        [
            rule_id,
            generation,
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
    discriminator: datetime,
) -> Event:
    return Event(
        rule_id=rule.rule_id,
        episode=state.episode,
        kind=kind,
        level=level,
        value=value,
        sample_time=sample_time,
        event_id=_event_id(
            rule.rule_id,
            cast(str, state.generation),
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


def _provisional_level(rule: RuleSpec, state: RuleState) -> str | None:
    active = state.active_level
    if active is None:
        return None
    if any(level.name == active for level in rule.levels):
        return active
    try:
        old_index = state.level_order.index(active)
    except ValueError:
        return None
    if old_index >= len(rule.levels):
        return rule.levels[-1].name
    return rule.levels[old_index].name


def _sanitize_state(rule: RuleSpec, state: RuleState, now: datetime) -> RuleState:
    names = tuple(level.name for level in rule.levels)
    allowed = set(names)
    direction_changed = (
        state.rule_direction is not None and state.rule_direction is not rule.direction
    )
    active_missing = (
        state.active_level is not None and state.active_level not in allowed
    )
    needs_rederive = state.needs_rederive or direction_changed or active_missing
    prior_order = state.level_order
    level_order = prior_order if needs_rederive and prior_order else names

    notification_times = tuple(
        (name, timestamp)
        for name, timestamp in state.level_notification_times
        if name in allowed and timestamp <= now
    )
    episode_levels = tuple(
        name for name in state.episode_notified_levels if name in allowed
    )
    pending = state.pending_escalation
    if pending is not None and pending not in allowed:
        pending = _provisional_level(rule, state)
    if (
        state.active_level is not None
        and not state.episode_announced
        and pending is None
    ):
        pending = _provisional_level(rule, state)

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

    episode_started = state.episode_started_at
    if state.active_level is not None and episode_started is None:
        episode_started = now
    if (
        state.active_level is not None
        and state.episode_announced
        and last_notification is None
    ):
        last_notification = now

    return replace(
        state,
        newest_sample_time=newest_sample_time,
        newest_value=newest_value,
        last_evaluated_sample_time=last_evaluated,
        last_episode_notification_time=last_notification,
        episode_started_at=episode_started,
        episode_notified_levels=episode_levels,
        pending_escalation=pending,
        level_notification_times=notification_times,
        rule_direction=rule.direction,
        level_order=level_order,
        needs_rederive=needs_rederive,
    )


def _send_escalation(
    rule: RuleSpec,
    state: RuleState,
    level_name: str,
    now: datetime,
    *,
    value: float | None,
    sample_time: datetime | None,
) -> tuple[RuleState, Event]:
    ordinal = min(state.escalation_ordinal + 1, MAX_COUNTER)
    notified = tuple(dict.fromkeys((*state.episode_notified_levels, level_name)))
    state = replace(
        state,
        level_notification_times=_mapping_set_time(
            state.level_notification_times, level_name, now
        ),
        episode_notified_levels=notified,
        escalation_ordinal=ordinal,
        episode_announced=True,
        pending_escalation=None,
        last_episode_notification_time=now,
    )
    discriminator = state.episode_started_at or sample_time or NO_SAMPLE_DISCRIMINATOR
    return state, _event(
        rule,
        state,
        EventKind.ESCALATED,
        level=level_name,
        ordinal=ordinal,
        value=value,
        sample_time=sample_time,
        discriminator=discriminator,
    )


def _attempt_escalation(
    rule: RuleSpec,
    state: RuleState,
    level_name: str,
    now: datetime,
    *,
    value: float | None,
    sample_time: datetime | None,
) -> tuple[RuleState, Event | None]:
    last_time = dict(state.level_notification_times).get(level_name)
    if last_time is not None and _elapsed(now, last_time) < rule.cooldown:
        return replace(
            state,
            pending_escalation=level_name,
            suppressed_escalations=min(state.suppressed_escalations + 1, MAX_COUNTER),
        ), None
    return _send_escalation(
        rule,
        state,
        level_name,
        now,
        value=value,
        sample_time=sample_time,
    )


def _recover(
    rule: RuleSpec, state: RuleState, sample: Sample
) -> tuple[RuleState, list[Event]]:
    events: list[Event] = []
    if (
        rule.recovery_notify
        and state.episode_announced
        and state.active_level is not None
    ):
        discriminator = state.episode_started_at or sample.timestamp
        events.append(
            _event(
                rule,
                state,
                EventKind.RECOVERED,
                level=None,
                ordinal=0,
                value=float(sample.value),
                sample_time=sample.timestamp,
                discriminator=discriminator,
            )
        )
    recovered = replace(
        state,
        active_level=None,
        clear_count=0,
        reminder_count=0,
        last_episode_notification_time=None,
        episode_started_at=None,
        episode_announced=False,
        episode_notified_levels=(),
        pending_escalation=None,
        escalation_ordinal=0,
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
    if state.active_level is None:
        remapped = replace(
            state,
            needs_rederive=False,
            level_order=tuple(level.name for level in rule.levels),
        )
        return _evaluate_threshold(rule, remapped, sample, now, allow_clear=allow_clear)

    entry_level = _entry_level(rule, float(sample.value))
    if entry_level is None:
        if not allow_clear:
            return replace(state, last_evaluated_sample_time=sample.timestamp), []
        return _recover(rule, state, sample)
    level_name = rule.levels[entry_level].name
    already_notified = level_name in state.episode_notified_levels
    state = replace(
        state,
        active_level=level_name,
        clear_count=0,
        needs_rederive=False,
        level_order=tuple(level.name for level in rule.levels),
        last_evaluated_sample_time=sample.timestamp,
    )
    if already_notified:
        return state, []
    state, event = _attempt_escalation(
        rule,
        state,
        level_name,
        now,
        value=float(sample.value),
        sample_time=sample.timestamp,
    )
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
        level_name = rule.levels[entry_level].name
        state = replace(
            state,
            active_level=level_name,
            episode=min(state.episode + 1, MAX_COUNTER),
            clear_count=0,
            reminder_count=0,
            last_episode_notification_time=None,
            episode_started_at=sample.timestamp,
            episode_announced=False,
            episode_notified_levels=(),
            pending_escalation=None,
            escalation_ordinal=0,
            needs_rederive=False,
            level_order=tuple(level.name for level in rule.levels),
            last_evaluated_sample_time=sample.timestamp,
        )
        state, event = _attempt_escalation(
            rule,
            state,
            level_name,
            now,
            value=float(sample.value),
            sample_time=sample.timestamp,
        )
        if event is not None:
            events.append(event)
        return state, events

    if entry_level is not None and entry_level > previous_level:
        level_name = rule.levels[entry_level].name
        state = replace(
            state,
            active_level=level_name,
            clear_count=0,
            last_evaluated_sample_time=sample.timestamp,
        )
        state, event = _attempt_escalation(
            rule,
            state,
            level_name,
            now,
            value=float(sample.value),
            sample_time=sample.timestamp,
        )
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
    return _recover(rule, state, sample)


def _maybe_emit_pending(
    rule: RuleSpec, state: RuleState, now: datetime
) -> tuple[RuleState, Event | None]:
    if state.pending_escalation is None:
        return state, None
    level_name = _provisional_level(rule, state)
    if level_name is None:
        return replace(state, pending_escalation=None), None
    if state.episode_announced and level_name in state.episode_notified_levels:
        return replace(state, pending_escalation=None), None
    last_time = dict(state.level_notification_times).get(level_name)
    if last_time is not None and _elapsed(now, last_time) < rule.cooldown:
        return replace(state, pending_escalation=level_name), None
    return _send_escalation(
        rule,
        state,
        level_name,
        now,
        value=state.newest_value,
        sample_time=state.newest_sample_time,
    )


def _maybe_remind(
    rule: RuleSpec, state: RuleState, now: datetime
) -> tuple[RuleState, Event | None]:
    if not state.episode_announced:
        return state, None
    active_level = _provisional_level(rule, state)
    if (
        rule.reminder_max == 0
        or active_level != rule.levels[-1].name
        or state.reminder_count >= rule.reminder_max
    ):
        return state, None
    anchor = cast(
        datetime, state.last_episode_notification_time or state.episode_started_at
    )
    if _elapsed(now, anchor) < rule.reminder_interval:
        return state, None
    count = state.reminder_count + 1
    state = replace(
        state,
        reminder_count=count,
        last_episode_notification_time=now,
    )
    discriminator = state.episode_started_at or NO_SAMPLE_DISCRIMINATOR
    return state, _event(
        rule,
        state,
        EventKind.REMINDER,
        level=active_level,
        ordinal=count,
        value=state.newest_value,
        sample_time=state.newest_sample_time,
        discriminator=discriminator,
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
    if state.generation is None:
        state = replace(state, generation=now.isoformat())
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
        )
        discriminator = state.newest_sample_time or NO_SAMPLE_DISCRIMINATOR
        events.append(
            _event(
                rule,
                state,
                EventKind.STALE,
                level=_provisional_level(rule, state),
                ordinal=state.stale_cycle,
                value=state.newest_value,
                sample_time=state.newest_sample_time,
                discriminator=discriminator,
            )
        )
    elif is_fresh and state.stale:
        discriminator = state.newest_sample_time or NO_SAMPLE_DISCRIMINATOR
        events.append(
            _event(
                rule,
                state,
                EventKind.RESTORED,
                level=_provisional_level(rule, state),
                ordinal=state.stale_cycle,
                value=state.newest_value,
                sample_time=state.newest_sample_time,
                discriminator=discriminator,
            )
        )
        state = replace(state, stale=False)

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

    state, pending_event = _maybe_emit_pending(rule, state, now)
    if pending_event is not None:
        events.append(pending_event)
    state, reminder = _maybe_remind(rule, state, now)
    if reminder is not None:
        events.append(reminder)
    return state, events

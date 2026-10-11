"""Immutable domain types for the alert rules engine."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from itertools import pairwise
from typing import Final, cast

MAX_LEVELS: Final = 128
MAX_TEXT_LENGTH: Final = 256
MAX_COUNTER: Final = 2**63 - 1
MAX_TIMESTAMP_LENGTH: Final = 64
STATE_VERSION: Final = 3

type LevelTime = tuple[str, datetime]


class Direction(StrEnum):
    """The direction in which increasing severity is reached."""

    RISING = "rising"
    FALLING = "falling"


class EventKind(StrEnum):
    """Events produced by rule evaluation."""

    ESCALATED = "escalated"
    RECOVERED = "recovered"
    REMINDER = "reminder"
    STALE = "stale"
    RESTORED = "restored"


class InvalidRuleStateError(ValueError):
    """Raised when persisted rule state is malformed or outside safe bounds."""


def _is_aware(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _valid_name(value: object) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_TEXT_LENGTH


def _valid_counter(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= MAX_COUNTER


def _finite_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


@dataclass(frozen=True, slots=True)
class LevelSpec:
    """One named threshold in a severity ladder."""

    name: str
    threshold: float

    def __post_init__(self) -> None:
        if not _valid_name(self.name):
            raise ValueError("level name must be a non-empty bounded string")  # noqa: TRY003  # per-check validation message
        if not _finite_number(self.threshold):
            raise ValueError("level threshold must be finite")  # noqa: TRY003  # per-check validation message


@dataclass(frozen=True, slots=True)
class RuleSpec:
    """Validated configuration for one alert rule."""

    rule_id: str
    direction: Direction
    levels: tuple[LevelSpec, ...]
    hysteresis: float = 0.0
    clear_after_samples: int = 1
    recovery_notify: bool = True
    cooldown: timedelta = timedelta(minutes=15)
    reminder_interval: timedelta = timedelta(minutes=60)
    reminder_max: int = 3
    stale_after: timedelta = timedelta(minutes=35)

    def __post_init__(self) -> None:  # noqa: C901, PLR0912  # flat validation checklist, deliberately not split
        if not _valid_name(self.rule_id):
            raise ValueError("rule_id must be a non-empty bounded string")  # noqa: TRY003  # per-check validation message
        if not isinstance(self.direction, Direction):
            raise ValueError("direction must be a Direction")  # noqa: TRY003, TRY004  # per-check validation message
        if (
            not isinstance(self.levels, tuple)
            or not self.levels
            or len(self.levels) > MAX_LEVELS
            or any(not isinstance(level, LevelSpec) for level in self.levels)
        ):
            raise ValueError(f"levels must contain 1 to {MAX_LEVELS} LevelSpec values")  # noqa: TRY003  # per-check validation message
        names = [level.name for level in self.levels]
        if len(set(names)) != len(names):
            raise ValueError("level names must be unique")  # noqa: TRY003  # per-check validation message
        thresholds = [float(level.threshold) for level in self.levels]
        if self.direction is Direction.RISING:
            ordered = all(left < right for left, right in pairwise(thresholds))
        else:
            ordered = all(left > right for left, right in pairwise(thresholds))
        if not ordered:
            raise ValueError("thresholds must be strictly ordered by increasing severity")  # noqa: TRY003  # per-check validation message
        if not _finite_number(self.hysteresis) or self.hysteresis < 0:
            raise ValueError("hysteresis must be finite and non-negative")  # noqa: TRY003  # per-check validation message
        if (
            isinstance(self.clear_after_samples, bool)
            or not isinstance(self.clear_after_samples, int)
            or self.clear_after_samples < 1
        ):
            raise ValueError("clear_after_samples must be at least 1")  # noqa: TRY003  # per-check validation message
        if not isinstance(self.recovery_notify, bool):
            raise ValueError("recovery_notify must be a bool")  # noqa: TRY003, TRY004  # per-check validation message
        if (
            not isinstance(self.reminder_max, int)
            or isinstance(self.reminder_max, bool)
            or not 0 <= self.reminder_max <= MAX_COUNTER
        ):
            raise ValueError("reminder_max must be a non-negative integer")  # noqa: TRY003  # per-check validation message
        durations = (
            ("cooldown", self.cooldown, True),
            ("reminder_interval", self.reminder_interval, False),
            ("stale_after", self.stale_after, False),
        )
        for name, duration, allow_zero in durations:
            if not isinstance(duration, timedelta):
                raise ValueError(f"{name} must be a timedelta")  # noqa: TRY003, TRY004  # per-check validation message
            if duration < timedelta(0) or (not allow_zero and duration == timedelta(0)):
                qualifier = "non-negative" if allow_zero else "positive"
                raise ValueError(f"{name} must be {qualifier}")  # noqa: TRY003  # per-check validation message


@dataclass(frozen=True, slots=True)
class Sample:
    """A numeric measurement and its source timestamp."""

    value: float
    timestamp: datetime


@dataclass(frozen=True, slots=True)
class Event:
    """A deterministic event for a downstream delivery layer."""

    rule_id: str
    episode: int
    kind: EventKind
    level: str | None
    value: float | None
    sample_time: datetime | None
    event_id: str


@dataclass(frozen=True, slots=True)
class RuleState:
    """All persisted state needed to evaluate one rule deterministically."""

    generation: str | None = None
    active_level: str | None = None
    episode: int = 0
    clear_count: int = 0
    newest_sample_time: datetime | None = None
    newest_value: float | None = None
    last_evaluated_sample_time: datetime | None = None
    stale: bool = False
    stale_cycle: int = 0
    reminder_count: int = 0
    last_episode_notification_time: datetime | None = None
    episode_started_at: datetime | None = None
    episode_announced: bool = False
    episode_notified_levels: tuple[str, ...] = ()
    pending_escalation: str | None = None
    escalation_ordinal: int = 0
    rule_direction: Direction | None = None
    level_order: tuple[str, ...] = ()
    needs_rederive: bool = False
    level_notification_times: tuple[LevelTime, ...] = ()
    suppressed_escalations: int = 0

    def __post_init__(self) -> None:
        try:
            self._validate()
        except (TypeError, ValueError, OverflowError) as exc:
            if isinstance(exc, InvalidRuleStateError):
                raise
            raise InvalidRuleStateError(str(exc)) from exc

    def _validate(self) -> None:  # noqa: C901, PLR0912  # flat validation checklist, deliberately not split
        self._validate_generation()
        if self.active_level is not None and not _valid_name(self.active_level):
            raise InvalidRuleStateError("active_level must be a bounded level name")  # noqa: TRY003  # per-check validation message
        if self.pending_escalation is not None and not _valid_name(self.pending_escalation):
            raise InvalidRuleStateError("pending_escalation must be a bounded level name")  # noqa: TRY003  # per-check validation message
        for name in (
            "episode",
            "clear_count",
            "stale_cycle",
            "reminder_count",
            "escalation_ordinal",
            "suppressed_escalations",
        ):
            if not _valid_counter(getattr(self, name)):
                raise InvalidRuleStateError(f"{name} is outside safe bounds")  # noqa: TRY003  # per-check validation message
        if (
            not isinstance(self.stale, bool)
            or not isinstance(self.needs_rederive, bool)
            or not isinstance(self.episode_announced, bool)
        ):
            raise InvalidRuleStateError("state flags must be bools")  # noqa: TRY003  # per-check validation message
        if self.rule_direction is not None and not isinstance(self.rule_direction, Direction):
            raise InvalidRuleStateError("rule_direction must be a Direction or null")  # noqa: TRY003  # per-check validation message
        if (
            not isinstance(self.level_order, tuple)
            or len(self.level_order) > MAX_LEVELS
            or any(not _valid_name(name) for name in self.level_order)
            or len(set(self.level_order)) != len(self.level_order)
        ):
            raise InvalidRuleStateError("level_order must contain unique bounded names")  # noqa: TRY003  # per-check validation message
        for name in (
            "newest_sample_time",
            "last_evaluated_sample_time",
            "last_episode_notification_time",
            "episode_started_at",
        ):
            value = getattr(self, name)
            if value is not None and (not isinstance(value, datetime) or not _is_aware(value)):
                raise InvalidRuleStateError(f"{name} must be an aware datetime or null")  # noqa: TRY003  # per-check validation message
        if self.newest_value is not None and not _finite_number(self.newest_value):
            raise InvalidRuleStateError("newest_value must be finite or null")  # noqa: TRY003  # per-check validation message
        self._validate_level_times(self.level_notification_times, "level notification times")
        self._validate_names(self.episode_notified_levels, "episode_notified_levels")
        if self.active_level is not None and self.episode < 1:
            raise InvalidRuleStateError("an active level requires a positive episode")  # noqa: TRY003  # per-check validation message
        if self.active_level is None and self.clear_count != 0:
            raise InvalidRuleStateError("normal state cannot have a clear_count")  # noqa: TRY003  # per-check validation message
        if self.reminder_count and self.active_level is None:
            raise InvalidRuleStateError("normal state cannot have reminders")  # noqa: TRY003  # per-check validation message
        if self.pending_escalation is not None and self.active_level is None:
            raise InvalidRuleStateError("normal state cannot have a pending escalation")  # noqa: TRY003  # per-check validation message
        if self.episode_announced and self.active_level is None:
            raise InvalidRuleStateError("normal state cannot have an announced episode")  # noqa: TRY003  # per-check validation message

    def _validate_generation(self) -> None:
        if self.generation is None:
            return
        if not isinstance(self.generation, str) or len(self.generation) > MAX_TIMESTAMP_LENGTH:
            raise InvalidRuleStateError("generation must be a bounded ISO timestamp")  # noqa: TRY003  # per-check validation message
        try:
            timestamp = datetime.fromisoformat(self.generation)
        except ValueError as exc:
            raise InvalidRuleStateError("generation is not an ISO timestamp") from exc  # noqa: TRY003  # per-check validation message
        if not _is_aware(timestamp):
            raise InvalidRuleStateError("generation must be timezone-aware")  # noqa: TRY003  # per-check validation message

    @staticmethod
    def _validate_names(values: object, field: str) -> None:
        if (
            not isinstance(values, tuple)
            or len(values) > MAX_LEVELS
            or any(not _valid_name(name) for name in values)
            or len(set(values)) != len(values)
        ):
            raise InvalidRuleStateError(f"{field} must contain unique bounded names")  # noqa: TRY003  # per-check validation message

    @staticmethod
    def _validate_level_times(values: object, field: str) -> None:
        if not isinstance(values, tuple) or len(values) > MAX_LEVELS:
            raise InvalidRuleStateError(f"too many {field}")  # noqa: TRY003  # per-check validation message
        names: set[str] = set()
        for item in values:
            if not isinstance(item, tuple) or len(item) != 2:  # noqa: PLR2004  # a (name, timestamp) pair
                raise InvalidRuleStateError(f"invalid {field} entry")  # noqa: TRY003  # per-check validation message
            name, timestamp = item
            if not _valid_name(name) or name in names:
                raise InvalidRuleStateError(f"invalid or duplicate {field} level")  # noqa: TRY003  # per-check validation message
            if not isinstance(timestamp, datetime) or not _is_aware(timestamp):
                raise InvalidRuleStateError(f"{field} timestamp must be aware")  # noqa: TRY003  # per-check validation message
            names.add(name)

    def to_dict(self) -> dict[str, object]:
        """Return a bounded, JSON-compatible representation."""

        def encode_time(value: datetime | None) -> str | None:
            return value.isoformat() if value is not None else None

        return {
            "version": STATE_VERSION,
            "generation": self.generation,
            "active_level": self.active_level,
            "episode": self.episode,
            "clear_count": self.clear_count,
            "newest_sample_time": encode_time(self.newest_sample_time),
            "newest_value": self.newest_value,
            "last_evaluated_sample_time": encode_time(self.last_evaluated_sample_time),
            "stale": self.stale,
            "stale_cycle": self.stale_cycle,
            "reminder_count": self.reminder_count,
            "last_episode_notification_time": encode_time(self.last_episode_notification_time),
            "episode_started_at": encode_time(self.episode_started_at),
            "episode_announced": self.episode_announced,
            "episode_notified_levels": list(self.episode_notified_levels),
            "pending_escalation": self.pending_escalation,
            "escalation_ordinal": self.escalation_ordinal,
            "rule_direction": (
                self.rule_direction.value if self.rule_direction is not None else None
            ),
            "level_order": list(self.level_order),
            "needs_rederive": self.needs_rederive,
            "level_notification_times": [
                [name, timestamp.isoformat()] for name, timestamp in self.level_notification_times
            ],
            "suppressed_escalations": self.suppressed_escalations,
        }

    @classmethod
    def from_dict(cls, data: object) -> RuleState:  # noqa: C901  # flat decode checklist, deliberately not split
        """Validate and decode untrusted persisted state."""

        keys = {
            "version",
            "generation",
            "active_level",
            "episode",
            "clear_count",
            "newest_sample_time",
            "newest_value",
            "last_evaluated_sample_time",
            "stale",
            "stale_cycle",
            "reminder_count",
            "last_episode_notification_time",
            "episode_started_at",
            "episode_announced",
            "episode_notified_levels",
            "pending_escalation",
            "escalation_ordinal",
            "rule_direction",
            "level_order",
            "needs_rederive",
            "level_notification_times",
            "suppressed_escalations",
        }
        if not isinstance(data, dict) or len(data) != len(keys) or set(data) != keys:
            raise InvalidRuleStateError("state must contain exactly the version 3 fields")  # noqa: TRY003  # per-check validation message
        if (
            not isinstance(data["version"], int)
            or isinstance(data["version"], bool)
            or data["version"] != STATE_VERSION
        ):
            raise InvalidRuleStateError("unsupported state version")  # noqa: TRY003  # per-check validation message

        def decode_time(name: str) -> datetime | None:
            raw = data[name]
            if raw is None:
                return None
            if not isinstance(raw, str) or len(raw) > MAX_TIMESTAMP_LENGTH:
                raise InvalidRuleStateError(f"{name} must be a bounded ISO timestamp")  # noqa: TRY003  # per-check validation message
            try:
                value = datetime.fromisoformat(raw)
            except ValueError as exc:
                raise InvalidRuleStateError(f"{name} is not an ISO timestamp") from exc  # noqa: TRY003  # per-check validation message
            if not _is_aware(value):
                raise InvalidRuleStateError(f"{name} must be timezone-aware")  # noqa: TRY003  # per-check validation message
            return value

        notification_times = cls._decode_pairs(data["level_notification_times"])
        raw_direction = data["rule_direction"]
        if raw_direction is None:
            direction = None
        elif isinstance(raw_direction, str):
            try:
                direction = Direction(raw_direction)
            except ValueError as exc:
                raise InvalidRuleStateError("invalid rule_direction") from exc  # noqa: TRY003  # per-check validation message
        else:
            raise InvalidRuleStateError("invalid rule_direction")  # noqa: TRY003  # per-check validation message
        raw_level_order = data["level_order"]
        if not isinstance(raw_level_order, list) or len(raw_level_order) > MAX_LEVELS:
            raise InvalidRuleStateError("level_order must be a bounded list")  # noqa: TRY003  # per-check validation message
        level_order = tuple(raw_level_order)
        raw_active_level = data["active_level"]
        if (
            isinstance(raw_active_level, str)
            and level_order
            and raw_active_level not in level_order
        ):
            raise InvalidRuleStateError("active_level must appear in non-empty level_order")  # noqa: TRY003  # per-check validation message
        raw_episode_levels = data["episode_notified_levels"]
        if not isinstance(raw_episode_levels, list) or len(raw_episode_levels) > MAX_LEVELS:
            raise InvalidRuleStateError("episode_notified_levels must be a bounded list")  # noqa: TRY003  # per-check validation message
        episode_levels = tuple(raw_episode_levels)
        return cls(
            generation=cast("str | None", data["generation"]),
            active_level=cast("str | None", raw_active_level),
            episode=cast("int", data["episode"]),
            clear_count=cast("int", data["clear_count"]),
            newest_sample_time=decode_time("newest_sample_time"),
            newest_value=cast("float | None", data["newest_value"]),
            last_evaluated_sample_time=decode_time("last_evaluated_sample_time"),
            stale=cast("bool", data["stale"]),
            stale_cycle=cast("int", data["stale_cycle"]),
            reminder_count=cast("int", data["reminder_count"]),
            last_episode_notification_time=decode_time("last_episode_notification_time"),
            episode_started_at=decode_time("episode_started_at"),
            episode_announced=cast("bool", data["episode_announced"]),
            episode_notified_levels=cast("tuple[str, ...]", episode_levels),
            pending_escalation=cast("str | None", data["pending_escalation"]),
            escalation_ordinal=cast("int", data["escalation_ordinal"]),
            rule_direction=direction,
            level_order=cast("tuple[str, ...]", level_order),
            needs_rederive=cast("bool", data["needs_rederive"]),
            level_notification_times=notification_times,
            suppressed_escalations=cast("int", data["suppressed_escalations"]),
        )

    @staticmethod
    def _decode_pairs(
        raw: object,
    ) -> tuple[tuple[str, datetime], ...]:
        if not isinstance(raw, list) or len(raw) > MAX_LEVELS:
            raise InvalidRuleStateError("state history must be a bounded list")  # noqa: TRY003  # per-check validation message
        result: list[tuple[str, datetime]] = []
        for item in raw:
            if not isinstance(item, list) or len(item) != 2 or not _valid_name(item[0]):  # noqa: PLR2004  # a (name, timestamp) pair
                raise InvalidRuleStateError("invalid state history entry")  # noqa: TRY003  # per-check validation message
            name = cast("str", item[0])
            value = item[1]
            if not isinstance(value, str) or len(value) > MAX_TIMESTAMP_LENGTH:
                raise InvalidRuleStateError("invalid notification timestamp")  # noqa: TRY003  # per-check validation message
            try:
                timestamp = datetime.fromisoformat(value)
            except ValueError as exc:
                raise InvalidRuleStateError("invalid notification timestamp") from exc  # noqa: TRY003  # per-check validation message
            if not _is_aware(timestamp):
                raise InvalidRuleStateError("notification timestamp must be aware")  # noqa: TRY003  # per-check validation message
            result.append((name, timestamp))
        return tuple(result)

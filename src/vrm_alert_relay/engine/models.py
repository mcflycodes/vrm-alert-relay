"""Immutable domain types for the alert rules engine."""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final, TypeAlias, cast

MAX_LEVELS: Final = 128
MAX_TEXT_LENGTH: Final = 256
MAX_COUNTER: Final = 2**63 - 1

LevelTime: TypeAlias = tuple[str, datetime]
LevelCount: TypeAlias = tuple[str, int]


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
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= MAX_COUNTER
    )


@dataclass(frozen=True, slots=True)
class LevelSpec:
    """One named threshold in a severity ladder."""

    name: str
    threshold: float

    def __post_init__(self) -> None:
        if not _valid_name(self.name):
            raise ValueError("level name must be a non-empty bounded string")
        if (
            isinstance(self.threshold, bool)
            or not isinstance(self.threshold, (int, float))
            or not math.isfinite(self.threshold)
        ):
            raise ValueError("level threshold must be finite")


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

    def __post_init__(self) -> None:
        if not _valid_name(self.rule_id):
            raise ValueError("rule_id must be a non-empty bounded string")
        if not isinstance(self.direction, Direction):
            raise ValueError("direction must be a Direction")
        if (
            not isinstance(self.levels, tuple)
            or not self.levels
            or len(self.levels) > MAX_LEVELS
            or any(not isinstance(level, LevelSpec) for level in self.levels)
        ):
            raise ValueError(f"levels must contain 1 to {MAX_LEVELS} LevelSpec values")
        names = [level.name for level in self.levels]
        if len(set(names)) != len(names):
            raise ValueError("level names must be unique")
        thresholds = [float(level.threshold) for level in self.levels]
        if self.direction is Direction.RISING:
            ordered = all(
                left < right
                for left, right in zip(thresholds, thresholds[1:], strict=False)
            )
        else:
            ordered = all(
                left > right
                for left, right in zip(thresholds, thresholds[1:], strict=False)
            )
        if not ordered:
            raise ValueError(
                "thresholds must be strictly ordered by increasing severity"
            )
        if (
            isinstance(self.hysteresis, bool)
            or not isinstance(self.hysteresis, (int, float))
            or not math.isfinite(self.hysteresis)
            or self.hysteresis < 0
        ):
            raise ValueError("hysteresis must be finite and non-negative")
        if (
            isinstance(self.clear_after_samples, bool)
            or not isinstance(self.clear_after_samples, int)
            or self.clear_after_samples < 1
        ):
            raise ValueError("clear_after_samples must be at least 1")
        if not isinstance(self.recovery_notify, bool):
            raise ValueError("recovery_notify must be a bool")
        if (
            not isinstance(self.reminder_max, int)
            or isinstance(self.reminder_max, bool)
            or not 0 <= self.reminder_max <= MAX_COUNTER
        ):
            raise ValueError("reminder_max must be a non-negative integer")
        durations = (
            ("cooldown", self.cooldown, True),
            ("reminder_interval", self.reminder_interval, False),
            ("stale_after", self.stale_after, False),
        )
        for name, duration, allow_zero in durations:
            if not isinstance(duration, timedelta):
                raise ValueError(f"{name} must be a timedelta")
            if duration < timedelta(0) or (not allow_zero and duration == timedelta(0)):
                qualifier = "non-negative" if allow_zero else "positive"
                raise ValueError(f"{name} must be {qualifier}")


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

    active_level: int | None = None
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
    level_notification_times: tuple[LevelTime, ...] = ()
    level_escalation_counts: tuple[LevelCount, ...] = ()
    suppressed_escalations: int = 0

    def __post_init__(self) -> None:
        try:
            self._validate()
        except (TypeError, ValueError, OverflowError) as exc:
            if isinstance(exc, InvalidRuleStateError):
                raise
            raise InvalidRuleStateError(str(exc)) from exc

    def _validate(self) -> None:
        if self.active_level is not None and (
            not _valid_counter(self.active_level) or self.active_level >= MAX_LEVELS
        ):
            raise InvalidRuleStateError("active_level is outside safe bounds")
        for name in (
            "episode",
            "clear_count",
            "stale_cycle",
            "reminder_count",
            "suppressed_escalations",
        ):
            if not _valid_counter(getattr(self, name)):
                raise InvalidRuleStateError(f"{name} is outside safe bounds")
        if not isinstance(self.stale, bool):
            raise InvalidRuleStateError("stale must be a bool")
        for name in (
            "newest_sample_time",
            "last_evaluated_sample_time",
            "last_episode_notification_time",
            "episode_started_at",
        ):
            value = getattr(self, name)
            if value is not None and (
                not isinstance(value, datetime) or not _is_aware(value)
            ):
                raise InvalidRuleStateError(f"{name} must be an aware datetime or null")
        if self.newest_value is not None and (
            isinstance(self.newest_value, bool)
            or not isinstance(self.newest_value, (int, float))
            or not math.isfinite(self.newest_value)
        ):
            raise InvalidRuleStateError("newest_value must be finite or null")
        if len(self.level_notification_times) > MAX_LEVELS:
            raise InvalidRuleStateError("too many level notification times")
        if len(self.level_escalation_counts) > MAX_LEVELS:
            raise InvalidRuleStateError("too many level escalation counts")
        self._validate_level_times()
        self._validate_level_counts()
        if self.active_level is None and self.clear_count != 0:
            raise InvalidRuleStateError("normal state cannot have a clear_count")
        if self.reminder_count and self.active_level is None:
            raise InvalidRuleStateError("normal state cannot have reminders")

    def _validate_level_times(self) -> None:
        names: set[str] = set()
        for item in self.level_notification_times:
            if not isinstance(item, tuple) or len(item) != 2:
                raise InvalidRuleStateError("invalid level notification entry")
            name, timestamp = item
            if not _valid_name(name) or name in names:
                raise InvalidRuleStateError("invalid or duplicate notification level")
            if not isinstance(timestamp, datetime) or not _is_aware(timestamp):
                raise InvalidRuleStateError("notification time must be aware")
            names.add(name)

    def _validate_level_counts(self) -> None:
        names: set[str] = set()
        for item in self.level_escalation_counts:
            if not isinstance(item, tuple) or len(item) != 2:
                raise InvalidRuleStateError("invalid level escalation entry")
            name, count = item
            if (
                not _valid_name(name)
                or name in names
                or not _valid_counter(count)
                or count == 0
            ):
                raise InvalidRuleStateError("invalid or duplicate escalation count")
            names.add(name)

    def to_dict(self) -> dict[str, object]:
        """Return a bounded, JSON-compatible representation."""

        def encode_time(value: datetime | None) -> str | None:
            return value.isoformat() if value is not None else None

        return {
            "version": 1,
            "active_level": self.active_level,
            "episode": self.episode,
            "clear_count": self.clear_count,
            "newest_sample_time": encode_time(self.newest_sample_time),
            "newest_value": self.newest_value,
            "last_evaluated_sample_time": encode_time(self.last_evaluated_sample_time),
            "stale": self.stale,
            "stale_cycle": self.stale_cycle,
            "reminder_count": self.reminder_count,
            "last_episode_notification_time": encode_time(
                self.last_episode_notification_time
            ),
            "episode_started_at": encode_time(self.episode_started_at),
            "level_notification_times": [
                [name, timestamp.isoformat()]
                for name, timestamp in self.level_notification_times
            ],
            "level_escalation_counts": [
                [name, count] for name, count in self.level_escalation_counts
            ],
            "suppressed_escalations": self.suppressed_escalations,
        }

    @classmethod
    def from_dict(cls, data: object) -> RuleState:
        """Validate and decode untrusted persisted state."""

        keys = {
            "version",
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
            "level_notification_times",
            "level_escalation_counts",
            "suppressed_escalations",
        }
        if not isinstance(data, dict) or len(data) != len(keys) or set(data) != keys:
            raise InvalidRuleStateError(
                "state must contain exactly the version 1 fields"
            )
        if (
            not isinstance(data["version"], int)
            or isinstance(data["version"], bool)
            or data["version"] != 1
        ):
            raise InvalidRuleStateError("unsupported state version")

        def decode_time(name: str) -> datetime | None:
            raw = data[name]
            if raw is None:
                return None
            if not isinstance(raw, str) or len(raw) > 64:
                raise InvalidRuleStateError(f"{name} must be a bounded ISO timestamp")
            try:
                value = datetime.fromisoformat(raw)
            except ValueError as exc:
                raise InvalidRuleStateError(f"{name} is not an ISO timestamp") from exc
            if not _is_aware(value):
                raise InvalidRuleStateError(f"{name} must be timezone-aware")
            return value

        notification_times = cls._decode_pairs(
            data["level_notification_times"], decode_values_as_times=True
        )
        escalation_counts = cls._decode_pairs(
            data["level_escalation_counts"], decode_values_as_times=False
        )
        return cls(
            active_level=cast(int | None, data["active_level"]),
            episode=cast(int, data["episode"]),
            clear_count=cast(int, data["clear_count"]),
            newest_sample_time=decode_time("newest_sample_time"),
            newest_value=cast(float | None, data["newest_value"]),
            last_evaluated_sample_time=decode_time("last_evaluated_sample_time"),
            stale=cast(bool, data["stale"]),
            stale_cycle=cast(int, data["stale_cycle"]),
            reminder_count=cast(int, data["reminder_count"]),
            last_episode_notification_time=decode_time(
                "last_episode_notification_time"
            ),
            episode_started_at=decode_time("episode_started_at"),
            level_notification_times=cast(tuple[LevelTime, ...], notification_times),
            level_escalation_counts=cast(tuple[LevelCount, ...], escalation_counts),
            suppressed_escalations=cast(int, data["suppressed_escalations"]),
        )

    @staticmethod
    def _decode_pairs(
        raw: object, *, decode_values_as_times: bool
    ) -> tuple[tuple[str, datetime] | tuple[str, int], ...]:
        if not isinstance(raw, list) or len(raw) > MAX_LEVELS:
            raise InvalidRuleStateError("state history must be a bounded list")
        result: list[tuple[str, datetime] | tuple[str, int]] = []
        for item in raw:
            if not isinstance(item, list) or len(item) != 2 or not _valid_name(item[0]):
                raise InvalidRuleStateError("invalid state history entry")
            name = cast(str, item[0])
            value = item[1]
            if decode_values_as_times:
                if not isinstance(value, str) or len(value) > 64:
                    raise InvalidRuleStateError("invalid notification timestamp")
                try:
                    timestamp = datetime.fromisoformat(value)
                except ValueError as exc:
                    raise InvalidRuleStateError(
                        "invalid notification timestamp"
                    ) from exc
                if not _is_aware(timestamp):
                    raise InvalidRuleStateError("notification timestamp must be aware")
                result.append((name, timestamp))
            else:
                if not _valid_counter(value) or value == 0:
                    raise InvalidRuleStateError("invalid escalation count")
                result.append((name, cast(int, value)))
        return tuple(result)

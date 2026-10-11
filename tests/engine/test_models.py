"""Validation and serialization tests for engine domain types."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, tzinfo

import pytest

from vrm_alert_relay.engine import (
    Direction,
    InvalidRuleStateError,
    LevelSpec,
    RuleSpec,
    RuleState,
)

BASE = datetime(2030, 1, 1, tzinfo=UTC)


def valid_rule(**changes: object) -> RuleSpec:
    values: dict[str, object] = {
        "rule_id": "fictitious-rule",
        "direction": Direction.RISING,
        "levels": (LevelSpec("warning", 10.0), LevelSpec("critical", 20.0)),
    }
    values.update(changes)
    return RuleSpec(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"rule_id": ""}, "rule_id"),
        ({"direction": "rising"}, "direction"),
        ({"levels": ()}, "levels"),
        ({"levels": (LevelSpec("same", 1), LevelSpec("same", 2))}, "unique"),
        (
            {"levels": (LevelSpec("warning", 10), LevelSpec("critical", 10))},
            "ordered",
        ),
        ({"hysteresis": -1}, "hysteresis"),
        ({"hysteresis": float("nan")}, "hysteresis"),
        ({"clear_after_samples": 0}, "clear_after_samples"),
        ({"clear_after_samples": True}, "clear_after_samples"),
        ({"recovery_notify": 1}, "recovery_notify"),
        ({"cooldown": timedelta(seconds=-1)}, "cooldown"),
        ({"cooldown": "fifteen minutes"}, "timedelta"),
        ({"reminder_interval": timedelta(0)}, "reminder_interval"),
        ({"stale_after": timedelta(0)}, "stale_after"),
        ({"reminder_max": -1}, "reminder_max"),
        ({"reminder_max": True}, "reminder_max"),
    ],
)
def test_invalid_rule_specs_raise_value_error(changes: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        valid_rule(**changes)


def test_falling_thresholds_must_be_strictly_decreasing() -> None:
    valid_rule(
        direction=Direction.FALLING,
        levels=(LevelSpec("warning", 20), LevelSpec("critical", 10)),
    )
    with pytest.raises(ValueError, match="ordered"):
        valid_rule(
            direction=Direction.FALLING,
            levels=(LevelSpec("warning", 10), LevelSpec("critical", 20)),
        )


@pytest.mark.parametrize(
    ("name", "threshold"),
    [
        ("", 1.0),
        ("x" * 257, 1.0),
        ("warning", float("nan")),
        ("warning", float("inf")),
        ("warning", True),
        ("warning", 10**400),
    ],
)
def test_invalid_levels_raise_value_error(name: str, threshold: float) -> None:
    with pytest.raises(ValueError, match=r"^level (name|threshold) must be"):
        LevelSpec(name, threshold)


def populated_state() -> RuleState:
    return RuleState(
        generation=BASE.isoformat(),
        active_level="critical",
        episode=7,
        clear_count=2,
        newest_sample_time=BASE,
        newest_value=22.5,
        last_evaluated_sample_time=BASE,
        stale=True,
        stale_cycle=3,
        reminder_count=2,
        last_episode_notification_time=BASE + timedelta(minutes=1),
        episode_started_at=BASE - timedelta(minutes=2),
        episode_announced=True,
        episode_notified_levels=("warning", "critical"),
        pending_escalation="critical",
        escalation_ordinal=2,
        rule_direction=Direction.RISING,
        level_order=("warning", "critical"),
        level_notification_times=(
            ("critical", BASE + timedelta(minutes=1)),
            ("warning", BASE),
        ),
        suppressed_escalations=4,
    )


def test_state_round_trips_through_json_compatible_dict() -> None:
    state = populated_state()
    encoded = state.to_dict()
    assert RuleState.from_dict(encoded) == state
    assert RuleState.from_dict(RuleState().to_dict()) == RuleState()
    assert isinstance(encoded["level_notification_times"], list)


def test_schema_version_is_bumped_and_old_state_is_rejected() -> None:
    encoded = RuleState().to_dict()
    assert encoded["version"] == 3
    encoded["version"] = 2
    with pytest.raises(InvalidRuleStateError, match="version"):
        RuleState.from_dict(encoded)


def test_persisted_active_level_requires_positive_episode() -> None:
    encoded = populated_state().to_dict()
    encoded["episode"] = 0
    with pytest.raises(InvalidRuleStateError, match="positive episode"):
        RuleState.from_dict(encoded)


def test_persisted_active_level_must_exist_in_nonempty_level_order() -> None:
    encoded = populated_state().to_dict()
    encoded["level_order"] = ["warning"]
    with pytest.raises(InvalidRuleStateError, match="active_level must appear"):
        RuleState.from_dict(encoded)


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("version", 1),
        ("version", 1.0),
        ("version", True),
        ("generation", 1),
        ("generation", "not-a-time"),
        ("generation", "2030-01-01T00:00:00"),
        ("active_level", 1),
        ("active_level", ""),
        ("episode", -1),
        ("episode", True),
        ("clear_count", -1),
        ("newest_sample_time", "not-a-time"),
        ("newest_sample_time", "2030-01-01T00:00:00"),
        ("newest_value", float("nan")),
        ("newest_value", True),
        ("last_evaluated_sample_time", 4),
        ("stale", 1),
        ("stale_cycle", -1),
        ("reminder_count", -1),
        ("last_episode_notification_time", "bad"),
        ("episode_started_at", "bad"),
        ("episode_announced", 1),
        ("episode_notified_levels", "bad"),
        ("pending_escalation", 1),
        ("escalation_ordinal", -1),
        ("rule_direction", "sideways"),
        ("rule_direction", 1),
        ("level_order", "bad"),
        ("needs_rederive", 1),
        ("level_notification_times", "bad"),
        ("suppressed_escalations", -1),
    ],
)
def test_corrupt_scalar_state_is_rejected(field: str, bad_value: object) -> None:
    encoded = populated_state().to_dict()
    encoded[field] = bad_value
    with pytest.raises(InvalidRuleStateError):
        RuleState.from_dict(encoded)


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("level_notification_times", [["warning"]]),
        ("level_notification_times", [["", BASE.isoformat()]]),
        ("level_notification_times", [["warning", 1]]),
        ("level_notification_times", [["warning", "bad"]]),
        ("level_notification_times", [["warning", "2030-01-01T00:00:00"]]),
        ("episode_notified_levels", [""]),
        ("episode_notified_levels", ["warning", "warning"]),
    ],
)
def test_corrupt_history_state_is_rejected(field: str, bad_value: object) -> None:
    encoded = populated_state().to_dict()
    encoded[field] = bad_value
    with pytest.raises(InvalidRuleStateError):
        RuleState.from_dict(encoded)


def test_state_rejects_missing_extra_and_non_mapping_inputs() -> None:
    encoded = populated_state().to_dict()
    del encoded["episode"]
    with pytest.raises(InvalidRuleStateError, match="exactly"):
        RuleState.from_dict(encoded)
    encoded["episode"] = 7
    encoded["extra"] = 1
    with pytest.raises(InvalidRuleStateError, match="exactly"):
        RuleState.from_dict(encoded)
    with pytest.raises(InvalidRuleStateError, match="exactly"):
        RuleState.from_dict([])


@pytest.mark.parametrize(
    "kwargs",
    [
        {"active_level": ""},
        {"episode": -1},
        {"stale": 1},
        {"needs_rederive": 1},
        {"episode_announced": 1},
        {"rule_direction": "rising"},
        {"level_order": ("same", "same")},
        {"episode_notified_levels": ("same", "same")},
        {"pending_escalation": "warning"},
        {"pending_escalation": ""},
        {"generation": "bad"},
        {"active_level": "warning"},
        {"newest_sample_time": datetime(2030, 1, 1)},
        {"newest_value": float("inf")},
        {"clear_count": 1},
        {"reminder_count": 1},
        {"level_notification_times": (("warning", datetime(2030, 1, 1)),)},
    ],
)
def test_direct_state_construction_is_validated(kwargs: dict[str, object]) -> None:
    with pytest.raises(InvalidRuleStateError):
        RuleState(**kwargs)  # type: ignore[arg-type]


def test_state_history_is_bounded() -> None:
    encoded = RuleState().to_dict()
    encoded["episode_notified_levels"] = [f"level-{index}" for index in range(129)]
    with pytest.raises(InvalidRuleStateError, match="bounded"):
        RuleState.from_dict(encoded)


def test_direct_state_history_validation_covers_shape_duplicates_and_bounds() -> None:
    too_many_times = tuple((f"level-{index}", BASE) for index in range(129))
    invalid_states: list[dict[str, object]] = [
        {"level_notification_times": None},
        {"level_notification_times": too_many_times},
        {"episode_notified_levels": tuple(f"level-{index}" for index in range(129))},
        {"level_notification_times": (("warning",),)},
        {"level_notification_times": (("warning", BASE), ("warning", BASE))},
    ]
    for kwargs in invalid_states:
        with pytest.raises(InvalidRuleStateError):
            RuleState(**kwargs)  # type: ignore[arg-type]


def test_normal_state_cannot_claim_an_announced_episode() -> None:
    with pytest.raises(
        InvalidRuleStateError, match="normal state cannot have an announced episode"
    ):
        RuleState(episode=1, episode_announced=True)


def test_unexpected_validation_error_is_converted_to_state_error() -> None:
    class BrokenTimezone(tzinfo):
        def utcoffset(self, value: datetime | None) -> timedelta | None:  # noqa: ARG002  # tzinfo interface
            raise ValueError("fictitious broken timezone")  # noqa: TRY003  # deliberate failure for the test

    broken_time = datetime(2030, 1, 1, tzinfo=BrokenTimezone())
    with pytest.raises(InvalidRuleStateError, match="fictitious broken timezone"):
        RuleState(newest_sample_time=broken_time)

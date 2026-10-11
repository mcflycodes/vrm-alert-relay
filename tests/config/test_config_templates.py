"""Level message templates are checked against the restricted syntax at load."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from vrm_alert_relay.config import RelayConfig

Data = dict[str, Any]
Parse = Callable[[Any], RelayConfig]
Problems = Callable[[Any], tuple[str, ...]]

LOC = "rules[0].levels[1].message"


def test_placeholders_are_accepted(config_data: Data, parse: Parse) -> None:
    message = "{level}: {label} is {value}{unit} at {installation} ({time}) {{literal}}"
    config_data["rules"][0]["levels"][1]["message"] = message
    assert parse(config_data).rules[0].levels[1].message == message


@pytest.mark.parametrize(
    ("message", "problem"),
    [
        ("{phone}", "unknown placeholder"),
        ("{rule.__class__.__init__}", "bare field name"),
        ("{label!r}", "bare field name"),
        ("{value:>100000}", "bare field name"),
        ("{rule[0]}", "bare field name"),
        ("open {brace", "unmatched"),
        ("bidi \u202e override", "control or format characters"),
    ],
)
def test_unsupported_template_syntax_is_rejected_at_load(
    config_data: Data, problems: Problems, message: str, problem: str
) -> None:
    config_data["rules"][0]["levels"][1]["message"] = message
    (found,) = problems(config_data)
    assert found.startswith(f"{LOC}: ")
    assert problem in found
    assert "allowed placeholders are {rule}, {level}, {value}" in found
    assert message not in found

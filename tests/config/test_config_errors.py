"""Error rendering: YAML paths and masking."""

from __future__ import annotations

import pytest

from vrm_alert_relay.config import ConfigError
from vrm_alert_relay.config.errors import format_path, mask_digits


@pytest.mark.parametrize(
    ("loc", "expected"),
    [
        ((), "<root>"),
        (("rules", 2, "levels", 1, "threshold"), "rules[2].levels[1].threshold"),
        (("recipients", "owner_sms", "phone"), "recipients.owner_sms.phone"),
        (("recipients", "Bad Name", "[key]"), 'recipients["Bad Name"] (key)'),
        (("recipients", "line\nbreak"), 'recipients["line\\nbreak"]'),
        (("recipients", "+1 (202) 555-0142"), 'recipients["***0142"]'),
        (("k", "x" * 100), f'k["{"x" * 64}..."]'),
        (("k", ""), 'k[""]'),
    ],
)
def test_format_path(loc: tuple[str | int, ...], expected: str) -> None:
    assert format_path(loc) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("+12025550142", "***0142"),
        ("call 202-555-0142 now", "call ***0142 now"),
        ("(202) 555.0142", "(***0142"),
        ("site 1234 ok", "site 1234 ok"),
        ("1-63 characters", "1-63 characters"),
        ("ids 12345 and 678", "ids ***2345 and 678"),
    ],
)
def test_mask_digits(text: str, expected: str) -> None:
    assert mask_digits(text) == expected


def test_config_error_rendering() -> None:
    error = ConfigError(["a: first", "b: second"])
    assert error.problems == ("a: first", "b: second")
    assert str(error) == "invalid configuration:\n  - a: first\n  - b: second"


def test_config_error_always_has_a_problem() -> None:
    assert ConfigError([]).problems == ("invalid configuration",)

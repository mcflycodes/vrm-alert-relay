"""Rendering configuration paths without echoing untrusted mapping keys."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from vrm_alert_relay.config import config_warnings
from vrm_alert_relay.config._paths import (
    SourceMap,
    describe,
    display_name,
    is_displayable_key,
    render_path,
)

if TYPE_CHECKING:
    from collections.abc import Callable

Data = dict[str, Any]


@pytest.mark.parametrize(
    ("loc", "expected"),
    [
        ((), ("<root>", False)),
        (("rules", 0, "levels", 1, "name"), ("rules[0].levels[1].name", False)),
        (("rules", 2, "recipients", 1), ("rules[2].recipients[1]", False)),
        (
            ("vrm", "installations", 0, "site_id"),
            ("vrm.installations[0].site_id", False),
        ),
        (("providers", "voipms", "did"), ("providers.voipms.did", False)),
        (("recipients", "owner_sms", "phone"), ("recipients.owner_sms.phone", False)),
        (
            ("recipients", "owner_app", "service"),
            ("recipients.owner_app.service", False),
        ),
        (("recipients", "Bad Name", "[key]"), ("recipients[#?] (key)", True)),
        (("vrm", "unknown", "deeper"), ("vrm", True)),
        (("health", "port", "x"), ("health.port", True)),
        (("providers", "voipms", "did", "x"), ("providers.voipms.did", True)),
        (("health", "port", 0), ("health.port", True)),
        (("rules", "x"), ("rules", True)),
        (("recipients", 0), ("recipients", True)),
        (("recipients", "owner", "unknown"), ("recipients.owner", True)),
    ],
)
def test_render_path(loc: tuple[str | int, ...], expected: tuple[str, bool]) -> None:
    assert render_path(loc) == expected


def test_withheld_keys_use_their_source_position_and_line() -> None:
    loc = ("recipients", "2025550142", "phone")
    source = SourceMap(
        lines={("recipients",): 3, ("recipients", "2025550142"): 9},
        positions={("recipients", "2025550142"): 2},
    )
    assert render_path(loc, source) == ("recipients[#2].phone", True)
    assert describe(loc, "is required", source) == ("recipients[#2].phone: is required (line 9)")


def test_line_is_only_added_when_something_is_withheld() -> None:
    source = SourceMap(lines={("vrm",): 4, ("vrm", "poll_interval"): 6})
    assert describe(("vrm", "poll_interval"), "x", source) == "vrm.poll_interval: x"
    assert describe(("vrm", "poll_interval"), "x", source, line=7) == (
        "vrm.poll_interval: x (line 7)"
    )
    assert describe(("vrm", "bogus"), "x", source) == "vrm: x (line 4)"
    assert describe(("vrm", "bogus"), "x") == "vrm: x"


@pytest.mark.parametrize(
    ("key", "shown"),
    [
        ("owner_sms", True),
        ("a", True),
        ("0", True),
        ("site-1234", True),
        ("a" * 63, True),
        ("fake-secret-canary-7q9x", True),
        ("a1-b2-c3-d4", True),
        ("a" * 64, False),
        ("r12345", False),
        ("2025550142", False),
        ("r2025550142", False),
        ("202-555-0142", False),
        ("202_555_0142", False),
        ("1-202-555-0142", False),
        ("a1-b2-c3-d4-e5", False),
        ("owner-1-2-3-4-5", False),
        ("Owner", False),
        ("-owner", False),
        ("_owner", False),
        ("owner sms", False),
        ("owner.sms", False),
        ("", False),
    ],
)
def test_is_displayable_key(key: str, shown: bool) -> None:
    assert is_displayable_key(key) is shown


PHONE_SHAPED_NAMES = ["r2025550142", "202-555-0142", "202_555_0142", "1-202-555-0142"]


@pytest.mark.parametrize("name", PHONE_SHAPED_NAMES)
def test_display_name(name: str) -> None:
    assert display_name(name, 3) == "[#3]"
    assert display_name("owner_sms", 3) == "owner_sms"


@pytest.mark.parametrize("name", PHONE_SHAPED_NAMES)
def test_warnings_withhold_phone_shaped_recipient_names(
    config_data: Data, parse: Callable[[Any], Any], name: str
) -> None:
    config_data["recipients"][name] = {"provider": "log"}
    warnings = config_warnings(parse(config_data))
    assert "recipients[#4]: not used by any rule" in warnings
    assert all(name not in warning and "0142" not in warning for warning in warnings)


@pytest.mark.parametrize("name", PHONE_SHAPED_NAMES)
def test_errors_withhold_phone_shaped_recipient_names(
    config_data: Data, problems: Callable[[Any], tuple[str, ...]], name: str
) -> None:
    config_data["recipients"][name] = {"provider": "voipms"}
    (problem,) = problems(config_data)
    assert problem.startswith("recipients[#4].phone: is required (line ")
    assert name not in problem
    assert "0142" not in problem

"""The optional system_recipients list. Every value here is fictitious."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from vrm_alert_relay.config import (
    SYSTEM_RECIPIENTS_DEFAULT_NOTE,
    ConfigError,
    RelayConfig,
    check_config,
    config_warnings,
)

Data = dict[str, Any]
Parse = Callable[[Any], RelayConfig]
Write = Callable[[Any], Path]
SecretWriter = Callable[..., str]


def test_default_is_the_ordered_union_of_rule_recipients(config_data: Data, parse: Parse) -> None:
    config = parse(config_data)
    assert config.system_recipients is None
    assert config.system_recipient_names() == ("owner_sms", "audit", "owner_app", "hook")


def test_explicit_list_is_used_as_given(config_data: Data, parse: Parse) -> None:
    config_data["system_recipients"] = ["hook", "owner_sms"]
    config = parse(config_data)
    assert config.system_recipient_names() == ("hook", "owner_sms")


@pytest.mark.parametrize(
    ("names", "problem"),
    [
        (["nobody"], "system_recipients[0]: unknown recipient (not defined under recipients)"),
        (
            ["audit", "audit"],
            "system_recipients[1]: duplicate recipient (same as system_recipients[0])",
        ),
    ],
)
def test_names_are_checked_against_the_allowlist(
    config_data: Data, parse: Parse, names: list[str], problem: str
) -> None:
    config_data["system_recipients"] = names
    with pytest.raises(ConfigError) as caught:
        parse(config_data)
    assert caught.value.problems == (problem,)


@pytest.mark.parametrize("value", [["Not A Name"], "audit", [1]])
def test_malformed_lists_are_rejected(config_data: Data, parse: Parse, value: Any) -> None:
    config_data["system_recipients"] = value
    with pytest.raises(ConfigError):
        parse(config_data)


def test_empty_list_means_system_notifications_are_only_logged(
    config_data: Data, parse: Parse
) -> None:
    config_data["system_recipients"] = []
    config = parse(config_data)
    assert config.system_recipients == ()
    assert config.system_recipient_names() == ()
    warnings = config_warnings(config)
    assert (
        "system_recipients: empty; system problems (monitoring degraded or restored, "
        "rate-limit summaries, storage notices) will only be logged"
    ) in warnings
    assert not any(w.startswith("system_recipients: no system recipients") for w in warnings)


def test_check_report_for_an_empty_list(
    config_data: Data, write_config: Write, secret_file: SecretWriter
) -> None:
    secret_file("vrm_token")
    config_data["system_recipients"] = []
    report = check_config(write_config(config_data))
    assert report.ok is True
    assert report.system_recipients == ()
    assert report.system_recipients_defaulted is False
    assert SYSTEM_RECIPIENTS_DEFAULT_NOTE not in report.notes
    assert any("will only be logged" in w for w in report.warnings)


def test_recipient_used_only_as_system_recipient_is_not_unused(
    config_data: Data, parse: Parse
) -> None:
    config_data["recipients"]["pager"] = {"provider": "log"}
    config_data["system_recipients"] = ["pager"]
    warnings = config_warnings(parse(config_data))
    assert not any("pager" in w for w in warnings)


def test_no_system_recipients_is_a_warning(config_data: Data, parse: Parse) -> None:
    config_data["rules"] = []
    warnings = config_warnings(parse(config_data))
    assert any(w.startswith("system_recipients: no system recipients") for w in warnings)


def test_check_report_masks_explicit_system_recipients(
    config_data: Data, write_config: Write, secret_file: SecretWriter
) -> None:
    secret_file("vrm_token")
    config_data["recipients"]["r2025550199"] = {"provider": "log"}
    config_data["system_recipients"] = ["r2025550199", "audit"]
    report = check_config(write_config(config_data))
    assert report.ok is True
    assert report.system_recipients == ("[#4]", "audit")
    assert report.system_recipients_defaulted is False
    assert SYSTEM_RECIPIENTS_DEFAULT_NOTE not in report.notes
    assert "0199" not in repr(report)

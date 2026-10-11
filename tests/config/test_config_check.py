"""check_config reports and live versus dry-run resolution."""

from __future__ import annotations

import errno
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from vrm_alert_relay.config import (
    STRUCTURE_ONLY_NOTE,
    CheckReport,
    DeliveryMode,
    RelayConfig,
    check_config,
    config_warnings,
)

Data = dict[str, Any]
Parse = Callable[[Any], RelayConfig]
Write = Callable[[Any], Path]
SecretWriter = Callable[..., str]

RECIPIENT_OF = {"voipms": "owner_sms", "homeassistant": "owner_app", "webhook": "hook"}
FAKE_VRM_CREDENTIAL = "fake-vrm-token-value\n"


def _deny_reads_of(monkeypatch: pytest.MonkeyPatch, denied: str) -> None:
    real_open = os.open

    def guarded(path: Any, flags: int, *args: Any) -> int:
        if os.fspath(path) == denied:
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_open(path, flags, *args)

    monkeypatch.setattr("vrm_alert_relay.config._files.os.open", guarded)


def _write_all_secrets(secret_file: SecretWriter, mode: int = 0o600) -> None:
    for name in (
        "vrm_token",
        "voipms_username",
        "voipms_password",
        "ha_token",
        "webhook_token",
    ):
        secret_file(name, f"fake-{name}-value\n", mode)


@pytest.mark.parametrize("sending", [False, True])
@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("provider", ["voipms", "homeassistant", "webhook"])
def test_delivery_mode_matrix(
    config_data: Data, parse: Parse, provider: str, enabled: bool, sending: bool
) -> None:
    config_data["sending"]["enabled"] = sending
    config_data["providers"][provider]["enabled"] = enabled
    config = parse(config_data)
    live = sending and enabled
    assert config.provider_is_live(provider) is live  # type: ignore[arg-type]
    expected = DeliveryMode.LIVE if live else DeliveryMode.DRY_RUN
    assert config.delivery_mode(RECIPIENT_OF[provider]) is expected
    assert config.delivery_mode("audit") is DeliveryMode.DRY_RUN
    assert config.provider_is_live("log") is False
    assert config.live_providers() == ((provider,) if live else ())
    assert set(config.live_providers()) | set(config.dry_run_providers()) == {
        "voipms",
        "homeassistant",
        "webhook",
        "log",
    }
    others = set(RECIPIENT_OF.values()) - {RECIPIENT_OF[provider]}
    assert all(config.delivery_mode(name) is DeliveryMode.DRY_RUN for name in others)


def test_delivery_modes_cover_every_recipient(config_data: Data, parse: Parse) -> None:
    config_data["sending"]["enabled"] = True
    config_data["providers"]["voipms"]["enabled"] = True
    modes = parse(config_data).delivery_modes()
    assert dict(modes) == {
        "owner_sms": DeliveryMode.LIVE,
        "owner_app": DeliveryMode.DRY_RUN,
        "hook": DeliveryMode.DRY_RUN,
        "audit": DeliveryMode.DRY_RUN,
    }
    assert DeliveryMode.LIVE == "live"


def test_unknown_recipient_raises_key_error(config_data: Data, parse: Parse) -> None:
    with pytest.raises(KeyError):
        parse(config_data).delivery_mode("nobody")


def test_recipient_of_absent_provider_section_is_dry_run(config_data: Data, parse: Parse) -> None:
    config_data["sending"]["enabled"] = True
    del config_data["providers"]
    config = parse(config_data)
    assert config.delivery_mode("owner_sms") is DeliveryMode.DRY_RUN
    assert config.live_providers() == ()


def test_check_dry_run_passes_with_only_the_vrm_token(
    config_data: Data, write_config: Write, secret_file: SecretWriter
) -> None:
    secret_file("vrm_token")
    report = check_config(write_config(config_data))
    assert report.ok is True
    assert report.ready is True
    assert report.secrets_checked is True
    assert report.notes == ()
    assert report.problems == ()
    assert (report.installations, report.rules, report.recipients) == (2, 3, 4)
    assert report.live_providers == ()
    assert report.dry_run_providers == ("voipms", "homeassistant", "webhook", "log")
    assert report.live_recipients == ()
    assert report.dry_run_recipients == ("owner_sms", "owner_app", "hook", "audit")


@pytest.mark.parametrize(
    ("content", "mode", "reason"),
    [
        (None, 0o600, "secret file does not exist"),
        ("", 0o600, "secret file is empty"),
        (FAKE_VRM_CREDENTIAL, 0o400, "secret file is not readable (permission denied)"),
    ],
)
def test_check_missing_or_unreadable_vrm_token_is_a_problem(
    config_data: Data,
    write_config: Write,
    secret_file: SecretWriter,
    monkeypatch: pytest.MonkeyPatch,
    content: str | None,
    mode: int,
    reason: str,
) -> None:
    if content is not None:
        path = secret_file("vrm_token", content, mode)
        if "permission denied" in reason:
            _deny_reads_of(monkeypatch, path)
    report = check_config(write_config(config_data))
    assert report.ok is False
    assert report.ready is False
    assert report.problems == (f"vrm.token_file: {reason}",)


def test_structure_only_skips_secret_files(config_data: Data, write_config: Write) -> None:
    config_data["sending"]["enabled"] = True
    config_data["providers"]["voipms"]["enabled"] = True
    report = check_config(write_config(config_data), structure_only=True)
    assert report.ok is True
    assert report.ready is False
    assert report.secrets_checked is False
    assert report.notes == (STRUCTURE_ONLY_NOTE,)
    assert "not been verified as ready to deploy" in STRUCTURE_ONLY_NOTE
    assert report.problems == ()
    assert not any("secret file" in w for w in report.warnings)
    assert report.live_providers == ("voipms",)


def test_structure_only_still_reports_structural_problems(
    config_data: Data, write_config: Write
) -> None:
    config_data["rules"][0]["recipients"] = ["nobody"]
    report = check_config(write_config(config_data), structure_only=True)
    assert report.ok is False
    assert report.ready is False
    assert report.notes == (STRUCTURE_ONLY_NOTE,)
    assert report.problems == (
        "rules[0].recipients[0]: unknown recipient (not defined under recipients)",
    )


def test_structure_only_never_reads_secret_files(
    config_data: Data, write_config: Write, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_args: Any) -> Any:
        raise AssertionError("secret file read during a structure-only check")

    config_path = write_config(config_data)
    monkeypatch.setattr("vrm_alert_relay.config.loader.read_secret_file", forbidden)
    assert check_config(config_path, structure_only=True).ok is True
    with pytest.raises(AssertionError):
        check_config(config_path)


def test_check_enabled_but_not_live_provider_warns_about_secrets(
    config_data: Data, write_config: Write, secret_file: SecretWriter
) -> None:
    secret_file("vrm_token")
    secret_file("voipms_username", "")
    config_data["providers"]["voipms"]["enabled"] = True
    report = check_config(write_config(config_data))
    assert report.ok is True
    assert tuple(w for w in report.warnings if w.startswith("providers.")) == (
        "providers.voipms.username_file: secret file is empty (required before sending is enabled)",
        (
            "providers.voipms.password_file: secret file does not exist "
            "(required before sending is enabled)"
        ),
    )


def test_check_disabled_providers_secrets_are_not_read(
    config_data: Data, write_config: Write, secret_file: SecretWriter
) -> None:
    secret_file("vrm_token")
    secret_file("voipms_password", "")
    config_data["sending"]["enabled"] = True
    config_data["providers"]["webhook"]["enabled"] = True
    secret_file("webhook_token")
    report = check_config(write_config(config_data))
    assert report.ok is True
    assert not any(w.startswith("providers.voipms") for w in report.warnings)
    assert report.live_providers == ("webhook",)
    assert report.live_recipients == ("hook",)


def test_check_live_provider_requires_secret_files(
    config_data: Data, write_config: Write, secret_file: SecretWriter
) -> None:
    secret_file("vrm_token")
    secret_file("voipms_username")
    config_data["sending"]["enabled"] = True
    config_data["providers"]["voipms"]["enabled"] = True
    report = check_config(write_config(config_data))
    assert report.ok is False
    assert report.problems == ("providers.voipms.password_file: secret file does not exist",)
    assert report.live_providers == ("voipms",)
    assert report.live_recipients == ("owner_sms",)


def test_check_fully_live_configuration(
    config_data: Data, write_config: Write, secret_file: SecretWriter
) -> None:
    _write_all_secrets(secret_file)
    config_data["sending"]["enabled"] = True
    for provider in ("voipms", "homeassistant", "webhook"):
        config_data["providers"][provider]["enabled"] = True
    report = check_config(write_config(config_data))
    assert report == CheckReport(
        ok=True,
        ready=True,
        secrets_checked=True,
        installations=2,
        rules=3,
        recipients=4,
        live_providers=("voipms", "homeassistant", "webhook"),
        dry_run_providers=("log",),
        live_recipients=("owner_sms", "owner_app", "hook"),
        dry_run_recipients=("audit",),
    )


def test_check_broken_vrm_token_is_a_problem(
    config_data: Data, write_config: Write, secret_file: SecretWriter
) -> None:
    secret_file("vrm_token", "x" * 5000)
    report = check_config(write_config(config_data))
    assert report.ok is False
    assert report.problems == ("vrm.token_file: secret file is larger than 4096 bytes",)


def test_check_reports_permissive_secret_files(
    config_data: Data, write_config: Write, secret_file: SecretWriter
) -> None:
    secret_file("vrm_token", mode=0o644)
    report = check_config(write_config(config_data))
    assert report.ok is True
    assert (
        "vrm.token_file: secret file is readable by group or others; "
        "restrict it to mode 0600 or 0400"
    ) in report.warnings


def test_check_never_reports_secret_content(
    config_data: Data, write_config: Write, secret_file: SecretWriter
) -> None:
    secret_file("vrm_token", "fake-vrm-secret\x07bell\n")
    secret_file("ha_token", b"fake-ha-secret-\xff\n")
    config_data["sending"]["enabled"] = True
    config_data["providers"]["homeassistant"]["enabled"] = True
    report = check_config(write_config(config_data))
    assert report.ok is False
    text = repr(report)
    assert "fake-vrm-secret" not in text
    assert "fake-ha-secret" not in text
    assert len(report.problems) == 2


def test_check_invalid_configuration(config_data: Data, write_config: Write) -> None:
    config_data["rules"][0]["recipients"] = ["nobody"]
    report = check_config(write_config(config_data))
    assert report == CheckReport(
        ok=False,
        problems=("rules[0].recipients[0]: unknown recipient (not defined under recipients)",),
    )


def test_check_missing_file(tmp_path: Path) -> None:
    report = check_config(tmp_path / "absent.yaml")
    assert report.ok is False
    assert report.problems == ("configuration file: does not exist",)


@pytest.mark.parametrize("name", ["r2025550142", "202-555-0142", "202_555_0142", "1-202-555-0142"])
def test_check_report_lists_phone_shaped_names_by_position(
    config_data: Data, write_config: Write, secret_file: SecretWriter, name: str
) -> None:
    secret_file("vrm_token")
    secret_file("webhook_token")
    config_data["sending"]["enabled"] = True
    config_data["providers"]["webhook"]["enabled"] = True
    hook = config_data["recipients"].pop("hook")
    config_data["recipients"][name] = hook
    config_data["recipients"]["r2025550199"] = {"provider": "log"}
    config_data["rules"][1]["recipients"] = ["owner_app", name]
    config_data["rules"][2]["recipients"] = ["audit", "r2025550199"]
    report = check_config(write_config(config_data))
    assert report.ok is True
    assert report.live_recipients == ("[#3]",)
    assert report.dry_run_recipients == ("owner_sms", "owner_app", "audit", "[#4]")
    text = repr(report)
    assert name not in text
    assert "0142" not in text
    assert "0199" not in text


def test_check_masks_phone_numbers(config_data: Data, write_config: Write) -> None:
    config_data["recipients"]["owner_sms"]["phone"] = "+1 102 555 0142"
    report = check_config(write_config(config_data))
    assert report.ok is False
    assert "1025550142" not in repr(report)
    assert "102 555" not in repr(report)


def test_warnings_for_risky_or_unused_settings(config_data: Data, parse: Parse) -> None:
    config_data["sending"]["enabled"] = True
    config_data["recipients"]["spare"] = {"provider": "log"}
    config_data["health"] = {"enabled": True, "bind": "::"}
    logged_only = "is not enabled; messages to this recipient will be logged only"
    assert config_warnings(parse(config_data)) == [
        (
            "sending.enabled: sending is enabled but no provider is enabled; "
            "all messages will be logged only"
        ),
        f"recipients.owner_sms: provider 'voipms' {logged_only}",
        f"recipients.owner_app: provider 'homeassistant' {logged_only}",
        f"recipients.hook: provider 'webhook' {logged_only}",
        "recipients.spare: not used by any rule",
        "health.bind: the health endpoint listens on a non-loopback address",
    ]


def test_warning_when_no_rules(config_data: Data, parse: Parse) -> None:
    config_data["rules"] = []
    config_data["recipients"] = {}
    config_data["health"] = {"enabled": True, "bind": "::1"}
    assert config_warnings(parse(config_data)) == [
        "rules: no rules are configured; nothing will be monitored"
    ]

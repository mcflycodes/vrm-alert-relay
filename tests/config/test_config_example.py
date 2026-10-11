"""The published example configuration."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from vrm_alert_relay.config import (
    STRUCTURE_ONLY_NOTE,
    DeliveryMode,
    check_config,
    load_config,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_example_is_structurally_valid_in_dry_run(example_path: Path) -> None:
    report = check_config(example_path, structure_only=True)
    assert report.ok is True, report.problems
    assert report.ready is False
    assert report.notes == (STRUCTURE_ONLY_NOTE,)
    assert report.problems == ()
    assert (report.installations, report.rules, report.recipients) == (1, 2, 4)
    assert report.live_providers == ()
    assert report.live_recipients == ()


def test_example_is_ready_once_the_vrm_token_exists(example_path: Path, tmp_path: Path) -> None:
    token = tmp_path / "vrm_token"
    token.write_text("fake-vrm-token-value\n")
    token.chmod(0o600)
    text = example_path.read_text(encoding="utf-8")
    assert "token_file: /run/secrets/vrm_token\n" in text
    copy = tmp_path / "config.yaml"
    copy.write_text(text.replace("/run/secrets/vrm_token", str(token)), encoding="utf-8")
    report = check_config(copy)
    assert report.ok is True, report.problems
    assert report.ready is True
    assert report.secrets_checked is True


def test_example_declares_version_and_recommends_hysteresis(example_path: Path) -> None:
    config = load_config(example_path)
    assert config.version == 1
    assert all(rule.hysteresis > 0 for rule in config.rules)
    assert "Recommended: set a non-zero hysteresis" in example_path.read_text("utf-8")


def test_example_has_sending_and_providers_disabled(example_path: Path) -> None:
    config = load_config(example_path)
    assert config.sending.enabled is False
    assert not config.providers.voipms.enabled
    assert not config.providers.homeassistant.enabled
    assert not config.providers.webhook.enabled
    assert config.health.enabled is False
    assert set(config.delivery_modes().values()) == {DeliveryMode.DRY_RUN}


def test_example_uses_every_recipient_type(example_path: Path) -> None:
    config = load_config(example_path)
    providers = {recipient.provider for recipient in config.recipients.values()}
    assert providers == {"voipms", "homeassistant", "webhook", "log"}


def test_example_contains_only_fictitious_values(example_path: Path) -> None:
    config = load_config(example_path)
    assert [inst.site_id for inst in config.vrm.installations] == [123456]
    numbers = [config.providers.voipms.did] + [
        getattr(r, "phone", None) for r in config.recipients.values()
    ]
    for number in filter(None, numbers):
        assert re.fullmatch(r"[2-9][0-9]{2}55501[0-9]{2}", number.national)

    text = example_path.read_text(encoding="utf-8")
    allowed_hosts = {
        "vrmapi.victronenergy.com",
        "voip.ms",
        "homeassistant.example.invalid",
        "hooks.example.com",
    }
    hosts = {urlsplit(url).hostname for url in re.findall(r"https://[^\s\"']+", text)}
    assert hosts == allowed_hosts
    assert not re.search(r"\b(?:10|172|192)\.\d+\.\d+\.\d+\b", text)
    assert all(path.startswith("/run/secrets/") for path in re.findall(r"_file: (\S+)", text))

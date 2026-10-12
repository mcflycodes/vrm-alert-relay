"""Per-provider TLS trust (ca_file) and the plain-http opt-in (owner decision Q12)."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
import trustme

from vrm_alert_relay.config import RelayConfig, check_config, config_warnings

Data = dict[str, Any]
Parse = Callable[[Any], RelayConfig]
Problems = Callable[[Any], tuple[str, ...]]
Write = Callable[[Any], Path]
SecretWriter = Callable[..., str]

URL_KEY = {"homeassistant": "base_url", "webhook": "url"}
INSECURE = "allow_insecure_http: INSECURE: plain http:// is permitted"


@pytest.fixture
def ca_pem(tmp_path: Path) -> str:
    path = tmp_path / "private-ca.pem"
    trustme.CA().cert_pem.write_to_path(str(path))
    return str(path)


@pytest.mark.parametrize("provider", ["homeassistant", "webhook"])
def test_plain_http_is_refused_without_opt_in(
    config_data: Data, problems: Problems, provider: str
) -> None:
    config_data["providers"][provider][URL_KEY[provider]] = "http://ha.example.test:8123"
    found = problems(config_data)
    assert found == (
        (
            f"providers.{provider}.{URL_KEY[provider]}: must be an https:// URL "
            "(set allow_insecure_http: true for this provider to permit http://)"
        ),
    )


@pytest.mark.parametrize("provider", ["homeassistant", "webhook"])
def test_invalid_opt_in_value_keeps_http_refused(
    config_data: Data, problems: Problems, provider: str
) -> None:
    config_data["providers"][provider]["allow_insecure_http"] = "yes"
    config_data["providers"][provider][URL_KEY[provider]] = "http://ha.example.test"
    found = problems(config_data)
    assert len(found) == 2
    assert any("allow_insecure_http: must be true or false" in p for p in found)
    assert any("must be an https:// URL" in p for p in found)


@pytest.mark.parametrize("provider", ["homeassistant", "webhook"])
def test_plain_http_with_opt_in_is_accepted_with_a_warning(
    config_data: Data, parse: Parse, provider: str
) -> None:
    config_data["providers"][provider]["allow_insecure_http"] = True
    config_data["providers"][provider][URL_KEY[provider]] = "http://192.168.0.10:8123/x"
    config = parse(config_data)
    section = getattr(config.providers, provider)
    assert section.allow_insecure_http is True
    warnings = config_warnings(config)
    assert sum(INSECURE in w for w in warnings) == 1
    assert any(w.startswith(f"providers.{provider}.allow_insecure_http:") for w in warnings)


def test_opt_in_with_https_url_still_warns(config_data: Data, parse: Parse) -> None:
    config_data["providers"]["webhook"]["allow_insecure_http"] = True
    warnings = config_warnings(parse(config_data))
    assert any("providers.webhook.allow_insecure_http: INSECURE" in w for w in warnings)


def test_no_transport_warning_by_default(config_data: Data, parse: Parse) -> None:
    warnings = config_warnings(parse(config_data))
    assert not any("allow_insecure_http" in w or "ca_file" in w for w in warnings)


@pytest.mark.parametrize("section", ["vrm", "voipms"])
def test_vrm_and_voipms_have_no_transport_overrides(
    config_data: Data, problems: Problems, section: str
) -> None:
    target = config_data["vrm"] if section == "vrm" else config_data["providers"]["voipms"]
    target["allow_insecure_http"] = True
    target["ca_file"] = "/etc/ssl/private-ca.pem"
    found = problems(config_data)
    assert len(found) == 2
    assert all("unrecognized setting" in p for p in found)


@pytest.mark.parametrize("section", ["vrm", "voipms"])
def test_vrm_and_voipms_stay_https_only(
    config_data: Data, problems: Problems, section: str
) -> None:
    target = config_data["vrm"] if section == "vrm" else config_data["providers"]["voipms"]
    target["base_url"] = "http://vrm.example.test/v2"
    (problem,) = problems(config_data)
    assert problem.endswith("base_url: must be an https:// URL")


def test_other_schemes_are_refused_even_with_opt_in(config_data: Data, problems: Problems) -> None:
    config_data["providers"]["webhook"]["allow_insecure_http"] = True
    config_data["providers"]["webhook"]["url"] = "ftp://hooks.example.test/"
    (problem,) = problems(config_data)
    assert problem.startswith("providers.webhook.url: must be an https:// URL")


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("relative/ca.pem", "must be an absolute path to a PEM CA certificate file"),
        ("", "must not be empty"),
        ("/etc/ca\n.pem", "must not contain line breaks or control characters"),
        ("/" + "a" * 5000, "must be at most 4096 characters"),
    ],
)
def test_ca_file_must_be_an_absolute_path(
    config_data: Data, problems: Problems, value: str, reason: str
) -> None:
    config_data["providers"]["homeassistant"]["ca_file"] = value
    (problem,) = problems(config_data)
    assert problem == f"providers.homeassistant.ca_file: {reason}"


@pytest.mark.parametrize("provider", ["homeassistant", "webhook"])
def test_ca_file_is_accepted(config_data: Data, parse: Parse, provider: str) -> None:
    config_data["providers"][provider]["ca_file"] = "/etc/vrm-alert-relay/ca.pem"
    assert getattr(parse(config_data).providers, provider).ca_file == "/etc/vrm-alert-relay/ca.pem"


def test_ca_file_with_plain_http_is_flagged(config_data: Data, parse: Parse) -> None:
    ha = config_data["providers"]["homeassistant"]
    ha.update(allow_insecure_http=True, base_url="http://ha.example.test", ca_file="/etc/ca.pem")
    warnings = config_warnings(parse(config_data))
    assert "providers.homeassistant.ca_file: has no effect because the URL uses plain http://" in (
        warnings
    )


def _live(config_data: Data, secret_file: SecretWriter, provider: str, *, sending: bool) -> None:
    secret_file("vrm_token")
    secret_file("ha_token")
    secret_file("webhook_token")
    config_data["sending"]["enabled"] = sending
    config_data["providers"][provider]["enabled"] = True


@pytest.mark.parametrize("provider", ["homeassistant", "webhook"])
def test_check_config_loads_a_valid_ca_file(
    config_data: Data, write_config: Write, secret_file: SecretWriter, ca_pem: str, provider: str
) -> None:
    _live(config_data, secret_file, provider, sending=True)
    config_data["providers"][provider]["ca_file"] = ca_pem
    report = check_config(write_config(config_data))
    assert report.ok is True
    assert not any("ca_file" in w for w in report.warnings)


@pytest.mark.parametrize("provider", ["homeassistant", "webhook"])
def test_check_config_reports_an_unusable_ca_file_for_a_live_provider(
    config_data: Data, write_config: Write, secret_file: SecretWriter, tmp_path: Path, provider: str
) -> None:
    _live(config_data, secret_file, provider, sending=True)
    bad = tmp_path / "not-a-ca.pem"
    bad.write_text("fictitious, not a certificate\n")
    config_data["providers"][provider]["ca_file"] = str(bad)
    report = check_config(write_config(config_data))
    assert report.ok is False
    assert report.problems == (
        f"providers.{provider}.ca_file: CA file could not be loaded as PEM certificates",
    )


def test_check_config_warns_about_an_unusable_ca_file_before_sending(
    config_data: Data, write_config: Write, secret_file: SecretWriter, tmp_path: Path
) -> None:
    _live(config_data, secret_file, "webhook", sending=False)
    config_data["providers"]["webhook"]["ca_file"] = str(tmp_path / "missing.pem")
    report = check_config(write_config(config_data))
    assert report.ok is True
    assert (
        "providers.webhook.ca_file: CA file could not be loaded as PEM certificates "
        "(required before sending is enabled)"
    ) in report.warnings


def test_check_config_ignores_ca_file_of_disabled_provider_and_structure_only(
    config_data: Data, write_config: Write, secret_file: SecretWriter, tmp_path: Path
) -> None:
    secret_file("vrm_token")
    config_data["providers"]["webhook"]["ca_file"] = str(tmp_path / "missing.pem")
    assert check_config(write_config(config_data)).ok is True
    config_data["providers"]["webhook"]["enabled"] = True
    config_data["sending"]["enabled"] = True
    report = check_config(write_config(config_data), structure_only=True)
    assert report.ok is True
    assert not any("ca_file" in p for p in report.problems + report.warnings)


def test_check_config_shows_the_insecure_warning(
    config_data: Data, write_config: Write, secret_file: SecretWriter
) -> None:
    _live(config_data, secret_file, "homeassistant", sending=True)
    ha = config_data["providers"]["homeassistant"]
    ha.update(allow_insecure_http=True, base_url="http://ha.example.test:8123")
    report = check_config(write_config(config_data))
    assert report.ok is True
    assert any(
        "providers.homeassistant.allow_insecure_http: INSECURE" in w for w in report.warnings
    )

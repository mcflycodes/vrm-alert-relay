"""Shared fixtures for configuration tests. Every value here is fictitious."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
import yaml

from vrm_alert_relay.config import ConfigError, RelayConfig, parse_config

if TYPE_CHECKING:
    from collections.abc import Callable

EXAMPLE_CONFIG = Path(__file__).resolve().parents[2] / "examples" / "config.example.yaml"
FAKE_CREDENTIAL = "fake-secret-for-tests-only"


class _NoAliasDumper(yaml.SafeDumper):
    def ignore_aliases(self, data: Any) -> bool:
        return True


def dump(data: Any) -> str:
    return yaml.dump(data, Dumper=_NoAliasDumper, sort_keys=False, allow_unicode=True)


@pytest.fixture
def example_path() -> Path:
    return EXAMPLE_CONFIG


@pytest.fixture
def fake_secret() -> str:
    return FAKE_CREDENTIAL


@pytest.fixture
def to_yaml() -> Callable[[Any], str]:
    return dump


@pytest.fixture
def secrets_dir(tmp_path: Path) -> Path:
    path = tmp_path / "secrets"
    path.mkdir()
    return path


@pytest.fixture
def config_data(secrets_dir: Path) -> dict[str, Any]:
    """A complete dry-run configuration using every provider and recipient type."""
    return {
        "version": 1,
        "sending": {"enabled": False},
        "vrm": {
            "token_file": str(secrets_dir / "vrm_token"),
            "installations": [
                {"id": "cabin", "site_id": 123456},
                {"id": "shed", "site_id": 123457},
            ],
        },
        "recipients": {
            "owner_sms": {"provider": "voipms", "phone": "+1 202 555 0142"},
            "owner_app": {"provider": "homeassistant", "service": "mobile_app_test"},
            "hook": {"provider": "webhook"},
            "audit": {"provider": "log"},
        },
        "providers": {
            "voipms": {
                "enabled": False,
                "username_file": str(secrets_dir / "voipms_username"),
                "password_file": str(secrets_dir / "voipms_password"),
                "did": "2025550100",
            },
            "homeassistant": {
                "enabled": False,
                "base_url": "https://homeassistant.example.invalid:8123",
                "token_file": str(secrets_dir / "ha_token"),
            },
            "webhook": {
                "enabled": False,
                "url": "https://hooks.example.com/relay",
                "auth_header_name": "X-Relay-Token",
                "auth_header_value_file": str(secrets_dir / "webhook_token"),
            },
            "log": {},
        },
        "rules": [
            {
                "id": "freezer",
                "installation": "cabin",
                "measurement": {"code": "tsT", "instance": 20},
                "direction": "rising",
                "levels": [
                    {"name": "warning", "threshold": -12},
                    {"name": "critical", "threshold": -4.5, "message": "Too warm"},
                ],
                "recipients": ["owner_sms", "audit"],
            },
            {
                "id": "battery",
                "installation": "shed",
                "measurement": {
                    "code": "bs",
                    "instance": 512,
                    "service_type": "battery",
                },
                "direction": "falling",
                "levels": [
                    {"name": "warning", "threshold": 40},
                    {"name": "critical", "threshold": 20},
                ],
                "recipients": ["owner_app", "hook"],
            },
            {
                "id": "voltage",
                "installation": "shed",
                "measurement": {"code": "bv", "instance": 512},
                "direction": "falling",
                "levels": [
                    {"name": "warning", "threshold": 12.2},
                    {"name": "alert", "threshold": 12.0},
                    {"name": "critical", "threshold": 11.8},
                ],
                "recipients": ["audit"],
            },
        ],
        "health": {"enabled": False},
    }


@pytest.fixture
def parse() -> Callable[[Any], RelayConfig]:
    def _parse(data: Any) -> RelayConfig:
        return parse_config(dump(data))

    return _parse


@pytest.fixture
def problems() -> Callable[[Any], tuple[str, ...]]:
    """Parse data that must be rejected and return the reported problems."""

    def _problems(data: Any) -> tuple[str, ...]:
        text = data if isinstance(data, str | bytes) else dump(data)
        with pytest.raises(ConfigError) as caught:
            parse_config(text)
        return caught.value.problems

    return _problems


@pytest.fixture
def write_config(tmp_path: Path) -> Callable[[Any], Path]:
    def _write(data: Any) -> Path:
        path = tmp_path / "config.yaml"
        if isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(data if isinstance(data, str) else dump(data), encoding="utf-8")
        return path

    return _write


@pytest.fixture
def secret_file(secrets_dir: Path) -> Callable[..., str]:
    """Write an obviously fake secret file and return its path."""

    def _write(name: str, content: str | bytes = FAKE_CREDENTIAL + "\n", mode: int = 0o600) -> str:
        path = secrets_dir / name
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        path.chmod(mode)
        return str(path)

    return _write

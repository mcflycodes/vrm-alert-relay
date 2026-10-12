"""Building providers from configuration: only live providers, dry-run otherwise (R24)."""

from __future__ import annotations

from typing import Any

import pytest
import trustme
import yaml
from provider_helpers import HA_TOKEN, VOIPMS_PASSWORD, VOIPMS_USER, WEBHOOK_SECRET, secret

from vrm_alert_relay.config import DeliveryMode, RelayConfig, RelaySecrets, parse_config
from vrm_alert_relay.logs.redaction import SecretRegistry
from vrm_alert_relay.net import InvalidCaFileError, SafeHttpClient, Timeouts
from vrm_alert_relay.providers import (
    DryRunLogProvider,
    HomeAssistantNotifyProvider,
    ProviderSet,
    ProviderSetupError,
    VoipmsSmsProvider,
    WebhookPostProvider,
    build_providers,
)

ALL = ("voipms", "homeassistant", "webhook")


def config_data(*, sending: bool, enabled: tuple[str, ...] = ALL) -> dict[str, Any]:
    return {
        "version": 1,
        "sending": {"enabled": sending},
        "vrm": {
            "token_file": "/run/secrets/vrm_token",
            "installations": [{"id": "cabin", "site_id": 123456}],
        },
        "recipients": {
            "sms": {"provider": "voipms", "phone": "+1 202 555 0142"},
            "app": {"provider": "homeassistant", "service": "mobile_app_example"},
            "hook": {"provider": "webhook"},
            "audit": {"provider": "log"},
        },
        "providers": {
            "voipms": {
                "enabled": "voipms" in enabled,
                "username_file": "/run/secrets/voipms_username",
                "password_file": "/run/secrets/voipms_password",
                "did": "2025550100",
            },
            "homeassistant": {
                "enabled": "homeassistant" in enabled,
                "base_url": "https://ha.example.test:8123",
                "token_file": "/run/secrets/ha_token",
            },
            "webhook": {
                "enabled": "webhook" in enabled,
                "url": "https://hooks.example.test/relay",
                "auth_header_name": "X-Relay-Token",
                "auth_header_value_file": "/run/secrets/webhook_token",
            },
        },
        "rules": [
            {
                "id": "freezer",
                "installation": "cabin",
                "measurement": {"code": "tsT", "instance": 20},
                "direction": "rising",
                "levels": [{"name": "warning", "threshold": -12}],
                "recipients": ["sms", "app", "hook", "audit"],
            }
        ],
    }


def parse(data: dict[str, Any]) -> RelayConfig:
    return parse_config(yaml.safe_dump(data))


def all_secrets() -> RelaySecrets:
    return RelaySecrets(
        vrm_token=secret("fake-vrm-token-0000"),
        voipms_username=secret(VOIPMS_USER),
        voipms_password=secret(VOIPMS_PASSWORD),
        homeassistant_token=secret(HA_TOKEN),
        webhook_auth_header_value=secret(WEBHOOK_SECRET),
    )


def test_sending_disabled_builds_only_the_dry_run_sink() -> None:
    config = parse(config_data(sending=False))
    with build_providers(config, RelaySecrets(), registry=SecretRegistry()) as built:
        assert dict(built.providers) == {}
        assert isinstance(built.dry_run, DryRunLogProvider)
        assert built.clients == ()
    assert all(mode is DeliveryMode.DRY_RUN for mode in config.delivery_modes().values())


def test_enabled_but_not_sending_needs_no_secrets() -> None:
    built = build_providers(parse(config_data(sending=False)), RelaySecrets())
    assert dict(built.providers) == {}


def test_live_providers_are_built() -> None:
    config = parse(config_data(sending=True))
    registry = SecretRegistry()
    with build_providers(config, all_secrets(), registry=registry, timeouts=Timeouts()) as built:
        assert set(built.providers) == set(ALL)
        assert isinstance(built.providers["voipms"], VoipmsSmsProvider)
        assert isinstance(built.providers["homeassistant"], HomeAssistantNotifyProvider)
        assert isinstance(built.providers["webhook"], WebhookPostProvider)
        assert len(built.clients) == 3
        assert not any(client.allow_insecure_http for client in built.clients)
        live = {
            config.recipients[name].provider
            for name, mode in config.delivery_modes().items()
            if mode is DeliveryMode.LIVE
        }
        assert live <= set(built.providers)
        with pytest.raises(TypeError):
            built.providers["log"] = built.dry_run  # type: ignore[index]
    for value in (VOIPMS_USER, VOIPMS_PASSWORD, HA_TOKEN, WEBHOOK_SECRET):
        assert value in registry.secrets
    assert "fake" not in repr(built)


@pytest.mark.parametrize("only", ALL)
def test_only_enabled_providers_are_built(only: str) -> None:
    built = build_providers(parse(config_data(sending=True, enabled=(only,))), all_secrets())
    assert list(built.providers) == [only]
    built.close()


def test_webhook_without_auth_header() -> None:
    data = config_data(sending=True, enabled=("webhook",))
    del data["providers"]["webhook"]["auth_header_name"]
    del data["providers"]["webhook"]["auth_header_value_file"]
    built = build_providers(parse(data), RelaySecrets())
    assert isinstance(built.providers["webhook"], WebhookPostProvider)
    built.close()


@pytest.mark.parametrize(
    ("provider", "missing", "setting"),
    [
        ("voipms", "voipms_username", "providers.voipms.username_file"),
        ("voipms", "voipms_password", "providers.voipms.password_file"),
        ("homeassistant", "homeassistant_token", "providers.homeassistant.token_file"),
        ("webhook", "webhook_auth_header_value", "providers.webhook.auth_header_value_file"),
    ],
)
def test_missing_secret_is_a_setup_error(provider: str, missing: str, setting: str) -> None:
    values = {
        "voipms_username": secret(VOIPMS_USER),
        "voipms_password": secret(VOIPMS_PASSWORD),
        "homeassistant_token": secret(HA_TOKEN),
        "webhook_auth_header_value": secret(WEBHOOK_SECRET),
    }
    del values[missing]
    with pytest.raises(ProviderSetupError) as caught:
        build_providers(
            parse(config_data(sending=True, enabled=(provider,))), RelaySecrets(**values)
        )
    assert str(caught.value).startswith(f"{setting}: ")
    assert "fake" not in str(caught.value)


@pytest.mark.parametrize(
    ("provider", "field", "setting"),
    [
        ("voipms", "did", "providers.voipms.did"),
        ("homeassistant", "base_url", "providers.homeassistant.base_url"),
        ("webhook", "url", "providers.webhook.url"),
    ],
)
def test_unvalidated_config_without_destination_is_refused(
    provider: str, field: str, setting: str
) -> None:
    config = parse(config_data(sending=True, enabled=(provider,)))
    section = getattr(config.providers, provider).model_copy(update={field: None})
    providers = config.providers.model_copy(update={provider: section})
    broken = config.model_copy(update={"providers": providers})
    with pytest.raises(ProviderSetupError, match=setting):
        build_providers(broken, all_secrets())


def test_ca_file_and_insecure_settings_reach_the_clients(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    pem = tmp_path / "ca.pem"
    trustme.CA().cert_pem.write_to_path(str(pem))
    data = config_data(sending=True, enabled=("homeassistant", "webhook"))
    data["providers"]["homeassistant"]["ca_file"] = str(pem)
    data["providers"]["webhook"].update(
        allow_insecure_http=True, url="http://hooks.example.test/relay"
    )
    seen: list[dict[str, Any]] = []
    original = SafeHttpClient.__init__

    def spy(self: SafeHttpClient, **kwargs: Any) -> None:
        seen.append(kwargs)
        original(self, **kwargs)

    monkeypatch.setattr(SafeHttpClient, "__init__", spy)
    with build_providers(parse(data), all_secrets()) as built:
        assert [c.allow_insecure_http for c in built.clients] == [False, True]
    assert seen[0]["ca_file"] == str(pem)
    assert seen[0]["allow_insecure_http"] is False
    assert seen[1]["ca_file"] is None
    assert seen[1]["allow_insecure_http"] is True


def test_failure_closes_clients_already_built(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = config_data(sending=True)
    data["providers"]["webhook"]["ca_file"] = str(tmp_path / "missing.pem")
    closed: list[SafeHttpClient] = []
    original = SafeHttpClient.close

    def spy(self: SafeHttpClient) -> None:
        closed.append(self)
        original(self)

    monkeypatch.setattr(SafeHttpClient, "close", spy)
    with pytest.raises(InvalidCaFileError):
        build_providers(parse(data), all_secrets())
    assert len(closed) == 2


def test_provider_set_close_closes_every_client(monkeypatch: pytest.MonkeyPatch) -> None:
    built = build_providers(parse(config_data(sending=True)), all_secrets())
    assert isinstance(built, ProviderSet)
    closed: list[SafeHttpClient] = []
    original = SafeHttpClient.close

    def spy(self: SafeHttpClient) -> None:
        closed.append(self)
        original(self)

    monkeypatch.setattr(SafeHttpClient, "close", spy)
    built.close()
    assert closed == list(built.clients)

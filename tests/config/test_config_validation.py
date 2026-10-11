"""Schema and semantic validation of the configuration."""

from __future__ import annotations

import copy
import re
from collections.abc import Callable
from types import MappingProxyType
from typing import Any

import pydantic
import pytest

from vrm_alert_relay.config import (
    ConfigError,
    HomeAssistantRecipient,
    PhoneNumber,
    RelayConfig,
    VoipmsRecipient,
)

Data = dict[str, Any]
Parse = Callable[[Any], RelayConfig]
Problems = Callable[[Any], tuple[str, ...]]

FULL_NUMBER_DIGITS = "2025550142"


def test_valid_configuration_loads(config_data: Data, parse: Parse) -> None:
    config = parse(config_data)
    assert [inst.id for inst in config.vrm.installations] == ["cabin", "shed"]
    assert [rule.id for rule in config.rules] == ["freezer", "battery", "voltage"]
    sms = config.recipients["owner_sms"]
    assert isinstance(sms, VoipmsRecipient)
    assert sms.phone.e164 == "+12025550142"
    assert sms.phone.national == FULL_NUMBER_DIGITS
    app = config.recipients["owner_app"]
    assert isinstance(app, HomeAssistantRecipient)
    assert app.service == "mobile_app_test"
    assert config.providers.voipms.did == PhoneNumber("2025550100")
    assert config.rules[0].levels[0].threshold == -12.0
    assert config.rules[0].levels[1].message == "Too warm"
    assert config.rules[1].measurement.service_type == "battery"


def test_defaults_match_requirements(secrets_dir: Any, parse: Parse) -> None:
    config = parse(
        {
            "version": 1,
            "vrm": {
                "token_file": str(secrets_dir / "vrm_token"),
                "installations": [{"id": "cabin", "site_id": 123456}],
            },
            "recipients": {"audit": {"provider": "log"}},
            "rules": [
                {
                    "id": "r",
                    "installation": "cabin",
                    "measurement": {"code": "bv", "instance": 0},
                    "direction": "rising",
                    "levels": [{"name": "warning", "threshold": 1}],
                    "recipients": ["audit"],
                }
            ],
        }
    )
    assert config.sending.enabled is False
    assert config.vrm.base_url == "https://vrmapi.victronenergy.com/v2"
    assert config.vrm.poll_interval == 60
    limits = config.rate_limits
    assert (limits.global_per_hour, limits.global_per_day, limits.retries) == (
        20,
        60,
        3,
    )
    providers = config.providers
    assert providers.voipms.enabled is False
    assert providers.voipms.base_url == "https://voip.ms/api/v1/rest.php"
    assert providers.homeassistant.enabled is False
    assert providers.webhook.enabled is False
    rule = config.rules[0]
    assert rule.cooldown_minutes == 15
    assert rule.reminder_interval_minutes == 60
    assert rule.reminder_max == 3
    assert rule.stale_after_minutes == 35
    assert rule.hysteresis == 0.0
    assert rule.clear_after_samples == 1
    assert rule.recovery_notify is True
    assert rule.measurement.service_type is None
    assert rule.levels[0].message is None
    health = config.health
    assert (health.enabled, health.bind, health.port) == (False, "127.0.0.1", 8080)


def test_configuration_is_immutable(config_data: Data, parse: Parse) -> None:
    config = parse(config_data)
    with pytest.raises(pydantic.ValidationError):
        config.sending.enabled = True  # type: ignore[misc]
    with pytest.raises(pydantic.ValidationError):
        config.rules[0].cooldown_minutes = 1  # type: ignore[misc]
    assert isinstance(config.rules, tuple)
    assert isinstance(config.rules[0].levels, tuple)
    assert isinstance(config.rules[0].recipients, tuple)
    assert isinstance(config.vrm.installations, tuple)
    assert isinstance(config.recipients, MappingProxyType)
    with pytest.raises(TypeError):
        config.recipients["new"] = config.recipients["audit"]  # type: ignore[index]


def test_model_dump_round_trips_structure(config_data: Data, parse: Parse) -> None:
    dumped = parse(config_data).model_dump(mode="json")
    assert dumped["recipients"]["owner_sms"] == {
        "provider": "voipms",
        "phone": "***-***-0142",
    }
    assert dumped["providers"]["voipms"]["did"] == "***-***-0100"
    assert dumped["rules"][0]["levels"][0]["threshold"] == -12.0


def line_of(text: str, needle: str) -> int:
    return next(n for n, line in enumerate(text.splitlines(), 1) if needle in line)


@pytest.mark.parametrize(
    ("mutate", "parent", "key"),
    [
        (lambda d: d.update(extra=1), "<root>", "extra"),
        (lambda d: d["vrm"].update(tokenpath="/x"), "vrm", "tokenpath"),
        (
            lambda d: d["rules"][2]["levels"][1].update(colour="red"),
            "rules[2].levels[1]",
            "colour",
        ),
        (
            lambda d: d["recipients"]["owner_sms"].update(email="x"),
            "recipients.owner_sms",
            "email",
        ),
        (lambda d: d["providers"].update(twilio={}), "providers", "twilio"),
        (
            lambda d: d["providers"].update(log={"level": "info"}),
            "providers.log",
            "level",
        ),
    ],
)
def test_unknown_keys_are_reported_by_parent_and_line(
    config_data: Data,
    problems: Problems,
    to_yaml: Callable[[Any], str],
    mutate: Callable[[Data], None],
    parent: str,
    key: str,
) -> None:
    mutate(config_data)
    text = to_yaml(config_data)
    line = line_of(text, f"{key}:")
    assert problems(text) == (f"{parent}: unrecognized setting (line {line})",)


@pytest.mark.parametrize(
    ("mutate", "path"),
    [
        (lambda d: d["sending"].update(enabled="true"), "sending.enabled"),
        (lambda d: d["vrm"].update(poll_interval="60"), "vrm.poll_interval"),
        (lambda d: d["vrm"].update(poll_interval=60.0), "vrm.poll_interval"),
        (
            lambda d: d["vrm"]["installations"][0].update(site_id="123456"),
            "vrm.installations[0].site_id",
        ),
        (
            lambda d: d["vrm"]["installations"][0].update(site_id=True),
            "vrm.installations[0].site_id",
        ),
        (
            lambda d: d["rules"][2]["levels"][1].update(threshold=True),
            "rules[2].levels[1].threshold",
        ),
        (
            lambda d: d["rules"][2]["levels"][1].update(threshold="12"),
            "rules[2].levels[1].threshold",
        ),
        (lambda d: d["rules"][0].update(recipients="audit"), "rules[0].recipients"),
        (lambda d: d["rules"][0].update(recovery_notify=1), "rules[0].recovery_notify"),
        (lambda d: d["health"].update(port="8080"), "health.port"),
        (lambda d: d.update(providers={"log": None}), "providers.log"),
    ],
)
def test_strict_types(
    config_data: Data, problems: Problems, mutate: Callable[[Data], None], path: str
) -> None:
    mutate(config_data)
    (problem,) = problems(config_data)
    assert problem.startswith(f"{path}: ")


@pytest.mark.parametrize(
    ("mutate", "path"),
    [
        (lambda d: d["vrm"].update(poll_interval=29), "vrm.poll_interval"),
        (lambda d: d["vrm"].update(poll_interval=3601), "vrm.poll_interval"),
        (
            lambda d: d["vrm"]["installations"][1].update(site_id=0),
            "vrm.installations[1].site_id",
        ),
        (
            lambda d: d.update(rate_limits={"global_per_hour": 0}),
            "rate_limits.global_per_hour",
        ),
        (
            lambda d: d.update(rate_limits={"global_per_day": 10_001}),
            "rate_limits.global_per_day",
        ),
        (lambda d: d.update(rate_limits={"retries": 11}), "rate_limits.retries"),
        (lambda d: d["rules"][1].update(hysteresis=-0.5), "rules[1].hysteresis"),
        (
            lambda d: d["rules"][1].update(clear_after_samples=0),
            "rules[1].clear_after_samples",
        ),
        (
            lambda d: d["rules"][1].update(cooldown_minutes=0),
            "rules[1].cooldown_minutes",
        ),
        (
            lambda d: d["rules"][1].update(reminder_interval_minutes=0),
            "rules[1].reminder_interval_minutes",
        ),
        (lambda d: d["rules"][1].update(reminder_max=21), "rules[1].reminder_max"),
        (
            lambda d: d["rules"][1].update(stale_after_minutes=0),
            "rules[1].stale_after_minutes",
        ),
        (
            lambda d: d["rules"][1]["measurement"].update(instance=-1),
            "rules[1].measurement.instance",
        ),
        (lambda d: d["health"].update(port=0), "health.port"),
        (lambda d: d["health"].update(port=65536), "health.port"),
    ],
)
def test_numeric_bounds(
    config_data: Data, problems: Problems, mutate: Callable[[Data], None], path: str
) -> None:
    mutate(config_data)
    (problem,) = problems(config_data)
    assert problem.startswith(f"{path}: ")


@pytest.mark.parametrize("value", [float("inf"), float("-inf"), float("nan")])
def test_non_finite_numbers_are_rejected(
    config_data: Data, problems: Problems, value: float
) -> None:
    config_data["rules"][2]["levels"][1]["threshold"] = value
    config_data["rules"][1]["hysteresis"] = value
    found = problems(config_data)
    assert {p.split(":")[0] for p in found} == {
        "rules[2].levels[1].threshold",
        "rules[1].hysteresis",
    }


def test_installation_list_bounds(config_data: Data, problems: Problems) -> None:
    config_data["vrm"]["installations"] = []
    (problem,) = problems(config_data)
    assert problem.startswith("vrm.installations: ")
    config_data["vrm"]["installations"] = [
        {"id": f"site{i}", "site_id": 100000 + i} for i in range(51)
    ]
    (problem,) = problems(config_data)
    assert problem.startswith("vrm.installations: ")


def test_installation_limit_is_inclusive(config_data: Data, parse: Parse) -> None:
    config_data["vrm"]["installations"] = [
        {"id": f"site{i}", "site_id": 100000 + i} for i in range(50)
    ]
    config_data["rules"] = []
    assert len(parse(config_data).vrm.installations) == 50


def test_rule_list_bound(config_data: Data, problems: Problems) -> None:
    template = config_data["rules"][2]
    config_data["rules"] = [dict(template, id=f"rule{i}") for i in range(201)]
    (problem,) = problems(config_data)
    assert problem.startswith("rules: ")


def test_rule_limit_is_inclusive(config_data: Data, parse: Parse) -> None:
    template = config_data["rules"][2]
    config_data["rules"] = [dict(template, id=f"rule{i}") for i in range(200)]
    assert len(parse(config_data).rules) == 200


def test_level_list_bounds(config_data: Data, problems: Problems, parse: Parse) -> None:
    rule = config_data["rules"][0]
    rule["levels"] = [{"name": f"l{i}", "threshold": i} for i in range(20)]
    assert len(parse(config_data).rules[0].levels) == 20
    rule["levels"] = [{"name": f"l{i}", "threshold": i} for i in range(21)]
    (problem,) = problems(config_data)
    assert problem.startswith("rules[0].levels: ")
    rule["levels"] = []
    (problem,) = problems(config_data)
    assert problem.startswith("rules[0].levels: ")


def test_recipient_list_bounds(
    config_data: Data, problems: Problems, parse: Parse
) -> None:
    config_data["recipients"] = {f"r{i}": {"provider": "log"} for i in range(50)}
    config_data["rules"] = []
    assert len(parse(config_data).recipients) == 50
    config_data["recipients"]["r50"] = {"provider": "log"}
    (problem,) = problems(config_data)
    assert problem.startswith("recipients: ")


def test_rule_needs_at_least_one_recipient(
    config_data: Data, problems: Problems
) -> None:
    config_data["rules"][1]["recipients"] = []
    (problem,) = problems(config_data)
    assert problem.startswith("rules[1].recipients: ")


@pytest.mark.parametrize(
    "name", ["Cabin", "-cabin", "_cabin", "a" * 64, "a b", "", "cabin!", "kühl"]
)
def test_invalid_names_are_rejected(
    config_data: Data, problems: Problems, name: str
) -> None:
    config_data["vrm"]["installations"][1]["id"] = name
    config_data["rules"][2]["id"] = name
    config_data["rules"][2]["levels"][0]["name"] = name
    found = problems(config_data)
    paths = {p.split(": ")[0] for p in found}
    assert {
        "vrm.installations[1].id",
        "rules[2].id",
        "rules[2].levels[0].name",
    } <= paths
    assert all("lowercase letters, digits" in p for p in found)


def test_longest_valid_name_is_accepted(config_data: Data, parse: Parse) -> None:
    name = "a" * 63
    config_data["rules"][2]["id"] = name
    assert parse(config_data).rules[2].id == name


def test_invalid_recipient_name_is_reported_as_key(
    config_data: Data, problems: Problems, to_yaml: Callable[[Any], str]
) -> None:
    config_data["recipients"]["Bad Name"] = {"provider": "log"}
    text = to_yaml(config_data)
    (problem,) = problems(text)
    assert problem.startswith("recipients[#4] (key): must be 1-63 lowercase")
    assert problem.endswith(f"(line {line_of(text, 'Bad Name:')})")
    assert "Bad" not in problem


@pytest.mark.parametrize(
    ("direction", "thresholds"),
    [
        ("rising", [1, 2, 2]),
        ("rising", [1, 3, 2]),
        ("falling", [3, 2, 2]),
        ("falling", [3, 1, 2]),
    ],
)
def test_thresholds_must_be_strictly_ordered(
    config_data: Data, problems: Problems, direction: str, thresholds: list[float]
) -> None:
    rule = config_data["rules"][2]
    rule["direction"] = direction
    for level, threshold in zip(rule["levels"], thresholds, strict=True):
        level["threshold"] = threshold
    (problem,) = problems(config_data)
    expected = "greater" if direction == "rising" else "less"
    assert problem == (
        f"rules[2].levels[2].threshold: must be {expected} than the previous "
        f"level's threshold for a {direction} rule"
    )


def test_unknown_direction_is_rejected(config_data: Data, problems: Problems) -> None:
    config_data["rules"][2]["direction"] = "up"
    (problem,) = problems(config_data)
    assert problem.startswith("rules[2].direction: ")


def test_unknown_rule_references(config_data: Data, problems: Problems) -> None:
    config_data["rules"][2]["installation"] = "barn"
    config_data["rules"][2]["recipients"] = ["audit", "nobody"]
    assert problems(config_data) == (
        "rules[2].installation: unknown installation (not listed in vrm.installations)",
        "rules[2].recipients[1]: unknown recipient (not defined under recipients)",
    )


def test_duplicates_are_rejected(config_data: Data, problems: Problems) -> None:
    config_data["vrm"]["installations"][1] = {"id": "cabin", "site_id": 123456}
    config_data["rules"][2]["id"] = "battery"
    config_data["rules"][2]["installation"] = "cabin"
    config_data["rules"][2]["levels"][2]["name"] = "warning"
    config_data["rules"][2]["recipients"] = ["audit", "audit"]
    config_data["rules"][1]["installation"] = "cabin"
    assert problems(config_data) == (
        "vrm.installations[1].id: duplicate installation id (same as vrm.installations[0].id)",
        "vrm.installations[1].site_id: duplicate site_id (same as vrm.installations[0].site_id)",
        "rules[2].id: duplicate rule id (same as rules[1].id)",
        "rules[2].levels[2].name: duplicate level name (same as rules[2].levels[0].name)",
        "rules[2].recipients[1]: duplicate recipient (same as rules[2].recipients[0])",
    )


def test_stale_age_must_exceed_poll_interval(
    config_data: Data, problems: Problems
) -> None:
    config_data["vrm"]["poll_interval"] = 120
    config_data["rules"][0]["stale_after_minutes"] = 2
    assert problems(config_data) == (
        "rules[0].stale_after_minutes: must be longer than vrm.poll_interval",
    )


def test_hourly_cap_cannot_exceed_daily_cap(
    config_data: Data, problems: Problems
) -> None:
    config_data["rate_limits"] = {"global_per_hour": 61, "global_per_day": 60}
    assert problems(config_data) == (
        "rate_limits.global_per_hour: must not exceed rate_limits.global_per_day",
    )


@pytest.mark.parametrize(
    ("provider", "field"),
    [
        ("voipms", "username_file"),
        ("voipms", "password_file"),
        ("voipms", "did"),
        ("homeassistant", "base_url"),
        ("homeassistant", "token_file"),
        ("webhook", "url"),
    ],
)
def test_enabled_provider_requires_its_settings(
    config_data: Data, problems: Problems, parse: Parse, provider: str, field: str
) -> None:
    section = config_data["providers"][provider]
    del section[field]
    parse(config_data)  # absent settings are fine while the provider is disabled
    section["enabled"] = True
    assert problems(config_data) == (
        f"providers.{provider}.{field}: is required when the provider is enabled",
    )


@pytest.mark.parametrize("missing", ["auth_header_name", "auth_header_value_file"])
def test_webhook_auth_settings_go_together(
    config_data: Data, problems: Problems, missing: str
) -> None:
    del config_data["providers"]["webhook"][missing]
    assert problems(config_data) == (
        "providers.webhook: auth_header_name and auth_header_value_file must be set together",
    )


def test_webhook_without_auth_is_valid(config_data: Data, parse: Parse) -> None:
    webhook = config_data["providers"]["webhook"]
    del webhook["auth_header_name"], webhook["auth_header_value_file"]
    webhook["enabled"] = True
    assert parse(config_data).providers.webhook.auth_header_name is None


@pytest.mark.parametrize(
    "value",
    [
        "2025550142",
        "202-555-0142",
        "(202) 555-0142",
        "202.555.0142",
        "1 202 555 0142",
        "12025550142",
        "+12025550142",
        "+1 (202) 555-0142",
    ],
)
def test_phone_numbers_are_normalized(
    config_data: Data, parse: Parse, value: str
) -> None:
    config_data["recipients"]["owner_sms"]["phone"] = value
    phone = parse(config_data).recipients["owner_sms"].phone  # type: ignore[union-attr]
    assert phone.e164 == "+12025550142"
    assert phone.national == FULL_NUMBER_DIGITS
    assert phone.last4 == "0142"


@pytest.mark.parametrize(
    "value",
    [
        "555-0142",
        "+44 20 7946 0142",
        "+2 202 555 0142",
        "+1202555014",
        "1025550142",
        "2021550142",
        "22025550142",
        "202555014x",
        "２０２５５５０１４２",
        "202 555 0142 ext 9",
        "2025550142" * 4,
        "",
    ],
)
def test_invalid_phone_numbers_are_rejected_and_masked(
    config_data: Data, problems: Problems, value: str
) -> None:
    config_data["recipients"]["owner_sms"]["phone"] = value
    (problem,) = problems(config_data)
    assert problem.startswith(
        "recipients.owner_sms.phone: must be a 10-digit NANP number or a +1 E.164 number"
    )
    assert not re.search(r"[0-9]{5}", problem)
    assert "２０２" not in problem
    digits = re.sub(r"[^0-9]", "", value)
    if len(digits) >= 4:
        assert problem.endswith(f"(value ending {digits[-4:]})")


def test_phone_number_object_never_shows_the_full_number() -> None:
    phone = PhoneNumber.parse("+1 202 555 0142")
    for text in (str(phone), repr(phone), f"{phone}", str([phone])):
        assert FULL_NUMBER_DIGITS not in text
        assert "0142" in text
    assert repr(phone) == "PhoneNumber('***-***-0142')"
    assert phone.masked == "***-***-0142"
    assert phone == PhoneNumber("2025550142")
    assert phone != PhoneNumber("2025550143")
    assert phone != FULL_NUMBER_DIGITS
    assert len({phone, PhoneNumber("2025550142")}) == 1
    with pytest.raises(ValueError, match="10-digit NANP"):
        PhoneNumber("1025550142")


def test_ipv6_host_fallback_validation() -> None:
    from vrm_alert_relay.config.fields import _check_host

    _check_host("[fd00::10]")
    with pytest.raises(ValueError, match="invalid IPv6 host"):
        _check_host("[not-an-ip]")


def test_unquoted_phone_number_is_rejected_with_hint(
    config_data: Data, problems: Problems
) -> None:
    config_data["recipients"]["owner_sms"]["phone"] = 2025550142
    config_data["providers"]["voipms"]["did"] = 2025550100
    found = problems(config_data)
    assert found == (
        "recipients.owner_sms.phone: must be a string (quote phone numbers in YAML)",
        "providers.voipms.did: must be a string (quote phone numbers in YAML)",
    )
    assert all(FULL_NUMBER_DIGITS not in p and "2025550100" not in p for p in found)


def test_invalid_did_is_masked(config_data: Data, problems: Problems) -> None:
    config_data["providers"]["voipms"]["did"] = "1025550100"
    (problem,) = problems(config_data)
    assert problem.startswith("providers.voipms.did: must be a 10-digit")
    assert "1025550100" not in problem
    assert problem.endswith("(value ending 0100)")


def test_phone_key_used_as_recipient_name_is_masked(
    config_data: Data, problems: Problems
) -> None:
    config_data["recipients"]["+12025550142"] = {"provider": "log"}
    (problem,) = problems(config_data)
    assert FULL_NUMBER_DIGITS not in problem
    assert "0142" not in problem
    assert problem.startswith("recipients[#4] (key): ")


@pytest.mark.parametrize(
    "service", ["notify.mobile_app", "Mobile_App", "mobile-app", "", "a" * 256]
)
def test_invalid_home_assistant_service(
    config_data: Data, problems: Problems, service: str
) -> None:
    config_data["recipients"]["owner_app"]["service"] = service
    (problem,) = problems(config_data)
    assert problem.startswith(
        "recipients.owner_app.service: must be a Home Assistant notify"
    )


def test_recipient_provider_discriminator(
    config_data: Data, problems: Problems
) -> None:
    config_data["recipients"]["owner_sms"] = {"provider": "carrier_pigeon"}
    config_data["recipients"]["owner_app"] = {"service": "mobile_app_test"}
    config_data["recipients"]["hook"] = {"provider": "voipms"}
    choices = "'voipms', 'homeassistant', 'webhook', 'log'"
    assert problems(config_data) == (
        f"recipients.owner_sms.provider: must be one of {choices}",
        f"recipients.owner_app.provider: is required (one of {choices})",
        "recipients.hook.phone: is required",
    )


GOOD_URLS = [
    "https://hooks.example.com/relay?channel=alerts",
    "https://homeassistant.example.invalid:8123",
    "https://10.0.0.10:8123/",
    "https://[fd00::10]:8123/api",
    "HTTPS://hooks.example.com/",
    "https://localhost/",
]

BAD_URLS = [
    ("http://hooks.example.com/", "must be an https:// URL"),
    ("ftp://hooks.example.com/", "must be an https:// URL"),
    ("hooks.example.com/relay", "must be an https:// URL"),
    ("https://", "must include a host"),
    ("https:///relay", "must include a host"),
    ("https://:8443/relay", "must include a host"),
    ("https://user:fake-password-123@hooks.example.com/", "must not contain user info"),
    ("https://user@hooks.example.com/", "must not contain user info"),
    ("https://hooks.example.com/#frag", "must not contain a fragment"),
    ("https://hooks.example.com/#", "must not contain a fragment"),
    ("https://hooks.example.com/a b", "must not contain whitespace"),
    ("https://hooks.example.com/\r\nX-Injected: 1", "must not contain whitespace"),
    ("https://hooks.example.com\\@evil.example.com/", "must not contain whitespace"),
    ("https://hooks.example.com:99999/", "has an invalid port"),
    ("https://hooks.example.com:0/", "has an invalid port"),
    ("https://hooks.example.com:http/", "has an invalid port"),
    ("https://[fd00::10/", "is not a valid URL"),
    ("https://[not-an-ip]/", "not a valid URL"),
    ("https://hooks_example.com/", "has an invalid host name"),
    ("https://bücher.example.com/", "has an invalid host name"),
    ("https://" + "a" * 2050 + ".example.com/", "must be at most 2048 characters"),
]


@pytest.mark.parametrize("url", GOOD_URLS)
def test_valid_urls_are_accepted(config_data: Data, parse: Parse, url: str) -> None:
    config_data["providers"]["webhook"]["url"] = url
    config_data["providers"]["homeassistant"]["base_url"] = url
    config_data["vrm"]["base_url"] = url
    config_data["providers"]["voipms"]["base_url"] = url
    config = parse(config_data)
    assert config.providers.webhook.url == url


@pytest.mark.parametrize(("url", "reason"), BAD_URLS)
def test_invalid_urls_are_rejected_without_echo(
    config_data: Data, problems: Problems, url: str, reason: str
) -> None:
    config_data["providers"]["webhook"]["url"] = url
    config_data["providers"]["homeassistant"]["base_url"] = url
    config_data["vrm"]["base_url"] = url
    config_data["providers"]["voipms"]["base_url"] = url
    found = problems(config_data)
    assert [p.split(": ")[0] for p in found] == [
        "vrm.base_url",
        "providers.voipms.base_url",
        "providers.homeassistant.base_url",
        "providers.webhook.url",
    ]
    assert all(reason in p for p in found)
    assert all("fake-password" not in p and "hooks.example" not in p for p in found)


def test_url_query_tokens_are_not_echoed(config_data: Data, problems: Problems) -> None:
    config_data["providers"]["webhook"]["url"] = (
        "http://hooks.example.com/?token=fake-token-123"
    )
    (problem,) = problems(config_data)
    assert "fake-token-123" not in problem


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("X Relay", "valid HTTP header name"),
        ("X-Relay\r\nX-Injected", "valid HTTP header name"),
        ("X-Relay:", "valid HTTP header name"),
        ("", "valid HTTP header name"),
        ("X" * 65, "valid HTTP header name"),
        ("Host", "transport controls"),
        ("content-length", "transport controls"),
        ("Transfer-Encoding", "transport controls"),
        ("Proxy-Authorization", "transport controls"),
    ],
)
def test_invalid_webhook_header_names(
    config_data: Data, problems: Problems, name: str, reason: str
) -> None:
    config_data["providers"]["webhook"]["auth_header_name"] = name
    (problem,) = problems(config_data)
    assert problem.startswith("providers.webhook.auth_header_name: ")
    assert reason in problem


@pytest.mark.parametrize("name", ["Authorization", "X-Relay-Token", "x-api-key"])
def test_valid_webhook_header_names(config_data: Data, parse: Parse, name: str) -> None:
    config_data["providers"]["webhook"]["auth_header_name"] = name
    assert parse(config_data).providers.webhook.auth_header_name == name


@pytest.mark.parametrize(
    ("message", "reason"),
    [
        ("line one\nline two", "line breaks or control characters"),
        ("carriage\rreturn", "line breaks or control characters"),
        ("nul\x00byte", "line breaks or control characters"),
        ("tab\tchar", "line breaks or control characters"),
        ("escape \x1b[31m", "line breaks or control characters"),
        ("delete\x7fchar", "line breaks or control characters"),
        ("c1\x9bcontrol", "line breaks or control characters"),
        ("x" * 321, "at most 320 characters"),
        ("", "must not be empty"),
    ],
)
def test_invalid_message_templates(
    config_data: Data, problems: Problems, message: str, reason: str
) -> None:
    config_data["rules"][2]["levels"][1]["message"] = message
    (problem,) = problems(config_data)
    assert problem.startswith("rules[2].levels[1].message: ")
    assert reason in problem


@pytest.mark.parametrize(
    "escape", ["\\N", "\\L", "\\P", "\\n", "\\r", "\\0", "\\e", "\\x85"]
)
def test_escaped_line_breaks_in_templates_are_rejected(
    config_data: Data, to_yaml: Callable[[Any], str], problems: Problems, escape: str
) -> None:
    config_data["rules"][2]["levels"][1]["message"] = "PLACEHOLDER"
    text = to_yaml(config_data).replace("PLACEHOLDER", f'"next{escape}line"')
    (problem,) = problems(text)
    assert problem == (
        "rules[2].levels[1].message: must not contain line breaks or control characters"
    )


def test_template_at_length_limit_is_stored_verbatim(
    config_data: Data, parse: Parse
) -> None:
    message = "{value} " + "x" * 312
    assert len(message) == 320
    config_data["rules"][2]["levels"][1]["message"] = message
    assert parse(config_data).rules[2].levels[1].message == message


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("fake-token-abc123", "must be an absolute path"),
        ("secrets/vrm_token", "must be an absolute path"),
        ("", "must not be empty"),
        ("/run/secrets/vrm\ntoken", "must not contain line breaks"),
        ("/" + "a" * 4096, "at most 4096 characters"),
    ],
)
def test_invalid_secret_paths_are_not_echoed(
    config_data: Data, problems: Problems, value: str, reason: str
) -> None:
    config_data["vrm"]["token_file"] = value
    config_data["providers"]["voipms"]["password_file"] = value
    found = problems(config_data)
    assert [p.split(": ")[0] for p in found] == [
        "vrm.token_file",
        "providers.voipms.password_file",
    ]
    assert all(reason in p for p in found)
    if value:
        assert all(value not in p for p in found)


@pytest.mark.parametrize(
    ("location", "key"),
    [
        (("vrm",), "token"),
        (("vrm",), "access_token"),
        (("providers", "voipms"), "password"),
        (("providers", "voipms"), "api_password"),
        (("providers", "voipms"), "username"),
        (("providers", "homeassistant"), "token"),
        (("providers", "webhook"), "auth_header_value"),
        (("providers", "webhook"), "secret"),
        (("providers", "webhook"), "api_key"),
        (("recipients", "owner_sms"), "apikey"),
        ((), "credentials"),
    ],
)
def test_inline_secrets_are_rejected(
    config_data: Data,
    problems: Problems,
    to_yaml: Callable[[Any], str],
    location: tuple[str, ...],
    key: str,
) -> None:
    section = config_data
    for part in location:
        section = section[part]
    section[key] = "fake-inline-secret-value"
    text = to_yaml(config_data)
    (problem,) = problems(text)
    parent = ".".join(location) or "<root>"
    assert problem == (
        f"{parent}: inline secret values are not allowed; put the value in a file "
        "and reference it with the matching '*_file' setting "
        f"(line {line_of(text, 'fake-inline-secret-value')})"
    )


def test_inline_secret_is_reported_with_other_problems(
    config_data: Data, problems: Problems
) -> None:
    inline_value = "fake-inline-secret-value"
    config_data["vrm"]["token"] = inline_value
    config_data["vrm"]["poll_interval"] = 5
    found = problems(config_data)
    assert sorted(p.split(":")[0] for p in found) == ["vrm", "vrm.poll_interval"]
    assert any(p.startswith("vrm: inline secret values are not allowed") for p in found)
    assert all("fake-inline-secret-value" not in p for p in found)


def test_names_that_look_like_secret_keys_are_allowed(
    config_data: Data, parse: Parse
) -> None:
    config_data["recipients"]["token"] = {"provider": "log"}
    config_data["rules"][2]["recipients"] = ["token"]
    assert parse(config_data).delivery_mode("token") == "dry_run"


@pytest.mark.parametrize(
    ("bind", "stored"), [("::1", "::1"), ("::", "::"), ("127.000.0.1", None)]
)
def test_health_bind_address(
    config_data: Data, parse: Parse, problems: Problems, bind: str, stored: str | None
) -> None:
    config_data["health"]["bind"] = bind
    if stored is None:
        (problem,) = problems(config_data)
        assert problem == "health.bind: must be an IPv4 or IPv6 address"
    else:
        assert parse(config_data).health.bind == stored


def test_health_bind_rejects_host_names(config_data: Data, problems: Problems) -> None:
    config_data["health"]["bind"] = "localhost"
    assert problems(config_data) == ("health.bind: must be an IPv4 or IPv6 address",)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("code", ""),
        ("code", "b v"),
        ("code", "x" * 33),
        ("service_type", "bat tery"),
        ("service_type", ""),
    ],
)
def test_invalid_measurement_identifiers(
    config_data: Data, problems: Problems, field: str, value: str
) -> None:
    config_data["rules"][1]["measurement"][field] = value
    (problem,) = problems(config_data)
    assert problem.startswith(f"rules[1].measurement.{field}: ")


def test_missing_required_sections(problems: Problems) -> None:
    assert problems({"sending": {"enabled": False}}) == (
        "version: is required; this release supports configuration version 1",
        "vrm: is required",
    )


@pytest.mark.parametrize("version", [0, 2, 99])
def test_unsupported_version_is_reported_alone(
    config_data: Data, problems: Problems, version: int
) -> None:
    config_data["version"] = version
    config_data["vrm"]["poll_interval"] = 1
    assert problems(config_data) == (
        "version: unsupported configuration version; this release supports configuration version 1",
    )


@pytest.mark.parametrize("version", ["1", 1.0, True, None])
def test_version_must_be_an_integer(
    config_data: Data, problems: Problems, version: object
) -> None:
    config_data["version"] = version
    (problem,) = problems(config_data)
    assert problem.startswith("version: must be a whole number")


def test_unsupported_version_rejected_by_direct_validation(
    config_data: Data, parse: Parse
) -> None:
    config = parse(config_data)
    assert config.version == 1
    data = copy.deepcopy(config_data)
    data["version"] = 2
    with pytest.raises(pydantic.ValidationError):
        RelayConfig.model_validate(data)


def test_many_field_problems_are_reported_together(
    config_data: Data, problems: Problems
) -> None:
    config_data["vrm"]["poll_interval"] = 1
    config_data["health"]["port"] = 0
    config_data["rules"][0]["direction"] = "sideways"
    assert len(problems(config_data)) == 3


def test_semantic_errors_raise_config_error_from_direct_validation(
    config_data: Data,
) -> None:
    data = copy.deepcopy(config_data)
    data["rules"][0]["installation"] = "barn"
    with pytest.raises(ConfigError) as caught:
        RelayConfig.model_validate(data)
    assert caught.value.problems == (
        "rules[0].installation: unknown installation (not listed in vrm.installations)",
    )


def test_python_objects_validate_directly(config_data: Data, parse: Parse) -> None:
    config = parse(config_data)
    rebuilt = RelayConfig.model_validate(
        {
            "version": 1,
            "vrm": config.vrm,
            "recipients": {"owner_sms": config.recipients["owner_sms"]},
            "providers": config.providers,
        }
    )
    assert rebuilt.recipients["owner_sms"] == config.recipients["owner_sms"]
    phone = PhoneNumber("2025550142")
    recipient = VoipmsRecipient.model_validate({"provider": "voipms", "phone": phone})
    assert recipient.phone is phone
    assert rebuilt.providers.is_enabled("log") is True

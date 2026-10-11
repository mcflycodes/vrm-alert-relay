"""No configuration error path may echo a secret-like value or a full phone number.

Each case plants a canary secret and/or a phone-shaped value where it triggers one
specific error path, then checks every rendering of the resulting error.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic_core import ErrorDetails

from vrm_alert_relay.config import (
    ConfigError,
    check_config,
    load_config,
    load_secrets,
    parse_config,
)
from vrm_alert_relay.config.loader import _error_message

Data = dict[str, Any]
Dump = Callable[[Any], str]
Builder = Callable[[Data, Dump], str | bytes]

CANARY = "fake-secret-CANARY-7Q9X"
CANARY_NAME = (
    "fake-secret-canary-7q9x"  # passes the name pattern, reaches semantic checks
)
PHONE = "+1 202 555 0142"
PHONE_NAME = "2025550142"
FORBIDDEN = (
    "CANARY",
    "canary",
    "7Q9X",
    "7q9x",
    "2025550142",
    "202 555 0142",
    "5550142",
    "555 0142",
    "555-0142",
)


def _assert_clean(error: BaseException, problems: tuple[str, ...]) -> None:
    rendered = [str(error), repr(error), repr(error.args), *problems]
    for text in rendered:
        for forbidden in FORBIDDEN:
            assert forbidden not in text, f"{forbidden!r} leaked in {text!r}"
    assert error.__cause__ is None
    assert error.__context__ is None


def _set(path: tuple[str | int, ...], value: Any) -> Builder:
    def build(data: Data, dump: Dump) -> str:
        target: Any = data
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
        return dump(data)

    return build


def _text(text: str | bytes) -> Builder:
    return lambda _data, _dump: text


def _rule_recipients(*names: str) -> Builder:
    return _set(("rules", 2, "recipients"), list(names))


def _duplicate_rule_id(data: Data, dump: Dump) -> str:
    data["rules"][1]["id"] = CANARY_NAME
    data["rules"][2]["id"] = CANARY_NAME
    return dump(data)


def _duplicate_installation(data: Data, dump: Dump) -> str:
    data["vrm"]["installations"] = [
        {"id": CANARY_NAME, "site_id": 202555014},
        {"id": CANARY_NAME, "site_id": 202555014},
    ]
    data["rules"] = []
    return dump(data)


def _duplicate_level(data: Data, dump: Dump) -> str:
    levels = data["rules"][2]["levels"]
    levels[0]["name"] = CANARY_NAME
    levels[1]["name"] = CANARY_NAME
    return dump(data)


def _duplicate_recipient_key(data: Data, dump: Dump) -> str:
    text = dump(data)
    entry = f"  '{PHONE_NAME}':\n    provider: log\n"
    return text.replace("recipients:\n", "recipients:\n" + entry + entry, 1)


def _template_line(data: Data, dump: Dump) -> str:
    data["rules"][2]["levels"][1]["message"] = "PLACEHOLDER"
    return dump(data).replace("PLACEHOLDER", f'"{CANARY}\\n{PHONE}"')


CASES: dict[str, Builder] = {
    # pydantic error types
    "string_type": _set(("recipients", "owner_app", "service"), 2025550142),
    "bool_type": _set(("sending", "enabled"), CANARY),
    "int_type": _set(("vrm", "poll_interval"), CANARY),
    "float_type": _set(("rules", 0, "levels", 0, "threshold"), PHONE),
    "literal_error": _set(("rules", 0, "direction"), CANARY),
    "union_tag_invalid": _set(("recipients", "owner_sms", "provider"), CANARY),
    "union_tag_not_found": _set(("recipients", "owner_sms"), {"phone": PHONE}),
    "extra_forbidden": _set(("vrm", "unknown_setting"), CANARY),
    "inline_secret": _set(("providers", "voipms", "password"), CANARY),
    "inline_token_phone": _set(("vrm", "token"), PHONE),
    "model_type": _set(("vrm",), CANARY),
    "mapping_under_leaf": _set(("health", "port"), {CANARY: {PHONE_NAME: 1}}),
    "dict_type": _set(("recipients",), CANARY),
    "tuple_type": _set(("rules",), CANARY),
    "too_long": _rule_recipients(*[CANARY_NAME] * 51),
    "less_than_equal": _set(("vrm", "installations", 0, "site_id"), 2025550142),
    "greater_than_equal": _set(("vrm", "poll_interval"), -2025550142),
    "version_unsupported": _set(("version",), 2025550142),
    "version_type": _set(("version",), CANARY),
    # field validators
    "url_userinfo": _set(
        ("providers", "webhook", "url"), f"https://u:{CANARY}@h.example.com/"
    ),
    "url_scheme": _set(
        ("vrm", "base_url"), f"http://hooks.example.com/?t={CANARY}&p={PHONE}"
    ),
    "url_host": _set(
        ("providers", "homeassistant", "base_url"), f"https://{CANARY}_x/"
    ),
    "phone_invalid": _set(("recipients", "owner_sms", "phone"), "+1 102 555 0142"),
    "phone_canary": _set(("recipients", "owner_sms", "phone"), CANARY),
    "did_invalid": _set(("providers", "voipms", "did"), "+44 202 555 0142"),
    "header_name": _set(("providers", "webhook", "auth_header_name"), f"X {CANARY}"),
    "template_length": _set(
        ("rules", 0, "levels", 0, "message"), (CANARY + PHONE) * 20
    ),
    "template_line_break": _template_line,
    "secret_path_relative": _set(("vrm", "token_file"), CANARY),
    "secret_path_phone": _set(("providers", "voipms", "password_file"), PHONE),
    "bind": _set(("health", "bind"), CANARY),
    "name_pattern": _set(("rules", 0, "id"), CANARY),
    "measurement_code": _set(("rules", 0, "measurement", "code"), CANARY),
    "service_type": _set(("rules", 0, "measurement", "service_type"), f"{CANARY} x"),
    "ha_service": _set(("recipients", "owner_app", "service"), CANARY),
    # semantic checks
    "unknown_recipient_phone": _rule_recipients(PHONE_NAME),
    "unknown_recipient_canary": _rule_recipients(CANARY_NAME),
    "duplicate_recipient": _rule_recipients("audit", "audit", PHONE_NAME),
    "unknown_installation": _set(("rules", 2, "installation"), CANARY_NAME),
    "duplicate_rule_id": _duplicate_rule_id,
    "duplicate_installation": _duplicate_installation,
    "duplicate_level": _duplicate_level,
    # YAML loading
    "yaml_unknown_tag": _text(f"vrm: !{CANARY} {{}}\n"),
    "yaml_python_tag": _text(f"vrm: !!python/name:{CANARY} {{}}\n"),
    "yaml_scanner": _text(f'vrm: "{CANARY} {PHONE}\n'),
    "yaml_parser": _text(f"vrm: [{CANARY}, {PHONE}\n"),
    "yaml_composer": _text(f"a: {CANARY}\n---\nb: {PHONE}\n"),
    "yaml_reader": _text(f"a: {CANARY}\x07{PHONE}\n"),
    "yaml_anchor": _text(f"a: &{CANARY} {PHONE}\nb: *{CANARY}\n"),
    "yaml_merge": _text(f"a:\n  <<: {{x: {CANARY}}}\n"),
    "yaml_duplicate_key": _text(f"a: {CANARY}\na: {PHONE}\n"),
    "yaml_duplicate_phone_key": _duplicate_recipient_key,
    "yaml_non_string_key": _text(f"{PHONE_NAME}: {CANARY}\n"),
    "yaml_nesting": _text("a: " + "[" * 20 + CANARY + "]" * 20 + "\n"),
    "yaml_unparseable_int": _text(f"a: {PHONE_NAME * 500}\n"),
    "yaml_not_mapping": _text(f"- {CANARY}\n- {PHONE}\n"),
    "yaml_not_utf8": _text(f"a: {CANARY} {PHONE}\n".encode() + b"\xff"),
}


def _key(path: tuple[str | int, ...], key: str, value: Any = 1) -> Builder:
    def build(data: Data, dump: Dump) -> str:
        target: Any = data
        for part in path:
            target = target[part]
        target[key] = value
        return dump(data)

    return build


def _duplicate(prefix: str, key: str, indent: str = "") -> Builder:
    return _text(f"{prefix}{indent}'{key}': 1\n{indent}'{key}': 2\n")


INLINE_LOOKING_KEY = "fake-secret-CANARY-7Q9X_token"

# The canary as a mapping key in every position. None of these keys pass the
# recipient-name rule, so none may be shown.
KEY_CASES: dict[str, Builder] = {
    "top_level": _key((), CANARY),
    "top_level_phone": _key((), PHONE_NAME),
    "vrm": _key(("vrm",), CANARY),
    "installation": _key(("vrm", "installations", 0), CANARY),
    "sending": _key(("sending",), PHONE),
    "providers": _key(("providers",), CANARY, {"enabled": True}),
    "provider_section": _key(("providers", "voipms"), CANARY),
    "log_provider": _key(("providers", "log"), CANARY),
    "rule": _key(("rules", 0), CANARY),
    "level": _key(("rules", 0, "levels", 1), CANARY),
    "measurement": _key(("rules", 0, "measurement"), CANARY),
    "health": _key(("health",), CANARY),
    "recipient_field": _key(("recipients", "owner_sms"), CANARY),
    "recipient_name": _key(("recipients",), CANARY, {"provider": "log"}),
    "recipient_name_phone": _key(("recipients",), PHONE_NAME, {"provider": "voipms"}),
    "recipient_name_phone_formatted": _key(("recipients",), PHONE, {"provider": "log"}),
    "recipient_name_digits_inside": _key(
        ("recipients",), f"owner-{PHONE_NAME}", {"provider": "voipms"}
    ),
    "recipient_bad_provider": _key(("recipients",), CANARY, {"provider": CANARY}),
    "recipient_missing_provider": _key(("recipients",), CANARY, {"phone": PHONE}),
    "recipient_unknown_field": _key(
        ("recipients",), PHONE_NAME, {"provider": "log", CANARY: 1}
    ),
    "inline_secret_looking_key": _key(("vrm",), INLINE_LOOKING_KEY, CANARY),
    "nested_under_unknown_key": _key((), CANARY, {PHONE_NAME: {CANARY: 1}}),
    "duplicate_under_leaf": _text(
        f"health:\n  port:\n    {CANARY}:\n      '{PHONE_NAME}': 1\n      '{PHONE_NAME}': 2\n"
    ),
    "duplicate_top_level": _duplicate("", CANARY),
    "duplicate_phone": _duplicate("", PHONE_NAME),
    "duplicate_in_vrm": _duplicate("vrm:\n", CANARY, "  "),
    "duplicate_recipient_name": _duplicate("recipients:\n", CANARY, "  "),
    "duplicate_recipient_phone_name": _duplicate("recipients:\n", PHONE_NAME, "  "),
    "duplicate_under_bad_recipient": _text(
        f"recipients:\n  {CANARY}:\n    '{PHONE_NAME}': 1\n    '{PHONE_NAME}': 2\n"
    ),
    "duplicate_in_rule": _text(f"rules:\n  - {CANARY}: 1\n    {CANARY}: 2\n"),
    "duplicate_under_unknown": _text(f"{CANARY}:\n  {CANARY}: 1\n  {CANARY}: 2\n"),
    "merge_under_unknown": _text(f"{CANARY}:\n  <<: {{a: 1}}\n"),
    "non_string_under_unknown": _text(f"{CANARY}:\n  {PHONE_NAME}: 1\n"),
    "oversized_under_unknown": _text(f"{CANARY}: [" + ",".join(["1"] * 1001) + "]\n"),
}


@pytest.mark.parametrize("build", KEY_CASES.values(), ids=KEY_CASES.keys())
def test_config_errors_never_echo_mapping_keys(
    config_data: Data, to_yaml: Dump, build: Builder, request: pytest.FixtureRequest
) -> None:
    text = build(copy.deepcopy(config_data), to_yaml)
    with pytest.raises(ConfigError) as caught:
        parse_config(text)
    _assert_clean(caught.value, caught.value.problems)
    assert all("(line " in problem for problem in caught.value.problems)
    if "duplicate" in request.node.callspec.id:
        assert all("duplicate key" in p for p in caught.value.problems)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            f"{CANARY}: 1\n",
            "<root>: unrecognized setting (line 1)",
        ),
        (
            f"version: 1\n{CANARY}: 1\n{CANARY}: 2\n",
            "<root>: duplicate key (line 3)",
        ),
        (
            f"recipients:\n  owner: {{provider: log}}\n  {CANARY}:\n    provider: {CANARY}\n",
            (
                "recipients[#1].provider: must be one of "
                "'voipms', 'homeassistant', 'webhook', 'log' (line 4)"
            ),
        ),
    ],
    ids=["unknown_key", "duplicate_key", "recipient_key_provider"],
)
def test_reviewer_key_repros(text: str, expected: str) -> None:
    with pytest.raises(ConfigError) as caught:
        parse_config(text)
    assert expected in caught.value.problems
    _assert_clean(caught.value, caught.value.problems)


def test_valid_recipient_names_are_intentionally_shown(
    config_data: Data, to_yaml: Dump
) -> None:
    # Operators need to see their own valid names. A name passing the identifier
    # pattern with no run of five or more digits is shown even if it looks
    # like a secret; anything else is withheld as possibly mispasted data.
    config_data["recipients"][CANARY_NAME] = {"provider": "voipms"}
    with pytest.raises(ConfigError) as caught:
        parse_config(to_yaml(config_data))
    assert caught.value.problems == (f"recipients.{CANARY_NAME}.phone: is required",)


@pytest.mark.parametrize(
    "name",
    [
        CANARY,
        PHONE_NAME,
        f"r{PHONE_NAME}",
        "a" * 64,
        "Owner",
        "-owner",
        "owner.sms",
        "",
    ],
)
def test_names_failing_the_display_rule_are_withheld(
    config_data: Data, to_yaml: Dump, name: str
) -> None:
    config_data["recipients"][name] = {"provider": "voipms"}
    text = to_yaml(config_data)
    with pytest.raises(ConfigError) as caught:
        parse_config(text)
    for problem in caught.value.problems:
        assert problem.startswith("recipients[#4]")
        assert "(line " in problem
        if name:
            assert name not in problem


@pytest.mark.parametrize("build", CASES.values(), ids=CASES.keys())
def test_config_errors_never_echo_values(
    config_data: Data, to_yaml: Dump, build: Builder
) -> None:
    text = build(copy.deepcopy(config_data), to_yaml)
    with pytest.raises(ConfigError) as caught:
        parse_config(text)
    _assert_clean(caught.value, caught.value.problems)


@pytest.mark.parametrize(
    "content",
    [
        (f"a: {CANARY} {PHONE}\n" * 20000).encode(),
        f"a: {CANARY} {PHONE}\n".encode() + b"\xff",
        None,
        "directory",
    ],
    ids=["oversize", "not_utf8", "missing", "directory"],
)
def test_config_file_errors_never_echo_content(
    tmp_path: Path, content: bytes | str | None
) -> None:
    path = tmp_path / "config.yaml"
    if isinstance(content, bytes):
        path.write_bytes(content)
    elif content == "directory":
        path.mkdir()
    with pytest.raises(ConfigError) as caught:
        load_config(path)
    _assert_clean(caught.value, caught.value.problems)


@pytest.mark.parametrize(
    "content",
    [
        f"{CANARY}\x01{PHONE}\n",
        f"{CANARY}\n{PHONE}\n",
        (CANARY + PHONE).encode() + b"\xff\xfe",
        (CANARY + PHONE) * 200,
        "",
    ],
)
def test_secret_file_errors_never_echo_content(
    config_data: Data,
    to_yaml: Dump,
    tmp_path: Path,
    secrets_dir: Path,
    content: str | bytes,
) -> None:
    token = secrets_dir / "vrm_token"
    if isinstance(content, bytes):
        token.write_bytes(content)
    else:
        token.write_text(content)
    path = tmp_path / "config.yaml"
    path.write_text(to_yaml(config_data))

    report = check_config(path)
    assert report.ok is False
    for text in (repr(report), *report.problems, *report.warnings):
        for forbidden in FORBIDDEN:
            assert forbidden not in text

    with pytest.raises(ConfigError) as caught:
        load_secrets(parse_config(to_yaml(config_data)))
    _assert_clean(caught.value, caught.value.problems)


def _details(kind: str, ctx: dict[str, Any] | None = None) -> ErrorDetails:
    details: dict[str, Any] = {
        "type": kind,
        "loc": ("x",),
        "msg": CANARY,
        "input": CANARY,
    }
    if ctx is not None:
        details["ctx"] = ctx
    return details  # type: ignore[return-value]


@pytest.mark.parametrize(
    ("details", "expected"),
    [
        (_details("value_error", {"error": ValueError(CANARY)}), "is invalid"),
        (_details("value_error"), "is invalid"),
        (_details("literal_error", {"expected": 3}), "is invalid"),
        (_details("less_than_equal", {"le": CANARY}), "is invalid"),
        (_details("less_than_equal", {"le": True}), "is invalid"),
        (_details("too_short", {"min_length": 2}), "must contain at least 2 item(s)"),
        (_details("greater_than", {"gt": 0}), "must be greater than 0"),
        (_details("less_than", {"lt": 9}), "must be less than 9"),
        (_details("some_future_error_type"), "is invalid"),
    ],
)
def test_upstream_message_text_is_never_used(
    details: ErrorDetails, expected: str
) -> None:
    assert _error_message(details, ("x",)) == expected

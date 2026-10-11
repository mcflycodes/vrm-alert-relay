from __future__ import annotations

import base64
import json
import time
from typing import Any
from urllib.parse import quote, quote_plus

import pytest

from vrm_alert_relay.logs import (
    REDACTED,
    SecretRegistry,
    mask_recipient,
    redact_mapping,
    redact_secrets,
    redact_text,
    redact_value,
    register_derived_secret,
)
from vrm_alert_relay.logs import redaction as redaction_module
from vrm_alert_relay.logs.redaction import (
    MAX_DEPTH,
    MAX_ITEMS,
    MAX_NODES,
    TRUNCATED,
    escape_controls,
    is_sensitive_key,
    truncate,
)

CANARY = "fictitious-api-password-0001"
CANARY_2 = "fictitious-token-value-0002"


@pytest.fixture
def registry() -> SecretRegistry:
    instance = SecretRegistry()
    instance.register(CANARY)
    instance.register(CANARY_2)
    return instance


# Registered secrets


def test_registered_secret_replaced(registry: SecretRegistry) -> None:
    text = f"connecting with {CANARY} and {CANARY_2}{CANARY}"
    assert redact_text(text, registry=registry) == (
        f"connecting with {REDACTED} and {REDACTED}{REDACTED}"
    )


def test_short_secrets_ignored() -> None:
    registry = SecretRegistry()
    registry.register("abcde")
    assert registry.secrets == ()
    assert redact_text("abcde", registry=registry) == "abcde"


def test_encoded_variants_registered() -> None:
    registry = SecretRegistry()
    value = "fict pass/with&chars'\\"
    registry.register(value)
    for rendered in (
        value,
        "fict%20pass%2Fwith%26chars%27%5C",
        "fict+pass%2Fwith%26chars%27%5C",
        repr({"v": value}),
    ):
        assert "fict" not in redact_text(f"value={rendered!s} end", registry=registry)


TRICKY = 'fictitious"pa\\ss/wörd'


def _rendered_variants(value: str) -> list[str]:
    raw = value.encode()
    return [
        json.dumps({"detail": value}),
        json.dumps({"detail": value}, ensure_ascii=False),
        json.dumps(value),
        repr(value),
        quote(value, safe=""),
        quote(value, safe="").lower(),
        quote_plus(value, safe=""),
        quote_plus(value, safe="").lower(),
        base64.b64encode(raw).decode(),
        base64.b64encode(raw).decode().rstrip("="),
        base64.urlsafe_b64encode(raw).decode(),
    ]


@pytest.mark.parametrize("index", range(11))
def test_encoded_forms_of_registered_secret_redacted(index: int) -> None:
    registry = SecretRegistry()
    registry.register(TRICKY)
    rendered = _rendered_variants(TRICKY)[index]
    result = redact_text(f"value {rendered} end", registry=registry, max_length=10_000)
    assert REDACTED in result
    assert "fictitious" not in result
    assert "rd" not in result


def test_derived_credentials_need_their_own_registration() -> None:
    registry = SecretRegistry()
    registry.register("fictitious-pass")
    basic = base64.b64encode(b"relay-user:fictitious-pass").decode()
    header = f"Basic {basic}"
    assert basic in redact_text(f"sent {header}", registry=registry)
    registry.register("relay-user:fictitious-pass")
    assert redact_text(f"sent {header}", registry=registry) == f"sent Basic {REDACTED}"


def test_register_derived_secret_uses_default_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fresh = SecretRegistry()
    monkeypatch.setattr(redaction_module, "default_registry", fresh)
    register_derived_secret("relay-user:fictitious-pass")
    basic = base64.b64encode(b"relay-user:fictitious-pass").decode()
    assert redact_text(basic) == REDACTED
    assert redact_secrets(f"x {basic}") == f"x {REDACTED}"


def test_short_value_variants_not_registered() -> None:
    registry = SecretRegistry()
    registry.register("a/b+c")
    assert registry.secrets == ()


def test_longest_secret_replaced_first() -> None:
    registry = SecretRegistry()
    registry.register("fictitious")
    registry.register("fictitious-longer-value")
    lengths = [len(secret) for secret in registry.secrets]
    assert lengths == sorted(lengths, reverse=True)
    order = registry.secrets.index
    assert order("fictitious-longer-value") < order("fictitious")
    assert (
        redact_text("x fictitious-longer-value y", registry=registry)
        == f"x {REDACTED} y"
    )


def test_register_rejects_non_string() -> None:
    with pytest.raises(TypeError):
        SecretRegistry().register(b"fictitious-bytes")  # type: ignore[arg-type]


def test_clear(registry: SecretRegistry) -> None:
    registry.clear()
    assert registry.secrets == ()


# Sensitive keys


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "api_password",
        "PASSWD",
        "client_secret",
        "access_token",
        "Authorization",
        "api_key",
        "x-api-key",
        "apikey",
        "Cookie",
        "set-cookie",
    ],
)
def test_sensitive_keys(key: str) -> None:
    assert is_sensitive_key(key)


@pytest.mark.parametrize("key", ["user", "message", "installation", "phone"])
def test_non_sensitive_keys(key: str) -> None:
    assert not is_sensitive_key(key)


@pytest.mark.parametrize(
    ("text", "leaked"),
    [
        ("api_password=hunter2-value&api_username=user", "hunter2-value"),
        ("password: correct-horse", "correct-horse"),
        ("token = abc123def", "abc123def"),
        ('{"token": "abc def ghi"}', "def ghi"),
        ("{'client_secret': 'abc def'}", "abc def"),
        ("{'api_key': 'it\\'s quoted'}", "quoted"),
        ("Authorization: Bearer eyJ.fictitious.sig", "eyJ.fictitious.sig"),
        ("authorization=Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
        ('Cookie: session=abc; theme="dark mode"', "dark mode"),
        ("Set-Cookie: id=xyz789; Path=/", "xyz789"),
        ('password="unterminated value here', "value here"),
        ("APIKEY=ZZZ999", "ZZZ999"),
        ("x-api-key: zzz-111", "zzz-111"),
    ],
)
def test_sensitive_key_values_redacted_in_text(text: str, leaked: str) -> None:
    result = redact_text(text, registry=SecretRegistry())
    assert leaked not in result
    assert REDACTED in result


def test_sensitive_key_redaction_keeps_other_fields() -> None:
    result = redact_text(
        "user=alice&password=hunter2-value&mode=sms", registry=SecretRegistry()
    )
    assert result == f"user=alice&password={REDACTED}&mode=sms"


def test_sensitive_word_without_value_unchanged() -> None:
    text = "invalid token provided; check the password policy"
    assert redact_text(text, registry=SecretRegistry()) == text


# URLs


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (
            "GET https://voip.example.com/api/v1/rest.php?api_username=u&api_password=p done",
            f"GET https://voip.example.com/api/v1/rest.php?{REDACTED} done",
        ),
        (
            "see https://example.com/a#access=xyz",
            f"see https://example.com/a?{REDACTED}",
        ),
        (
            "https://user:fictitious-pass@example.com/path?q=1",
            f"https://{REDACTED}@example.com/path?{REDACTED}",
        ),
        ("https://user@example.com", f"https://{REDACTED}@example.com"),
        ("https://example.com/plain/path", "https://example.com/plain/path"),
        ("https://example.com?x=1", f"https://example.com?{REDACTED}"),
        ('"https://example.com/p?x=1"', f'"https://example.com/p?{REDACTED}"'),
    ],
)
def test_urls(text: str, expected: str) -> None:
    assert redact_text(text, registry=SecretRegistry()) == expected


# Phone numbers


@pytest.mark.parametrize(
    "number",
    [
        "+12025550143",
        "+1 202 555 0143",
        "+1-202-555-0143",
        "+1 (202) 555-0143",
        "(202) 555-0143",
        "202-555-0143",
        "202.555.0143",
        "202 555 0143",
        "2025550143",
        "12025550143",
        "1-202-555-0143",
        "+44 20 7946 0143",
    ],
)
def test_phone_numbers_masked(number: str) -> None:
    result = redact_text(f"sent to {number}.", registry=SecretRegistry())
    assert result == "sent to ***0143."


@pytest.mark.parametrize(
    "text",
    [
        "2026-10-11T06:17:00Z",
        "2026-10-11 06:17:00.123",
        "version 1.2.3",
        "installation 123456",
        "uuid 123e4567-e89b-12d3-a456-426614174000",
        "uuid 12345678-1234-1234-1234-123456789012",
        "ratio 3.14159265358979",
        "port 8443",
        "soc 87.5%",
        "+1 555",
        "id_2025550143",
        "hash a2025550143b",
    ],
)
def test_non_phone_numbers_untouched(text: str) -> None:
    assert redact_text(text, registry=SecretRegistry()) == text


def test_phone_in_url_path_masked() -> None:
    result = redact_text(
        "https://example.com/sms/2025550143/status", registry=SecretRegistry()
    )
    assert result == "https://example.com/sms/***0143/status"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("+12025550143", "***0143"),
        ("(202) 555-0143", "***0143"),
        (" 202.555.0143 ", "***0143"),
        (2025550143, "***0143"),
        ("notify.mobile_app_example", "***mple"),
        ("ops@example.com", "***.com"),
        ("abcd", "***"),
        ("", "***"),
        ("tail\x1b[2J", "***\\x1b[2J"),
    ],
)
def test_mask_recipient(value: object, expected: str) -> None:
    assert mask_recipient(value) == expected


# Control characters and truncation


@pytest.mark.parametrize(
    ("raw", "escaped"),
    [
        ("a\nb", "a\\nb"),
        ("a\r\nb", "a\\r\\nb"),
        ("a\tb", "a\\tb"),
        ("a\x00b", "a\\x00b"),
        ("\x1b[31mred", "\\x1b[31mred"),
        ("a\x7fb", "a\\x7fb"),
        ("a\x85b", "a\\x85b"),
        ("evil\u202etxt", "evil\\u202etxt"),
        ("a\u2028b", "a\\u2028b"),
        ("a\u2066b", "a\\u2066b"),
        ("ünïcødé ✓", "ünïcødé ✓"),
    ],
)
def test_control_characters_escaped(raw: str, escaped: str) -> None:
    assert escape_controls(raw) == escaped
    assert redact_text(raw, registry=SecretRegistry()) == escaped


def test_truncation() -> None:
    assert truncate("abcdef", 10) == "abcdef"
    assert truncate("a" * 30, 20) == "a" * (20 - len(TRUNCATED)) + TRUNCATED
    assert truncate("a" * 20 + "z", 15, keep="tail") == TRUNCATED + "aaaz"
    assert truncate("abcdef", 3) == TRUNCATED
    assert truncate("abcdef", 3, keep="tail") == TRUNCATED


def test_long_field_truncated() -> None:
    result = redact_text("x" * 10_000, registry=SecretRegistry())
    assert len(result) == 2048
    assert result.endswith(TRUNCATED)
    assert len(redact_text("x" * 100, registry=SecretRegistry(), max_length=50)) == 50


def test_escape_expansion_still_bounded() -> None:
    result = redact_text("\x00" * 5000, registry=SecretRegistry())
    assert len(result) == 2048


def test_huge_input_is_fast_and_bounded(registry: SecretRegistry) -> None:
    hostile = (
        "token=" + "a" * 50 + " +1 202 555 0143 https://example.com/?q=" + "b" * 100
    ) * 20_000
    start = time.perf_counter()
    result = redact_text(hostile + CANARY, registry=registry)
    assert time.perf_counter() - start < 2.0
    assert len(result) <= 2048
    assert "0143 " not in result.replace("***0143", "")


def test_regex_heavy_input_is_fast() -> None:
    hostile = (
        "tokentokentoken" * 5000
        + "1" * 5000
        + "+1 " * 5000
        + "password='"
        + "\\" * 5000
    )
    start = time.perf_counter()
    redact_text(hostile, registry=SecretRegistry(), max_length=100_000)
    assert time.perf_counter() - start < 2.0


def test_pre_truncation_never_exposes_partial_secret(registry: SecretRegistry) -> None:
    bound = max(16 * 2048, 65536)
    shrinking = 'password="' + "x" * (bound - 20) + '" '
    text = shrinking + CANARY + " trailing"
    cut = bound - len(shrinking)
    assert 0 < cut < len(CANARY)
    result = redact_text(text, registry=registry)
    assert CANARY[:cut] not in result
    assert CANARY[:4] not in result


def test_pre_truncation_tail_never_exposes_partial_secret(
    registry: SecretRegistry,
) -> None:
    bound = max(16 * 2048, 65536)
    tail = " " + "y" * (bound - 10)
    text = "leading " + CANARY + tail
    result = redact_text(text, registry=registry, keep="tail")
    assert CANARY[-4:] not in result
    assert result.startswith(TRUNCATED)


# Structured values


def test_structured_values(registry: SecretRegistry) -> None:
    value: dict[str, Any] = {
        "api_password": "plain-but-keyed",
        "headers": {"Authorization": "Bearer abc", "Accept": "application/json"},
        "items": [{"token": "t1"}, {"name": f"uses {CANARY}"}],
        "recipient": 2025550143,
        "count": 3,
        "ratio": 0.5,
        "nan": float("nan"),
        "flag": True,
        "nothing": None,
        "blob": b"\x00\x01",
        "tags": ("a", "b"),
        "url": "https://example.com/p?token=x",
        7: "int key",
    }
    result = redact_value(value, registry=registry)
    assert result == {
        "api_password": REDACTED,
        "headers": {"Authorization": REDACTED, "Accept": "application/json"},
        "items": [{"token": REDACTED}, {"name": f"uses {REDACTED}"}],
        "recipient": "***0143",
        "count": 3,
        "ratio": 0.5,
        "nan": "nan",
        "flag": True,
        "nothing": None,
        "blob": "[2 bytes]",
        "tags": ["a", "b"],
        "url": f"https://example.com/p?{REDACTED}",
        "7": "int key",
    }


def test_sets_and_objects(registry: SecretRegistry) -> None:
    class Thing:
        def __str__(self) -> str:
            return f"Thing({CANARY})"

    class Broken:
        def __str__(self) -> str:
            raise RuntimeError("boom")

    assert redact_value({"x"}, registry=registry) == ["x"]
    assert redact_value(Thing(), registry=registry) == f"Thing({REDACTED})"
    assert redact_value(Broken(), registry=registry) == "<unprintable Broken>"
    assert redact_value({Broken(): 1}, registry=registry) == {"<unprintable Broken>": 1}
    assert (
        redact_value(ValueError(CANARY), registry=registry) == f"ValueError: {REDACTED}"
    )


def test_huge_int_bounded() -> None:
    assert redact_value(10**5000, registry=SecretRegistry()) == TRUNCATED


def test_deep_nesting_bounded() -> None:
    nested: dict[str, Any] = {}
    node_ref = nested
    for _ in range(1000):
        node_ref["child"] = {}
        node_ref = node_ref["child"]
    result = redact_value(nested, registry=SecretRegistry())
    depth = 0
    node: Any = result
    while isinstance(node, dict):
        node = node["child"]
        depth += 1
    assert depth == MAX_DEPTH
    assert node == TRUNCATED


def test_cyclic_structure_bounded() -> None:
    cyclic: list[Any] = []
    cyclic.append(cyclic)
    result = redact_value(cyclic, registry=SecretRegistry())
    assert isinstance(result, list)


def test_wide_containers_bounded() -> None:
    wide_dict = {f"k{i}": i for i in range(10_000)}
    wide_list = list(range(10_000))
    dict_result = redact_value(wide_dict, registry=SecretRegistry())
    list_result = redact_value(wide_list, registry=SecretRegistry())
    assert isinstance(dict_result, dict)
    assert len(dict_result) == MAX_ITEMS + 1
    assert dict_result[TRUNCATED] == f"{10_000 - MAX_ITEMS} more items"
    assert isinstance(list_result, list)
    assert len(list_result) == MAX_ITEMS + 1
    assert list_result[-1] == f"{TRUNCATED} {10_000 - MAX_ITEMS} more items"


def test_total_node_budget() -> None:
    value = [[str(i) for i in range(MAX_ITEMS)] for _ in range(MAX_ITEMS)]
    result = redact_value(value, registry=SecretRegistry())
    assert isinstance(result, list)
    kept = [item for row in result if isinstance(row, list) for item in row]
    assert TRUNCATED in result or TRUNCATED in kept
    assert len([item for item in kept if item != TRUNCATED]) < MAX_NODES


def test_keys_are_bounded_and_escaped() -> None:
    result = redact_value({"k\n" + "x" * 500: 1}, registry=SecretRegistry())
    assert isinstance(result, dict)
    (key,) = result
    assert key.startswith("k\\nx")
    assert len(key) == 128


def test_redact_mapping_returns_dict(registry: SecretRegistry) -> None:
    assert redact_mapping({}, registry=registry) == {}
    assert redact_mapping({"token": "x", "n": CANARY}, registry=registry) == {
        "token": REDACTED,
        "n": REDACTED,
    }


def test_default_registry_used(monkeypatch: pytest.MonkeyPatch) -> None:
    fresh = SecretRegistry()
    monkeypatch.setattr(redaction_module, "default_registry", fresh)
    redaction_module.register_secret("fictitious-global-0003")
    assert redact_text("x fictitious-global-0003") == f"x {REDACTED}"
    assert redact_value(["fictitious-global-0003"]) == [REDACTED]

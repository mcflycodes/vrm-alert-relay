from __future__ import annotations

import base64
import json
import logging
import time
from collections.abc import Callable, Sequence
from typing import Any
from urllib.parse import quote, quote_plus

import pytest

from vrm_alert_relay.logs import (
    MAX_SECRET_LENGTH,
    MAX_SECRETS,
    REDACTED,
    JsonFormatter,
    SecretRegistrationError,
    SecretRegistry,
    SecretTooLongError,
    TooManySecretsError,
    contains_secret,
    mask_recipient,
    redact_mapping,
    redact_secrets,
    redact_text,
    redact_value,
    register_derived_secret,
)
from vrm_alert_relay.logs import redaction as redaction_module
from vrm_alert_relay.logs.lattice import Lattice, escape_edges
from vrm_alert_relay.logs.redaction import (
    MAX_AMBIGUOUS_CHARACTERS,
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
    assert redact_text("x fictitious-longer-value y", registry=registry) == f"x {REDACTED} y"


def redacts(secret: str, *rendered: str) -> None:
    registry = SecretRegistry()
    registry.register(secret)
    for text in rendered:
        result = redact_secrets(f"<{text}>", registry)
        assert result == f"<{REDACTED}>", text
        assert contains_secret(text, registry)


def test_reviewer_noncanonical_percent_repros() -> None:
    redacts(
        "fict /\\pass",
        "fict%20%2f%5Cpass",
        "fict%20%2F%5cpass",
        "fict+%2f%5Cpass",
        "fict%20/%5cpass",
        "%66%69%63%74%20%2F%5C%70%61%73%73",
    )


def test_unicode_escapes_in_either_case() -> None:
    redacts(
        "fictitiousé",
        "fictitiousé",
        "fictitious\\u00E9",
        "fictitious\\u00e9",
        "fictitious\\U00E9",
        "fictitious%C3%A9",
        "fictitious%c3%a9",
        "fictitious%C3%a9",
        "\\u0066\\u0069\\u0063\\u0074itious\\u00E9",
    )


def test_mixed_literal_and_escaped_characters() -> None:
    redacts(
        'fict"pa\\ss/x',
        'fict"pa\\ss/x',
        'fict\\"pa\\\\ss\\/x',
        "fict\\u0022pa%5Css/x",
        'f%69ct"pa\\\\ss%2fx',
        "fict%22pa\\u005Css\\u002fx",
    )


def test_optional_and_short_escapes() -> None:
    redacts("fict/pass", "fict\\/pass", "fict/pass", "fict%2Fpass")
    redacts("fict\tpass\n", "fict\\tpass\\n", "fict\\u0009pass\\u000A", "fict\\x09pass\\x0a")
    redacts("fict'pass", "fict\\'pass", "fict%27pass")


def test_surrogate_pairs_and_lone_surrogates() -> None:
    redacts(
        "fict\U0001f600pass",
        "fict\\ud83d\\ude00pass",
        "fict\\uD83D\\uDE00pass",
        "fict%F0%9F%98%80pass",
    )
    redacts("fict\ud800pass", "fict\\ud800pass", "fict\ud800pass")


def test_matcher_is_exact_about_letters() -> None:
    registry = SecretRegistry()
    registry.register("fictitious-pass")
    for text in (
        "FICTITIOUS-PASS",
        "fictitious-pas",
        "fictitious pass",
        "fictitious%2Bpass",
    ):
        assert redact_secrets(text, registry) == text
        assert not contains_secret(text, registry)


def test_secret_length_is_capped_in_characters() -> None:
    registry = SecretRegistry()
    largest = "f" + "é" * (MAX_SECRET_LENGTH - 1)
    registry.register(largest)
    assert redact_secrets(f"a {largest} b", registry) == f"a {REDACTED} b"
    with pytest.raises(SecretTooLongError, match="512 characters"):
        registry.register(largest + "x")
    assert issubclass(SecretTooLongError, SecretRegistrationError)
    assert issubclass(SecretRegistrationError, ValueError)
    assert len(registry.secrets) > 0
    assert largest + "x" not in registry.secrets


def test_number_of_secrets_is_capped() -> None:
    registry = SecretRegistry()
    values = [f"fictitious-secret-{index:04d}" for index in range(MAX_SECRETS)]
    for value in values:
        registry.register(value)
    registry.register(values[0])
    registry.register("short")
    with pytest.raises(TooManySecretsError, match="32 secrets"):
        registry.register("fictitious-secret-extra")
    assert issubclass(TooManySecretsError, SecretRegistrationError)
    assert redact_secrets(values[-1], registry) == REDACTED
    assert redact_secrets("fictitious-secret-extra", registry) == ("fictitious-secret-extra")
    registry.clear()
    registry.register("fictitious-secret-extra")
    assert redact_secrets("fictitious-secret-extra", registry) == REDACTED


def test_concurrent_registration_of_the_same_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = SecretRegistry()
    compile_matcher = redaction_module._compile_matcher
    nested = False

    def racing(value: str) -> Any:
        nonlocal nested
        matcher = compile_matcher(value)
        if not nested:
            nested = True
            registry.register(value)
        return matcher

    monkeypatch.setattr(redaction_module, "_compile_matcher", racing)
    registry.register("fictitious-pass")
    assert registry.secrets.count("fictitious-pass") == 1
    assert redact_secrets("x fictitious-pass", registry) == f"x {REDACTED}"


def test_trim_keeps_text_that_only_resembles_an_encoded_prefix(
    registry: SecretRegistry,
) -> None:
    encoded = base64.b64encode(CANARY.encode()).decode()
    lookalike = encoded[0] + "?"
    assert registry.trim_partial(lookalike + encoded[:5], "head") == lookalike


def test_lone_high_surrogate_escape_before_another_escape() -> None:
    assert escape_edges("\\ud83d\\u0041", 0) == [(6, "\ud83d")]
    assert escape_edges("\\ud83d\\n", 0) == [(6, "\ud83d")]


def test_repeated_registration_is_a_no_op() -> None:
    registry = SecretRegistry()
    registry.register("fictitious-pass")
    before = registry.secrets
    registry.register("fictitious-pass")
    assert registry.secrets == before


def test_backslashes_within_backtracking_budget_match_mixed_forms() -> None:
    value = "ab\\cd\\ef\\gh"
    assert value.count("\\") <= MAX_AMBIGUOUS_CHARACTERS
    redacts(
        value,
        "ab\\cd\\\\ef\\u005cgh",
        "ab\\\\cd\\ef%5Cgh",
        "ab\\x5ccd\\\\ef\\gh",
    )


def test_many_backslashes_use_non_backtracking_matcher() -> None:
    secret = "fict" + "\\" * (MAX_AMBIGUOUS_CHARACTERS + 1) + "pass"
    redacts(
        secret,
        secret,
        json.dumps(secret)[1:-1],
        repr(secret)[1:-1],
        quote(secret, safe=""),
        quote(secret, safe="").lower(),
    )
    registry = SecretRegistry()
    registry.register(secret)
    pattern = redaction_module._compile_matcher(secret).pattern.pattern
    assert pattern.count("(?>") == len(secret)
    assert "(?:" not in pattern
    hostile = ("fict" + "\\" * 5000 + "x") * 4
    assert registry._state.lattice.detect(hostile) == ([], False)
    assert redact_secrets(hostile, registry) == hostile


def test_known_limitation_escape_heavy_secret_in_mixed_spelling_is_missed() -> None:
    """Documents the known limitation in the redaction module docstring.

    Over ``MAX_AMBIGUOUS_CHARACTERS`` backslashes, the matcher takes each
    backslash literally whenever it can, so a spelling that escapes only
    some of them is not matched. If this starts failing because the value is
    now redacted, the limitation is fixed: update the docstring and this test.
    """
    secret = "fict" + "\\" * (MAX_AMBIGUOUS_CHARACTERS + 1) + "pass"
    registry = SecretRegistry()
    registry.register(secret)
    mixed = "fict" + "\\\\" + "\\" * MAX_AMBIGUOUS_CHARACTERS + "pass"
    unicode_mixed = "fict" + "\\u005c" + "\\" * MAX_AMBIGUOUS_CHARACTERS + "pass"
    for text in (mixed, unicode_mixed):
        assert redact_secrets(f"<{text}>", registry) == f"<{text}>"
        assert not contains_secret(text, registry)
    still_matched = "fict" + "%5C" + "\\" * MAX_AMBIGUOUS_CHARACTERS + "pass"
    assert redact_secrets(f"<{still_matched}>", registry) == f"<{REDACTED}>"


def test_known_limitation_fully_byte_encoded_safe_ascii_is_missed() -> None:
    """Documents the escape-heavy limitation for fully percent-encoded text.

    Canonical ``quote`` and ``quote_plus`` output, which leaves unreserved
    ASCII as it is, is matched; a spelling that also percent-encodes those
    characters is not. If this starts failing because the value is now
    redacted, update the module docstring and this test.
    """
    secret = "%" * (MAX_AMBIGUOUS_CHARACTERS + 1) + "abc"
    registry = SecretRegistry()
    registry.register(secret)
    for canonical in (
        secret,
        quote(secret, safe=""),
        quote_plus(secret, safe=""),
        quote(secret, safe="").lower(),
    ):
        assert redact_secrets(f"<{canonical}>", registry) == f"<{REDACTED}>"
    fully_encoded = "".join(f"%{byte:02X}" for byte in secret.encode())
    assert fully_encoded == "%25%25%25%25%25%25%25%61%62%63"
    for text in (fully_encoded, fully_encoded.lower()):
        assert redact_secrets(f"<{text}>", registry) == f"<{text}>"
        assert not contains_secret(text, registry)


def test_backtracking_is_bounded_for_hostile_input() -> None:
    """A secret within the backtracking budget is never regex-matched on hostile text.

    The per-secret regex may backtrack on runs of ``\\``; it only runs for
    secrets the linear-time lattice detects, and the lattice does not detect
    this one in text that does not contain it, so the cost is the lattice's.
    """
    secret = "fict" + "\\" * MAX_AMBIGUOUS_CHARACTERS + "pass"
    registry = SecretRegistry()
    registry.register(secret)
    hostile = ("fict" + "\\" * 5000 + "x") * 4
    detected, literal = registry._state.lattice.detect(hostile)
    assert (detected, literal) == ([], False)
    assert not any(form in hostile for form in registry._state.exact)
    assert redact_secrets(hostile, registry) == hostile
    assert not contains_secret(hostile, registry)


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
    result = redact_text("user=alice&password=hunter2-value&mode=sms", registry=SecretRegistry())
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
    result = redact_text("https://example.com/sms/2025550143/status", registry=SecretRegistry())
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
    hostile = "tokentokentoken" * 5000 + "1" * 5000 + "+1 " * 5000 + "password='" + "\\" * 5000
    start = time.perf_counter()
    redact_text(hostile, registry=SecretRegistry(), max_length=100_000)
    assert time.perf_counter() - start < 2.0


def test_cut_never_exposes_partial_secret(registry: SecretRegistry) -> None:
    shrinking = 'password="' + "x" * (2048 - 20) + '" '
    text = shrinking + CANARY + " trailing"
    cut = 2048 - len(shrinking)
    assert 0 < cut < len(CANARY)
    result = redact_text(text, registry=registry)
    assert result == f'password="{REDACTED}" {TRUNCATED}'


def test_cut_tail_never_exposes_partial_secret(registry: SecretRegistry) -> None:
    tail = " " + "y" * (2048 - 10)
    text = "leading " + CANARY + tail
    result = redact_text(text, registry=registry, keep="tail")
    assert result == TRUNCATED + tail[-(2048 - len(TRUNCATED)) :]
    assert CANARY[-4:] not in result


def _percent_all(value: str) -> str:
    return "".join(f"%{byte:02x}" for byte in value.encode())


def _unicode_all(value: str) -> str:
    return "".join(f"\\u{ord(char):04X}" for char in value)


ENCODINGS = [_percent_all, _unicode_all, lambda value: value.replace("-", "%2D")]


@pytest.mark.parametrize("encode", ENCODINGS)
@pytest.mark.parametrize("fraction", [0.0, 0.2, 0.5, 0.99])
def test_cut_drops_encoded_partial_secret_at_head(
    registry: SecretRegistry, encode: Any, fraction: float
) -> None:
    encoded = encode(CANARY)
    inside = max(1, int(len(encoded) * fraction))
    filler = "y" * (2048 - inside - 1) + " "
    result = redact_text(filler + encoded + " after", registry=registry)
    assert result == filler[: 2048 - len(TRUNCATED)] + TRUNCATED


@pytest.mark.parametrize("encode", ENCODINGS)
@pytest.mark.parametrize("fraction", [0.0, 0.2, 0.5, 0.99])
def test_cut_drops_encoded_partial_secret_at_tail(
    registry: SecretRegistry, encode: Any, fraction: float
) -> None:
    encoded = encode(CANARY)
    inside = max(1, int(len(encoded) * fraction))
    tail = " " + "y" * (2048 - inside - 1)
    result = redact_text("before " + encoded + tail, registry=registry, keep="tail")
    assert result == TRUNCATED + tail[-(2048 - len(TRUNCATED)) :]


@pytest.mark.parametrize("keep", ["head", "tail"])
def test_cut_drops_partial_base64_secret(registry: SecretRegistry, keep: Any) -> None:
    encoded = base64.b64encode(CANARY.encode()).decode()
    shrinking = 'password="' + "x" * (2048 - 30) + '"'
    if keep == "head":
        text = shrinking + " " + encoded
        expected = f'password="{REDACTED}" {TRUNCATED}'
    else:
        text = encoded + " " + shrinking
        expected = f'{TRUNCATED} password="{REDACTED}"'
    assert redact_text(text, registry=registry, keep=keep) == expected


def test_cut_moves_out_of_sensitive_values() -> None:
    registry = SecretRegistry()
    keyed = 'password="' + "s" * 100 + '" '
    tail_text = keyed + "z" * (2048 - 50)
    result = redact_text(tail_text, registry=registry, keep="tail")
    assert "s" not in result
    phone = "call +1 202 555 0143 "
    head_text = "z" * (2048 - 8) + phone
    assert "202" not in redact_text(head_text, registry=registry)
    tail_phone = phone + "z" * (2048 - 8)
    assert "0143" not in redact_text(tail_phone, registry=registry, keep="tail")
    url = "https://user:fictitious@example.com/?q=1 "
    assert "user" not in redact_text("z" * (2048 - 12) + url, registry=registry)


CONTEXT = redaction_module._CUT_CONTEXT


def kept(text: str, position: int) -> str:
    return text[redaction_module._tail_start(text, position) :]


def test_tail_start_keeps_positions_outside_sensitive_values() -> None:
    assert kept("plain words\nnext line", 12) == "next line"
    assert kept("plain words and more", 8) == "rds and more"
    assert kept("Zq" * 10, 5) == ("Zq" * 10)[5:]
    long_run = "Zq" * 1000
    assert kept(long_run, 1500) == long_run[1500:]
    assert kept("it's fine\nZq more", 11) == "q more"


def test_tail_start_moves_past_line_bound_values() -> None:
    text = "x password=Zq123Zq after"
    assert kept(text, text.index("123")) == " after"
    header = "Authorization: Bearer " + "Zq" * 2000 + "\nnext"
    assert kept(header, 100) == "next"
    url = "see https://example.test/?token=" + "Zq" * 100
    assert kept(url, len(url) - 50) == ""
    assert redact_text(url, registry=SecretRegistry(), max_length=60, keep="tail") == (TRUNCATED)


def test_tail_start_drops_overlong_lines() -> None:
    line = "a" * (redaction_module._MAX_LINE_SCAN + 10)
    assert kept(line + "tail", len(line) - 5) == ""
    assert kept(line + "\nnext", len(line) - 5) == "next"


def test_tail_start_moves_past_open_quoted_values() -> None:
    text = 'password="' + "A" * 10 + "\n" + "Zq" * 10 + '" after'
    assert kept(text, text.index("Zq") + 3) == " after"
    escaped = 'password="a\\"b\nZqZq\\"Zq" after'
    assert kept(escaped, escaped.index("ZqZq") + 2) == " after"
    unclosed = 'password="' + "A" * 10 + "\n" + "Zq" * 10
    assert kept(unclosed, unclosed.index("Zq") + 3) == ""


def test_tail_start_treats_unknown_escapes_as_open() -> None:
    long_run = "x" + "\\" * (CONTEXT + 5) + '"' + "\nZq"
    assert kept(long_run, len(long_run) - 1) == ""
    many = 'password="' + '\\"' * (redaction_module._MAX_QUOTE_CANDIDATES + 5)
    many += "\nZq"
    assert kept(many, len(many) - 1) == ""


def test_tail_start_moves_past_values_after_multiline_separators() -> None:
    text = "token=\n\n   " + "Zq" * 50 + " after"
    assert kept(text, text.index("Zq") + 9) == " after"
    split = "secret\n=" + "Zq" * 20 + " after"
    assert kept(split, split.index("Zq") + 9) == " after"
    spaced = "token=" + "\n" * (CONTEXT + 50) + "Zq" * 20 + " after"
    assert kept(spaced, spaced.index("Zq") + 9) == " after"
    quoted = "password=" + "\n" * (CONTEXT + 50) + '"' + "Zq" * 20 + "\nZq" + '" after'
    assert kept(quoted, len(quoted) - 9) == " after"


def test_bare_value_without_a_line_start_in_reach_is_undecidable() -> None:
    line = "Zq" * redaction_module._MAX_LINE_SCAN
    text = "token=\n" + line + "\nnext"
    position = len("token=\n") + len(line) - 10
    assert redaction_module._after_open_bare_value(text, position) == text.index("next")
    assert redaction_module._after_open_bare_value(line, len(line) - 10) == len(line)


def test_forward_quote_scan_is_bounded_by_work(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    escaped = redaction_module._escaped

    def counting(text: str, index: int) -> bool | None:
        nonlocal calls
        calls += 1
        return escaped(text, index)

    monkeypatch.setattr(redaction_module, "_escaped", counting)
    text = 'password="\n' + "A" * 1500 + '\\"' * 20_000
    result = redact_text(text, registry=SecretRegistry(), max_length=len(text) - 1200, keep="tail")
    assert result == TRUNCATED
    assert 0 < calls <= 2 * redaction_module._MAX_QUOTE_CANDIDATES


def test_tail_start_withholds_after_too_many_moves(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = 'password="' + "A" * 10 + "\n" + "Zq" * 10 + '" after'
    monkeypatch.setattr(redaction_module, "_MAX_TAIL_STEPS", 1)
    assert kept(text, text.index("Zq") + 3) == ""


def test_tail_truncation_inside_long_values_is_fast() -> None:
    hostile = ('token="' + "\\" * 3 + "Zq " * 30 + "\n") * 2000
    start = time.perf_counter()
    for keep_from in range(0, len(hostile), len(hostile) // 50):
        kept(hostile, keep_from)
    redact_text(hostile, registry=SecretRegistry(), keep="tail")
    assert time.perf_counter() - start < 2.0


class _Sample:
    """Reproducible pseudo-random choices for generated test data (a 64-bit LCG)."""

    def __init__(self, seed: int) -> None:
        self._state = seed

    def randint(self, low: int, high: int) -> int:
        self._state = (self._state * 6364136223846793005 + 1442695040888963407) % 2**64
        return low + (self._state >> 33) % (high - low + 1)

    def choice[T](self, items: Sequence[T]) -> T:
        return items[self.randint(0, len(items) - 1)]


def test_detection_finds_every_regex_match() -> None:
    rng = _Sample(20261011)
    alphabet = "ab\\%u0+ é/\U0001f600"
    for _ in range(300):
        secret = "".join(rng.choice(alphabet) for _ in range(rng.randint(6, 10)))
        forms: list[Callable[[str], str]] = [
            lambda char: char,
            lambda char: "".join(f"%{byte:02X}" for byte in char.encode("utf-8")),
            lambda char: json.dumps(char)[1:-1],
            lambda char: json.dumps(char, ensure_ascii=True)[1:-1].upper(),
            lambda char: f"\\x{ord(char):02x}" if ord(char) < 0x100 else char,
            lambda char: "+" if char == " " else char,
        ]
        noise = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 8)))
        spelled = "".join(rng.choice(forms)(char) for char in secret)
        text = noise + spelled + noise[::-1]
        matcher = redaction_module._compile_matcher(secret)
        hit = matcher.pattern.search(text) is not None
        detected, _ = Lattice([secret]).detect(text)
        assert not hit or detected == [0], (secret, text)
        registry = SecretRegistry()
        registry.register(secret)
        assert contains_secret(text, registry) == (
            hit or any(form in text for form in matcher.exact)
        )


def test_matching_cost_is_bounded_with_full_registry() -> None:
    registry = SecretRegistry()
    stems = "bcdefghijklmnopqrstuvwxyz0123456"
    for stem in stems[:MAX_SECRETS]:
        registry.register("%a\\" + "a" * (MAX_SECRET_LENGTH - 4) + stem)
    near = "%a\\" + "a" * (MAX_SECRET_LENGTH - 4)
    hostile = (near * 70)[:65536]
    formatter = JsonFormatter(registry=registry)
    record = logging.LogRecord("relay", logging.INFO, __file__, 1, "%s", (hostile,), None)
    started = time.perf_counter()
    line = formatter.format(record)
    elapsed = time.perf_counter() - started
    print(f"near-prefix record with full registry formatted in {elapsed:.3f} s")
    assert elapsed < 0.25
    assert json.loads(line)["msg"].endswith(TRUNCATED)


# Structured values


def test_structured_values(registry: SecretRegistry) -> None:
    value: dict[object, Any] = {
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
    assert redact_value(ValueError(CANARY), registry=registry) == f"ValueError: {REDACTED}"


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

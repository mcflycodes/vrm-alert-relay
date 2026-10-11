"""Redaction of secrets, URLs, phone numbers and control characters.

Applied, in this order, to every string that reaches a log line:

1. values registered with :func:`register_secret` or
   :func:`register_derived_secret` (see below);
2. URL userinfo, query strings and fragments;
3. values of sensitive keys (``password=...``, ``"token": "..."``,
   ``Authorization: Bearer ...``);
4. phone-number-like sequences, masked to their last four digits;
5. control and bidirectional-override characters, escaped;
6. truncation to a bounded length.

Structured values (mappings, sequences) are redacted recursively with bounded
depth, item count and total size, and values under sensitive keys are replaced
outright.

Registered secrets
------------------

Each secret is compiled at registration into a matcher that accepts, for
every character independently, the literal character or any of its
encodings: percent-encoding of its UTF-8 bytes (hex in either case, ``+``
for a space), a JSON ``\\uXXXX`` escape (hex in either case, surrogate pairs
for characters outside the BMP), a JSON short escape (``\\"``, ``\\\\``,
``\\/``, ``\\n`` and so on) and the Python ``repr`` escapes ``\\'`` and
``\\xNN``. Mixed and noncanonical encodings therefore still match. The
standard and URL-safe base64 of the whole value, padded and unpadded, are
matched exactly.

A literal ``\\`` or ``%`` can also begin an escape, so matching those
characters can backtrack. To keep matching time bounded, a secret with more
than ``MAX_AMBIGUOUS_CHARACTERS`` of them gets a matcher that never
backtracks, plus exact matches of its canonical ``repr``, JSON and URL
encodings.

Encodings of a composite value are not built from the encodings of its
parts: base64 of ``user:password`` does not contain base64 of ``password``.
Adapters must register every credential they derive, such as
``f"{user}:{password}"`` for HTTP Basic, a full ``Authorization`` value or a
signature, with :func:`register_derived_secret`.
"""

from __future__ import annotations

import base64
import json
import math
import re
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Literal
from urllib.parse import quote, quote_plus

REDACTED: Final = "[REDACTED]"
TRUNCATED: Final = "[TRUNCATED]"
MIN_SECRET_LENGTH: Final = 6
MAX_SECRET_BYTES: Final = 4096
MAX_AMBIGUOUS_CHARACTERS: Final = 6
DEFAULT_MAX_FIELD_LENGTH: Final = 2048
MAX_DEPTH: Final = 6
MAX_ITEMS: Final = 50
MAX_NODES: Final = 500
MAX_KEY_LENGTH: Final = 128

_SENSITIVE_KEY = r"(?:password|passwd|secret|token|authorization|api[_-]?key|api[_-]?password|cookie)"
_SENSITIVE_KEY_RE = re.compile(_SENSITIVE_KEY, re.IGNORECASE)
_KEY_TEXT = rf"{_SENSITIVE_KEY}[\w-]{{0,32}}"
_QUOTED_KV_RE = re.compile(
    rf"(?P<key>{_KEY_TEXT})(?P<sep>[\"']?\s*[:=]\s*)(?P<q>[\"'])"
    r"(?:\\.|(?!(?P=q))[^\\])*(?:(?P=q)|\Z)",
    re.IGNORECASE,
)
_HEADER_KV_RE = re.compile(
    r"(?P<key>(?:proxy-)?authorization|(?:set-)?cookie)(?P<sep>[ \t]*:[ \t]*)(?![\"'\s])[^\r\n]+",
    re.IGNORECASE,
)
_BARE_KV_RE = re.compile(
    rf"(?P<key>{_KEY_TEXT})(?P<sep>[\"']?\s*[:=]\s*[\"']?)(?!\[REDACTED\])"
    r"(?:(?:bearer|basic|digest|token)\s+)?[^\s\"'&,;)}\]]+",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]{0,15}://[^\s\"'<>`]+")
_PHONE_RE = re.compile(
    r"""
    (?<![\w+*.\-])
    (?:
        \+\d{1,3}(?:[ .\-]?\(?\d{1,4}\)?){2,5}
      | (?:1[ .\-]?)?(?:\(\d{3}\)[ .\-]?|\d{3}[ .\-]?)\d{3}[ .\-]?\d{4}
      | \d{10,15}
    )
    (?!\w)
    """,
    re.VERBOSE,
)
_PHONEISH_RE = re.compile(r"\+?[\d\s().\-]+")
_NON_DIGIT_RE = re.compile(r"\D")
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-F]{2}")
_BACKSLASH_ESCAPES: Final = {
    '"': '\\"',
    "\\": "\\\\",
    "/": "\\/",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "'": "\\'",
}
_AMBIGUOUS: Final = frozenset("\\%")

_ESCAPES: dict[int, str] = {code: f"\\x{code:02x}" for code in range(0x20)}
_ESCAPES.update({code: f"\\x{code:02x}" for code in range(0x7F, 0xA0)})
_ESCAPES.update({ord("\n"): "\\n", ord("\r"): "\\r", ord("\t"): "\\t"})
_ESCAPES.update(
    {
        code: f"\\u{code:04x}"
        for code in (
            0x200E,
            0x200F,
            0x2028,
            0x2029,
            *range(0x202A, 0x202F),
            *range(0x2066, 0x206A),
        )
    }
)

Keep = Literal["head", "tail"]


@dataclass(frozen=True, slots=True)
class _Matcher:
    pattern: re.Pattern[str]
    exact: frozenset[str]


class SecretRegistry:
    """A thread-safe set of secrets to redact. See the module docstring."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._matchers: dict[str, _Matcher] = {}
        self._patterns: tuple[re.Pattern[str], ...] = ()
        self._exact: tuple[str, ...] = ()
        self._secrets: tuple[str, ...] = ()

    def register(self, value: str) -> None:
        """Redact ``value`` in any encoding. Values under six characters are ignored.

        Raises :class:`ValueError` for values over ``MAX_SECRET_BYTES`` in
        UTF-8, which bounds the size of the compiled matcher.
        """
        if not isinstance(value, str):
            raise TypeError("secret must be a string")
        if len(value) < MIN_SECRET_LENGTH:
            return
        if len(value.encode("utf-8", "surrogatepass")) > MAX_SECRET_BYTES:
            raise ValueError(f"secret exceeds {MAX_SECRET_BYTES} bytes")
        if value in self._matchers:
            return
        matcher = _compile_matcher(value)
        with self._lock:
            self._matchers[value] = matcher
            values = sorted(self._matchers, key=len, reverse=True)
            matchers = [self._matchers[secret] for secret in values]
            exact = {form for entry in matchers for form in entry.exact}
            self._patterns = tuple(entry.pattern for entry in matchers)
            self._exact = tuple(sorted(exact, key=len, reverse=True))
            self._secrets = tuple(sorted(exact | set(values), key=len, reverse=True))

    def clear(self) -> None:
        with self._lock:
            self._matchers = {}
            self._patterns = ()
            self._exact = ()
            self._secrets = ()

    @property
    def secrets(self) -> tuple[str, ...]:
        """Registered values and their exact-match encodings, longest first."""
        return self._secrets

    def redact(self, text: str) -> str:
        """Replace every match of a registered secret with ``[REDACTED]``."""
        for form in self._exact:
            if form in text:
                text = text.replace(form, REDACTED)
        for pattern in self._patterns:
            text = pattern.sub(REDACTED, text)
        return text

    def contains(self, text: str) -> bool:
        """Whether ``text`` contains a registered secret in any matched encoding."""
        return any(form in text for form in self._exact) or any(
            pattern.search(text) for pattern in self._patterns
        )


default_registry = SecretRegistry()


def register_secret(value: str) -> None:
    """Register a configured credential with the process-wide registry."""
    default_registry.register(value)


def register_derived_secret(value: str) -> None:
    """Register a credential computed from configured secrets.

    Composite values such as ``f"{user}:{password}"`` must be registered
    themselves, in addition to the configured secret: see the module
    docstring.
    """
    default_registry.register(value)


def redact_secrets(text: str, registry: SecretRegistry | None = None) -> str:
    """Replace registered secrets only; no other redaction step."""
    return (registry or default_registry).redact(text)


def contains_secret(text: str, registry: SecretRegistry | None = None) -> bool:
    return (registry or default_registry).contains(text)


def _compile_matcher(value: str) -> _Matcher:
    raw = value.encode("utf-8", "surrogatepass")
    exact: set[str] = set()
    for b64 in (base64.b64encode(raw), base64.urlsafe_b64encode(raw)):
        text = b64.decode("ascii")
        exact.update((text, text.rstrip("=")))
    backtracking = sum(char in _AMBIGUOUS for char in value) <= MAX_AMBIGUOUS_CHARACTERS
    if not backtracking:
        exact.update(_canonical_encodings(value))
    groups = []
    for char in value:
        alternatives = "|".join(_character_forms(char))
        if backtracking and char in _AMBIGUOUS:
            groups.append(f"(?:{alternatives})")
        else:
            groups.append(f"(?>{alternatives})")
    return _Matcher(
        pattern=re.compile("".join(groups)),
        exact=frozenset(form for form in exact if len(form) >= MIN_SECRET_LENGTH),
    )


def _character_forms(char: str) -> list[str]:
    """Regex alternatives for one character. Only ``\\`` and ``%`` overlap."""
    code = ord(char)
    forms = [
        re.escape(char),
        "".join(
            "%" + _hex_pattern(f"{byte:02X}")
            for byte in char.encode("utf-8", "surrogatepass")
        ),
    ]
    if char == " ":
        forms.append(r"\+")
    if code > 0xFFFF:
        offset = code - 0x10000
        units = [0xD800 + (offset >> 10), 0xDC00 + (offset & 0x3FF)]
    else:
        units = [code]
    forms.append("".join(r"\\[uU]" + _hex_pattern(f"{unit:04X}") for unit in units))
    if code < 0x100:
        forms.append(r"\\x" + _hex_pattern(f"{code:02X}"))
    if char in _BACKSLASH_ESCAPES:
        forms.append(re.escape(_BACKSLASH_ESCAPES[char]))
    return forms


def _hex_pattern(digits: str) -> str:
    return "".join(
        f"[{digit}{digit.lower()}]" if digit.isalpha() else digit for digit in digits
    )


def _canonical_encodings(value: str) -> set[str]:
    encodings = {
        repr(value)[1:-1],
        json.dumps(value)[1:-1],
        json.dumps(value, ensure_ascii=False)[1:-1],
    }
    for encoded in (
        quote(value, safe="", errors="surrogatepass"),
        quote_plus(value, safe="", errors="surrogatepass"),
    ):
        encodings.add(encoded)
        encodings.add(
            _PERCENT_ESCAPE_RE.sub(lambda match: match.group(0).lower(), encoded)
        )
    return encodings


def is_sensitive_key(key: str) -> bool:
    return _SENSITIVE_KEY_RE.search(key) is not None


def escape_controls(text: str) -> str:
    """Escape control and bidirectional-override characters as visible text."""
    return text.translate(_ESCAPES)


def truncate(text: str, limit: int, *, keep: Keep = "head") -> str:
    if len(text) <= limit:
        return text
    room = max(limit - len(TRUNCATED), 0)
    if keep == "tail":
        return TRUNCATED + (text[-room:] if room else "")
    return text[:room] + TRUNCATED


def mask_phone_numbers(text: str) -> str:
    return _PHONE_RE.sub(_mask_phone_match, text)


def mask_recipient(value: object) -> str:
    """Mask a recipient identifier to its last four characters, e.g. ``***0123``.

    Phone-number-like values keep their last four digits; anything else keeps
    its last four characters. Values of four characters or fewer are fully
    masked.
    """
    text = (value if isinstance(value, str) else str(value)).strip()
    digits = _NON_DIGIT_RE.sub("", text)
    if len(digits) >= 7 and _PHONEISH_RE.fullmatch(text):
        return "***" + digits[-4:]
    if len(text) <= 4:
        return "***"
    return "***" + escape_controls(text[-4:])


def redact_text(
    text: str,
    *,
    registry: SecretRegistry | None = None,
    max_length: int = DEFAULT_MAX_FIELD_LENGTH,
    keep: Keep = "head",
) -> str:
    """Apply every redaction step to ``text`` and bound its length."""
    registry = registry or default_registry
    text = _pre_truncate(text, max_length, keep, registry.secrets)
    text = redact_secrets(text, registry)
    text = _URL_RE.sub(_redact_url_match, text)
    text = _QUOTED_KV_RE.sub(_redact_quoted_match, text)
    text = _HEADER_KV_RE.sub(_redact_kv_match, text)
    text = _BARE_KV_RE.sub(_redact_kv_match, text)
    text = mask_phone_numbers(text)
    return truncate(escape_controls(text), max_length, keep=keep)


JsonValue = None | bool | int | float | str | list["JsonValue"] | dict[str, "JsonValue"]


def redact_value(
    value: object,
    *,
    registry: SecretRegistry | None = None,
    max_length: int = DEFAULT_MAX_FIELD_LENGTH,
) -> JsonValue:
    """Redact a structured value into JSON-serializable data with bounded size."""
    return _Redactor(registry or default_registry, max_length).value(value, 0)


def redact_mapping(
    value: Mapping[str, object],
    *,
    registry: SecretRegistry | None = None,
    max_length: int = DEFAULT_MAX_FIELD_LENGTH,
) -> dict[str, JsonValue]:
    """Like :func:`redact_value` for a mapping, always returning a dict."""
    return _Redactor(registry or default_registry, max_length).mapping(value, 0)


class _Redactor:
    def __init__(self, registry: SecretRegistry, max_length: int) -> None:
        self._registry = registry
        self._max_length = max_length
        self._nodes = MAX_NODES

    def text(self, text: str, max_length: int | None = None) -> str:
        limit = self._max_length if max_length is None else max_length
        return redact_text(text, registry=self._registry, max_length=limit)

    def value(self, value: object, depth: int) -> JsonValue:
        if self._nodes <= 0:
            return TRUNCATED
        self._nodes -= 1
        if value is None or isinstance(value, bool):
            return value
        if isinstance(value, int):
            return self._int(value)
        if isinstance(value, float):
            if not math.isfinite(value):
                return str(value)
            return REDACTED if self._registry.contains(repr(value)) else value
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, bytes | bytearray | memoryview):
            return f"[{len(value)} bytes]"
        if isinstance(value, Mapping):
            return self._mapping(value, depth)
        if isinstance(value, list | tuple | set | frozenset):
            return self._sequence(value, len(value), depth)
        if isinstance(value, BaseException):
            return self.text(f"{type(value).__name__}: {_safe_str(value)}")
        return self.text(_safe_str(value))

    def _int(self, value: int) -> int | str:
        try:
            text = str(value)
        except ValueError:
            return TRUNCATED
        redacted = self.text(text)
        return value if redacted == text else redacted

    def _mapping(self, value: Mapping[object, object], depth: int) -> JsonValue:
        if depth >= MAX_DEPTH:
            return TRUNCATED
        return self.mapping(value, depth)

    def mapping(self, value: Mapping[Any, object], depth: int) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= MAX_ITEMS:
                result[TRUNCATED] = f"{len(value) - MAX_ITEMS} more items"
                break
            raw_key = key if isinstance(key, str) else _safe_str(key)
            safe_key = self.text(raw_key, MAX_KEY_LENGTH)
            if is_sensitive_key(raw_key):
                self._nodes -= 1
                result[safe_key] = REDACTED
            else:
                result[safe_key] = self.value(item, depth + 1)
        return result

    def _sequence(self, items: Iterable[object], size: int, depth: int) -> JsonValue:
        if depth >= MAX_DEPTH:
            return TRUNCATED
        result: list[JsonValue] = []
        for index, item in enumerate(items):
            if index >= MAX_ITEMS:
                result.append(f"{TRUNCATED} {size - MAX_ITEMS} more items")
                break
            result.append(self.value(item, depth + 1))
        return result


def _safe_str(value: object) -> str:
    try:
        return str(value)
    except Exception:  # noqa: BLE001 - arbitrary __str__ implementations
        return f"<unprintable {type(value).__name__}>"


def _pre_truncate(
    text: str, max_length: int, keep: Keep, secrets: tuple[str, ...]
) -> str:
    """Bound regex work on huge inputs without exposing a partial secret at the cut."""
    bound = max(16 * max_length, 65536)
    if len(text) <= bound:
        return text
    if keep == "tail":
        text = text[-bound:]
        for secret in secrets:
            for size in range(min(len(secret), len(text)) - 1, 0, -1):
                if text.startswith(secret[-size:]):
                    text = text[size:]
                    break
        return text
    text = text[:bound]
    for secret in secrets:
        for size in range(min(len(secret), len(text)) - 1, 0, -1):
            if text.endswith(secret[:size]):
                text = text[:-size]
                break
    return text


def _redact_url_match(match: re.Match[str]) -> str:
    url = match.group(0)
    scheme, rest = url.split("://", 1)
    authority_end = len(rest)
    for marker in "/?#":
        position = rest.find(marker)
        if position != -1:
            authority_end = min(authority_end, position)
    authority, remainder = rest[:authority_end], rest[authority_end:]
    if "@" in authority:
        authority = f"{REDACTED}@{authority.rsplit('@', 1)[1]}"
    cut = len(remainder)
    for marker in "?#":
        position = remainder.find(marker)
        if position != -1:
            cut = min(cut, position)
    if cut < len(remainder):
        remainder = f"{remainder[:cut]}?{REDACTED}"
    return f"{scheme}://{authority}{remainder}"


def _redact_quoted_match(match: re.Match[str]) -> str:
    quote_char = match.group("q")
    return f"{match.group('key')}{match.group('sep')}{quote_char}{REDACTED}{quote_char}"


def _redact_kv_match(match: re.Match[str]) -> str:
    return f"{match.group('key')}{match.group('sep')}{REDACTED}"


def _mask_phone_match(match: re.Match[str]) -> str:
    digits = _NON_DIGIT_RE.sub("", match.group(0))
    if len(digits) < 8:
        return match.group(0)
    return "***" + digits[-4:]

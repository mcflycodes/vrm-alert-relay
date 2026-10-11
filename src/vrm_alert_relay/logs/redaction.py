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

A string longer than its limit is cut to the limit before step 1, so
matching cost is bounded by the field limit. Any part of a secret that runs
across the cut (in any matched encoding) is dropped with it. When the tail is
kept, a cut that may fall inside a sensitive value moves forward past the
value's end, or to the next line or closing quote when its start lies outside
the examined context; if there is none, the whole field is withheld.

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

At most ``MAX_SECRETS`` values of at most ``MAX_SECRET_LENGTH`` characters
can be registered; :class:`TooManySecretsError` and
:class:`SecretTooLongError` are raised beyond that. Secrets are first
detected in linear time by :mod:`vrm_alert_relay.logs.lattice`, and only
detected secrets are located with their matcher.

Known limitation: a literal ``\\`` or ``%`` can also begin an escape, so
matching those characters can backtrack. A secret with more than
``MAX_AMBIGUOUS_CHARACTERS`` of them gets a matcher that never backtracks:
at each ``\\`` or ``%`` of the secret it takes the literal character
whenever the text has one there. Such a secret is therefore missed when the
text spells some of those characters with an encoding that itself starts
with ``\\`` or ``%`` (``\\\\``, ``\\u005c`` or ``\\x5c`` for ``\\``;
``%25`` for ``%``) while spelling other characters differently, for
example the secret ``"fict" + "\\\\" * 7 + "pass"`` written with only its
first backslash JSON-escaped. Spellings that are entirely literal, that are
the exact output of ``repr``, ``json.dumps`` (with or without
``ensure_ascii``) or urllib's ``quote`` and ``quote_plus`` (percent hex in
either case), or that encode ``\\`` as ``%5C`` and ``%`` as ``\\u0025`` are
still matched. Those encoders leave unreserved ASCII such as letters and
digits as they are; a spelling that also encodes those characters is part of
this limitation, so the secret ``"%%%%%%%abc"`` written fully byte-encoded as
``%25%25%25%25%25%25%25%61%62%63`` is missed.

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
from typing import Any, Final, Literal, cast
from urllib.parse import quote, quote_plus

from vrm_alert_relay.logs.lattice import Lattice

REDACTED: Final = "[REDACTED]"
TRUNCATED: Final = "[TRUNCATED]"
MIN_SECRET_LENGTH: Final = 6
MAX_SECRET_LENGTH: Final = 512
MAX_SECRETS: Final = 32
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
_CUT_PATTERNS: Final = (_URL_RE, _QUOTED_KV_RE, _HEADER_KV_RE, _BARE_KV_RE, _PHONE_RE)
_CUT_CONTEXT: Final = 1024
_MAX_TAIL_STEPS: Final = 32
_MAX_LINE_SCAN: Final = 8 * _CUT_CONTEXT
_MAX_QUOTE_CANDIDATES: Final = 64
_SCHEME = r"(?:bearer|basic|digest|token)"
_BARE_STOP_RE = re.compile(r"[\s\"'&,;)}\]]")
_QUOTED_OPEN_RE = re.compile(rf"{_KEY_TEXT}[\"']?\s*[:=]\s*\Z", re.IGNORECASE)
_BARE_OPEN_RE = re.compile(
    rf"{_KEY_TEXT}[\"']?\s*[:=]\s*[\"']?(?:{_SCHEME}\s+)?\Z", re.IGNORECASE
)
_KEY_END_RE = re.compile(rf"{_KEY_TEXT}[\"']?\s*\Z", re.IGNORECASE)
_OPEN_TAIL_RE = re.compile(
    rf"[\w-]{{0,64}}[\"']?\s*(?:[:=]\s*[\"']?)?(?:{_SCHEME}\s+)?", re.IGNORECASE
)
_BARE_REST_RE = re.compile(
    rf"[\"']?\s*(?:[:=]\s*[\"']?)?(?:{_SCHEME}\s+)?[^\s\"'&,;)}}\]]*", re.IGNORECASE
)
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


class SecretRegistrationError(ValueError):
    """A secret could not be registered."""


class SecretTooLongError(SecretRegistrationError):
    """The value exceeds ``MAX_SECRET_LENGTH`` characters."""


class TooManySecretsError(SecretRegistrationError):
    """``MAX_SECRETS`` values are already registered."""


@dataclass(frozen=True, slots=True)
class _Matcher:
    pattern: re.Pattern[str]
    exact: frozenset[str]


@dataclass(frozen=True, slots=True)
class _State:
    values: tuple[str, ...]
    patterns: tuple[re.Pattern[str], ...]
    exact: tuple[str, ...]
    secrets: tuple[str, ...]
    lattice: Lattice


_EMPTY = _State((), (), (), (), Lattice(()))


class SecretRegistry:
    """A thread-safe set of secrets to redact. See the module docstring."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._matchers: dict[str, _Matcher] = {}
        self._state = _EMPTY

    def register(self, value: str) -> None:
        """Redact ``value`` in any encoding. Values under six characters are ignored.

        Raises :class:`SecretTooLongError` for values over
        ``MAX_SECRET_LENGTH`` characters and :class:`TooManySecretsError` when
        ``MAX_SECRETS`` other values are registered. Registering a value
        again does nothing.
        """
        if not isinstance(value, str):
            raise TypeError("secret must be a string")
        if len(value) < MIN_SECRET_LENGTH:
            return
        if len(value) > MAX_SECRET_LENGTH:
            raise SecretTooLongError(f"secret exceeds {MAX_SECRET_LENGTH} characters")
        with self._lock:
            if value in self._matchers:
                return
            self._check_capacity()
        matcher = _compile_matcher(value)
        with self._lock:
            if value in self._matchers:
                return
            self._check_capacity()
            self._matchers[value] = matcher
            self._state = _build_state(self._matchers)

    def _check_capacity(self) -> None:
        if len(self._matchers) >= MAX_SECRETS:
            raise TooManySecretsError(
                f"at most {MAX_SECRETS} secrets can be registered"
            )

    def clear(self) -> None:
        with self._lock:
            self._matchers = {}
            self._state = _EMPTY

    @property
    def secrets(self) -> tuple[str, ...]:
        """Registered values and their exact-match encodings, longest first."""
        return self._state.secrets

    def redact(self, text: str) -> str:
        """Replace every match of a registered secret with ``[REDACTED]``."""
        state = self._state
        for form in state.exact:
            if form in text:
                text = text.replace(form, REDACTED)
        detected, literal = state.lattice.detect(text)
        for index in detected:
            if literal:
                text = text.replace(state.values[index], REDACTED)
            else:
                text = state.patterns[index].sub(REDACTED, text)
        return text

    def contains(self, text: str) -> bool:
        """Whether ``text`` contains a registered secret in any matched encoding."""
        state = self._state
        if any(form in text for form in state.exact):
            return True
        detected, literal = state.lattice.detect(text)
        if literal:
            return bool(detected)
        return any(state.patterns[index].search(text) for index in detected)

    def trim_partial(self, text: str, keep: Keep) -> str:
        """Drop a partial secret, in any matched encoding, left at a cut.

        With ``keep="head"`` the text was cut at its end; with ``"tail"``,
        at its start.
        """
        state = self._state
        if keep == "tail":
            text = text[state.lattice.partial_suffix_end(text) :]
            return _trim_exact_suffixes(text, state.exact)
        text = text[: state.lattice.partial_prefix_start(text)]
        return _trim_exact_prefixes(text, state.exact)


def _build_state(matchers: Mapping[str, _Matcher]) -> _State:
    values = tuple(sorted(matchers, key=len, reverse=True))
    entries = [matchers[value] for value in values]
    exact = {form for entry in entries for form in entry.exact}
    return _State(
        values=values,
        patterns=tuple(entry.pattern for entry in entries),
        exact=tuple(sorted(exact, key=len, reverse=True)),
        secrets=tuple(sorted(exact | set(values), key=len, reverse=True)),
        lattice=Lattice(values),
    )


def _trim_exact_prefixes(text: str, forms: Iterable[str]) -> str:
    """Drop the end of ``text`` if it is the start of an exact form."""
    for form in forms:
        tail = text[-(len(form) - 1) :]
        position = tail.find(form[0])
        while position != -1:
            if form.startswith(tail[position:]):
                text = text[: len(text) - len(tail) + position]
                break
            position = tail.find(form[0], position + 1)
    return text


def _trim_exact_suffixes(text: str, forms: Iterable[str]) -> str:
    """Drop the start of ``text`` if it is the end of an exact form."""
    for form in forms:
        head = text[: len(form) - 1]
        position = head.rfind(form[-1])
        while position != -1:
            if form.endswith(head[: position + 1]):
                text = text[position + 1 :]
                break
            position = head.rfind(form[-1], 0, position)
    return text


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
    cut = len(text) > max_length
    if cut:
        text = registry.trim_partial(_cut(text, max_length, keep), keep)
    text = redact_secrets(text, registry)
    text = _URL_RE.sub(_redact_url_match, text)
    text = _QUOTED_KV_RE.sub(_redact_quoted_match, text)
    text = _HEADER_KV_RE.sub(_redact_kv_match, text)
    text = _BARE_KV_RE.sub(_redact_kv_match, text)
    text = mask_phone_numbers(text)
    text = escape_controls(text)
    if not cut:
        return truncate(text, max_length, keep=keep)
    room = max(max_length - len(TRUNCATED), 0)
    if keep == "tail":
        return TRUNCATED + (text[-room:] if room else "")
    return text[:room] + TRUNCATED


def _cut(text: str, limit: int, keep: Keep) -> str:
    """Cut ``text`` to ``limit``, moving the cut out of any URL, key-value or phone number.

    With ``keep="head"`` only matches within ``_CUT_CONTEXT`` characters of
    the cut are considered, which bounds the cost: a construct that starts
    before them keeps its key in the retained text and is redacted later.
    With ``keep="tail"`` see :func:`_tail_start`.
    """
    if keep == "tail":
        return text[_tail_start(text, len(text) - limit) :]
    position = limit
    low = max(position - _CUT_CONTEXT, 0)
    window = text[low : position + _CUT_CONTEXT]
    relative = position - low
    spans = [
        match.span() for pattern in _CUT_PATTERNS for match in pattern.finditer(window)
    ]
    moved = True
    while moved:
        moved = False
        for start, end in spans:
            if start < relative < end:
                relative = start
                moved = True
    return text[: low + relative]


def _tail_start(text: str, position: int) -> int:
    """Where text kept from ``position`` to the end may safely start.

    A tail that starts inside a sensitive value has lost the key, header
    name or URL scheme that later redaction relies on, so the start moves
    forward until it is shown to be outside every such construct: past the
    end of a line-bound one (URL, header, bare value, phone number), past the
    closing quote of a quoted value, past the value after a key whose
    separator runs across lines. Where that cannot be shown within the
    bounded context the start moves to the next line or closing quote, and
    with none left the whole field is withheld. Searches of the discarded
    text are plain substring scans; regular expressions see at most
    ``_MAX_LINE_SCAN`` characters of the current line and ``_CUT_CONTEXT``
    characters before a quote or value.
    """
    for _ in range(_MAX_TAIL_STEPS):
        if position >= len(text):
            break
        moved = _after_line_construct(text, position)
        if moved == position:
            moved = _after_open_quote(text, position)
        if moved == position:
            moved = _after_open_bare_value(text, position)
        if moved == position:
            return position
        position = moved
    return len(text)


def _next_line(text: str, position: int) -> int:
    ends = [
        end
        for end in (text.find("\n", position), text.find("\r", position))
        if end != -1
    ]
    return min(ends) + 1 if ends else len(text)


def _after_line_construct(text: str, position: int) -> int:
    """Move past a URL, key-value or phone number on this line that covers ``position``."""
    line = max(text.rfind("\n", 0, position), text.rfind("\r", 0, position)) + 1
    if line == position:
        return position
    if position - line > _MAX_LINE_SCAN:
        return _next_line(text, position)
    endpos = min(len(text), position + _CUT_CONTEXT)
    for pattern in _CUT_PATTERNS:
        for match in pattern.finditer(text, line, endpos):
            start, end = match.span()
            if start < position < end:
                return (
                    end
                    if end < endpos or endpos == len(text)
                    else _next_line(text, position)
                )
    return position


def _escaped(text: str, index: int) -> bool | None:
    """Whether the character at ``index`` follows an odd run of backslashes.

    None when the run is longer than ``_CUT_CONTEXT``.
    """
    start = max(index - _CUT_CONTEXT, 0)
    before = text[start:index]
    run = len(before) - len(before.rstrip("\\"))
    if run == len(before) and start > 0:
        return None
    return run % 2 == 1


def _after_open_quote(text: str, position: int) -> int:
    """Move past the closing quote of a sensitive quoted value open at ``position``.

    Inside such a value every quote of its kind is escaped, so the value
    opened at the last unescaped quote before ``position``.
    """
    for quote_char in "\"'":
        opened = _last_unescaped(text, quote_char, position)
        if opened == -1:
            continue
        if opened is not None:
            region_start = max(opened - _CUT_CONTEXT, 0)
            region = text[region_start:opened]
            if not _QUOTED_OPEN_RE.search(region) and not (
                region_start > 0 and _OPEN_TAIL_RE.fullmatch(region)
            ):
                continue
        closing = _next_unescaped(text, quote_char, position)
        return len(text) if closing == -1 else closing + 1
    return position


def _last_unescaped(text: str, quote_char: str, end: int) -> int | None:
    """Index of the last unescaped ``quote_char`` before ``end``, -1, or None if unknown."""
    index = text.rfind(quote_char, 0, end)
    for _ in range(_MAX_QUOTE_CANDIDATES):
        if index == -1:
            return -1
        escaped = _escaped(text, index)
        if escaped is None:
            return None
        if not escaped:
            return index
        index = text.rfind(quote_char, 0, index)
    return None


def _next_unescaped(text: str, quote_char: str, start: int) -> int:
    """Index of the first certainly unescaped ``quote_char`` from ``start``, or -1."""
    index = text.find(quote_char, start)
    while index != -1 and _escaped(text, index) is not False:
        index = text.find(quote_char, index + 1)
    return index


def _after_open_bare_value(text: str, position: int) -> int:
    """Move past a bare value whose key ends before the value run around ``position``.

    Covers separators that run across lines (``token=`` then a newline),
    which :func:`_after_line_construct` cannot see.
    """
    region_start = max(position - _CUT_CONTEXT, 0)
    if position > 0 and not _BARE_STOP_RE.match(text, position - 1):
        stop = _BARE_STOP_RE.search(text[region_start:position][::-1])
        if stop is None:
            return position
        value = position - stop.start()
    else:
        value = position
    region_start = max(value - _CUT_CONTEXT, 0)
    region = text[region_start:value]
    if not (
        _BARE_OPEN_RE.search(region)
        or (_KEY_END_RE.search(region) and text[value : value + 1] in (":", "="))
        or (region_start > 0 and _OPEN_TAIL_RE.fullmatch(region))
    ):
        return position
    rest = cast(re.Match[str], _BARE_REST_RE.match(text, value))
    return max(rest.end(), position)


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

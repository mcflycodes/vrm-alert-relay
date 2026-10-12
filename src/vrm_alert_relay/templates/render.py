"""Rendering notification text from restricted templates.

Rendering is a single pass over the parsed template: each placeholder is
replaced by its field's sanitized text, and substituted text is never parsed
again, so a label containing ``{rule}`` stays literal. Every field value is
stripped of control, format and line-separator characters, has its whitespace
collapsed and is truncated to a per-field limit before substitution; the
rendered text is bounded again as a whole. A template produces only text: it
has no way to name a recipient, a provider or a destination.
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from vrm_alert_relay.engine.models import EventKind
from vrm_alert_relay.templates.syntax import (
    MAX_TEMPLATE_CHARS,
    Literal,
    Placeholder,
    TemplateSyntaxError,
    parse_template,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from vrm_alert_relay.engine.models import Event
    from vrm_alert_relay.templates.syntax import Segment

__all__ = [
    "DEFAULT_TEMPLATES",
    "FIELD_LIMITS",
    "MAX_RENDERED_LENGTH",
    "MISSING",
    "NotificationKind",
    "Template",
    "TemplateFields",
    "fields_for_event",
    "neutralize_links",
    "render_notification",
    "sanitize_field",
    "sanitize_untrusted",
]

MAX_RENDERED_LENGTH: Final = 480
"""The longest text a template renders; providers may bound it further."""

MISSING: Final = "n/a"
"""Rendered for a field the notification does not carry (``unit`` renders empty)."""

FIELD_LIMITS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "rule": 64,
        "level": 64,
        "value": 24,
        "unit": 16,
        "installation": 64,
        "measurement": 64,
        "label": 64,
        "time": 24,
        "kind": 32,
        "count": 20,
    }
)
"""The longest text each placeholder can contribute, after sanitizing."""

_ELLIPSIS: Final = "…"
_TIME_FORMAT: Final = "%Y-%m-%d %H:%M UTC"
_PLAIN_NUMBER_LIMIT: Final = 1e6
# Untrusted input longer than this is cut before it is examined at all.
_PRESCAN_FACTOR: Final = 4


class NotificationKind(StrEnum):
    """What a notification reports: a rule event or a system condition."""

    ESCALATED = "escalated"
    REMINDER = "reminder"
    RECOVERED = "recovered"
    STALE = "stale"
    RESTORED = "restored"
    SUPPRESSION_SUMMARY = "suppression_summary"
    STORAGE_NOTICE = "storage_notice"
    MONITORING_DEGRADED = "monitoring_degraded"
    MONITORING_RESTORED = "monitoring_restored"


@dataclass(frozen=True, slots=True)
class TemplateFields:
    """The only values a template can show. Strings may be untrusted."""

    kind: NotificationKind
    rule: str | None = None
    level: str | None = None
    value: float | None = None
    unit: str | None = None
    """May come from VRM data: untrusted, so links in it are neutralized."""
    installation: str | None = None
    measurement: str | None = None
    label: str | None = None
    """A display label from VRM data: untrusted, so links in it are neutralized."""
    time: datetime | None = None
    count: int | None = None


def sanitize_field(text: str, limit: int) -> str:
    """Return ``text`` as one bounded line with no control or format characters.

    Characters in Unicode categories ``C*`` (control, format, surrogate,
    private use, unassigned) and ``Z*`` (spaces and line or paragraph
    separators) become spaces, runs of whitespace collapse to one space, and
    the result is cut to ``limit`` characters, ending in an ellipsis when cut.
    """
    head = text[: limit * _PRESCAN_FACTOR]
    cleaned = "".join(" " if unicodedata.category(char)[0] in "CZ" else char for char in head)
    collapsed = " ".join(cleaned.split())
    if len(collapsed) > limit:
        return collapsed[: limit - 1].rstrip() + _ELLIPSIS
    return collapsed


_HTTP_SCHEME: Final = re.compile(r"(?i)(h)tt(ps?)(?=://)")
_BARE_SCHEME: Final = re.compile(
    r"(?i)\b(mailto|tel|sms|smsto|callto|facetime|javascript|vbscript|data|file|geo|intent|market):"
)
_DOMAIN: Final = re.compile(r"[\w-]+(?:\.[\w-]+)*\.[^\W\d_]{2,}")
_IPV4: Final = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_EDGE_DOTS: Final = re.compile(r"^\.(?=[^\W\d_]{2})|(?<=\w)\.$")
_DOT: Final = "[.]"


def _defang_dots(match: re.Match[str]) -> str:
    return match.group(0).replace(".", _DOT)


def neutralize_links(text: str) -> str:
    """Make URLs, domains and IP addresses in ``text`` visibly non-clickable.

    ``https://evil.example.test/x`` becomes ``hxxps[:]//evil[.]example[.]test/x``:
    every ``://`` becomes ``[:]//`` (``http`` becoming ``hxxp``), a colon after
    a scheme such as ``tel`` or ``mailto`` becomes ``[:]``, and the dots of
    domain-like tokens (a final label of two or more letters), dotted IPv4
    addresses and a leading ``.com``-like or trailing dot become ``[.]``, so
    a domain cannot be formed by placing two fields side by side. Other text
    is unchanged.
    """
    text = _HTTP_SCHEME.sub(r"\1xx\2", text).replace("://", "[:]//")
    text = _BARE_SCHEME.sub(r"\1[:]", text)
    text = _DOMAIN.sub(_defang_dots, text)
    text = _IPV4.sub(_defang_dots, text)
    return _EDGE_DOTS.sub(_DOT, text)


# NFKC folds fullwidth and small forms (U+FF0E, U+FF1A, U+FF0F, U+FE52, ...)
# to ASCII, and U+FF61 to U+3002, but leaves the
# ideographic full stop, which IDNA also treats as a label separator.
_IDEOGRAPHIC_DOTS: Final = str.maketrans({"\u3002": "."})


def sanitize_untrusted(text: str, limit: int) -> str:
    """:func:`sanitize_field` for data from outside the configuration, such as
    VRM labels, with links neutralized (see :func:`neutralize_links`).

    The text is NFKC-normalized and ideographic full stops become ``.`` first,
    so lookalike punctuation (fullwidth colon, solidus and full stop, U+FF61,
    U+3002) is detected and neutralized like its ASCII form.
    """
    head = sanitize_field(text[: limit * _PRESCAN_FACTOR], limit * _PRESCAN_FACTOR)
    folded = unicodedata.normalize("NFKC", head).translate(_IDEOGRAPHIC_DOTS)
    return sanitize_field(neutralize_links(sanitize_field(folded, limit * _PRESCAN_FACTOR)), limit)


_UNTRUSTED_FIELDS: Final = frozenset({"label", "unit"})


def _format_value(value: float) -> str:
    if isinstance(value, bool) or not math.isfinite(value):
        return MISSING
    if abs(value) < _PLAIN_NUMBER_LIMIT:
        text = f"{value:.3f}".rstrip("0").rstrip(".")
        return "0" if text in ("-0", "") else text
    return f"{value:.6g}"


def _format_time(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        return MISSING
    return value.astimezone(UTC).strftime(_TIME_FORMAT)


def _field_text(fields: TemplateFields, name: str) -> str:  # noqa: PLR0911  # one return per field
    match name:
        case "value":
            return MISSING if fields.value is None else _format_value(fields.value)
        case "time":
            return MISSING if fields.time is None else _format_time(fields.time)
        case "count":
            return MISSING if fields.count is None else str(fields.count)
        case "kind":
            return str(fields.kind)
        case "unit":
            return fields.unit or ""
        case "label":
            return fields.label or fields.measurement or MISSING
        case _:
            raw: str | None = getattr(fields, name)
            return raw or MISSING


class Template:
    """A parsed, validated template. See :mod:`vrm_alert_relay.templates.syntax`."""

    __slots__ = ("_segments", "_source")

    def __init__(self, source: str) -> None:
        if not isinstance(source, str) or not source:
            raise TemplateSyntaxError("a template must be non-empty text")  # noqa: TRY003  # fixed operator-facing text
        if len(source) > MAX_TEMPLATE_CHARS:
            raise TemplateSyntaxError(f"a template must be at most {MAX_TEMPLATE_CHARS} characters")  # noqa: TRY003  # fixed operator-facing text
        self._source = source
        self._segments: tuple[Segment, ...] = parse_template(source)

    @property
    def source(self) -> str:
        return self._source

    @property
    def placeholders(self) -> frozenset[str]:
        return frozenset(s.name for s in self._segments if isinstance(s, Placeholder))

    def render(self, fields: TemplateFields, *, max_length: int = MAX_RENDERED_LENGTH) -> str:
        """Substitute ``fields`` in one pass and bound the result to ``max_length``."""
        parts: list[str] = []
        for segment in self._segments:
            if isinstance(segment, Literal):
                parts.append(segment.text)
            else:
                limit = FIELD_LIMITS[segment.name]
                clean = sanitize_untrusted if segment.name in _UNTRUSTED_FIELDS else sanitize_field
                parts.append(clean(_field_text(fields, segment.name), limit))
        return sanitize_field("".join(parts), max_length)

    def __repr__(self) -> str:
        return f"Template({self._source!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Template):
            return NotImplemented
        return self._source == other._source

    def __hash__(self) -> int:
        return hash(self._source)


DEFAULT_TEMPLATES: Final[Mapping[NotificationKind, Template]] = MappingProxyType(
    {
        NotificationKind.ESCALATED: Template(
            "{level}: {rule} at {installation}: {label} is {value}{unit} ({time})"
        ),
        NotificationKind.REMINDER: Template(
            "Reminder, still {level}: {rule} at {installation}: {label} is {value}{unit} ({time})"
        ),
        NotificationKind.RECOVERED: Template(
            "Recovered: {rule} at {installation} is back to normal: "
            "{label} is {value}{unit} ({time})"
        ),
        NotificationKind.STALE: Template(
            "Stale data: {rule} at {installation} has had no new {label} reading since {time}"
        ),
        NotificationKind.RESTORED: Template(
            "Data restored: {rule} at {installation} is reporting again: "
            "{label} is {value}{unit} ({time})"
        ),
        NotificationKind.SUPPRESSION_SUMMARY: Template(
            "VRM Alert Relay: {count} alert(s) held back by the global rate limit since {time}"
        ),
        NotificationKind.STORAGE_NOTICE: Template(
            "VRM Alert Relay: state storage is failing, so alerts continue under limits "
            "kept in memory only. Check the relay."
        ),
        NotificationKind.MONITORING_DEGRADED: Template(
            "VRM Alert Relay: monitoring of {installation} is degraded since {time}; "
            "alerts may be delayed or missed"
        ),
        NotificationKind.MONITORING_RESTORED: Template(
            "VRM Alert Relay: monitoring of {installation} is restored ({time})"
        ),
    }
)
"""The text sent for each kind when the configuration gives no template."""

_REMINDER_PREFIX: Final = "Reminder: "


def render_notification(
    fields: TemplateFields,
    *,
    level_message: str | None = None,
    max_length: int = MAX_RENDERED_LENGTH,
) -> str:
    """Render the text for one notification.

    ``level_message`` is the operator's template for the level, from
    configuration. It replaces the default for an escalation, and for a
    reminder it is sent after ``"Reminder: "``. Every other kind uses its
    default template.
    """
    if level_message is not None and fields.kind in (
        NotificationKind.ESCALATED,
        NotificationKind.REMINDER,
    ):
        text = Template(level_message).render(fields, max_length=max_length)
        if fields.kind is NotificationKind.REMINDER:
            text = sanitize_field(_REMINDER_PREFIX + text, max_length)
        return text
    return DEFAULT_TEMPLATES[fields.kind].render(fields, max_length=max_length)


_EVENT_KINDS: Final[Mapping[EventKind, NotificationKind]] = MappingProxyType(
    {kind: NotificationKind(kind.value) for kind in EventKind}
)


def fields_for_event(
    event: Event,
    *,
    installation: str,
    measurement: str,
    label: str | None = None,
    unit: str | None = None,
) -> TemplateFields:
    """The template fields of a rule event.

    ``installation`` and ``measurement`` come from configuration; ``label``
    and ``unit`` may come from VRM data and are sanitized when rendered.
    """
    return TemplateFields(
        kind=_EVENT_KINDS[event.kind],
        rule=event.rule_id,
        level=event.level,
        value=event.value,
        unit=unit,
        installation=installation,
        measurement=measurement,
        label=label,
        time=event.sample_time,
    )

"""The restricted message-template syntax.

A template is literal text with placeholders such as ``{rule}``. Only the
names in :data:`FIELD_NAMES` are accepted. There are no expressions, no
attribute or index access (``{rule.x}``, ``{rule[0]}``), no conversions
(``{rule!r}``) and no format specifications (``{value:>999}``); ``{{`` and
``}}`` stand for literal braces. Anything else is rejected when the
configuration is loaded.

This module has no dependencies so that configuration validation can use it.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Final

__all__ = [
    "FIELD_NAMES",
    "MAX_TEMPLATE_CHARS",
    "Literal",
    "Placeholder",
    "Segment",
    "TemplateSyntaxError",
    "parse_template",
]

FIELD_NAMES: Final = (
    "rule",
    "level",
    "value",
    "unit",
    "installation",
    "measurement",
    "label",
    "time",
    "kind",
    "count",
)
"""Every placeholder a template may use, in documentation order."""

MAX_TEMPLATE_CHARS: Final = 320
"""The longest template an operator may configure."""

_ALLOWED_TEXT: Final = ", ".join(f"{{{name}}}" for name in FIELD_NAMES)
_TOKEN: Final = re.compile(r"\{\{|\}\}|\{([^{}]*)\}|[{}]")
_NAME: Final = re.compile(r"[a-z]+")


class TemplateSyntaxError(ValueError):
    """A template uses unsupported syntax. ``reason`` is fixed operator-facing
    text that never contains the template itself."""

    def __init__(self, problem: str) -> None:
        self.reason = f"{problem}; allowed placeholders are {_ALLOWED_TEXT}"
        super().__init__(self.reason)


@dataclass(frozen=True, slots=True)
class Literal:
    """Text copied to the output as it is."""

    text: str


@dataclass(frozen=True, slots=True)
class Placeholder:
    """A field substituted once, at render time."""

    name: str


type Segment = Literal | Placeholder


def parse_template(text: str) -> tuple[Segment, ...]:
    """Split ``text`` into literal text and placeholders.

    Raises :class:`TemplateSyntaxError` for a control or format character
    (including line breaks and bidirectional overrides), an unknown placeholder, an
    expression, attribute or index access, a conversion, a format
    specification, or an unmatched brace.
    """
    if any(unicodedata.category(char)[0] == "C" or char in "\u2028\u2029" for char in text):
        raise TemplateSyntaxError("templates must not contain control or format characters")  # noqa: TRY003  # fixed operator-facing text
    segments: list[Segment] = []
    literal: list[str] = []
    position = 0
    for match in _TOKEN.finditer(text):
        literal.append(text[position : match.start()])
        position = match.end()
        token = match.group(0)
        if token in ("{{", "}}"):
            literal.append(token[0])
            continue
        name = match.group(1)
        if name is None:
            raise TemplateSyntaxError("unmatched '{' or '}' (write '{{' or '}}' for a brace)")  # noqa: TRY003  # fixed operator-facing text
        if not _NAME.fullmatch(name):
            raise TemplateSyntaxError(  # noqa: TRY003  # fixed operator-facing text
                "placeholders must be a bare field name, without expressions, "
                "attribute or index access, conversions or format specifications"
            )
        if name not in FIELD_NAMES:
            raise TemplateSyntaxError("unknown placeholder")  # noqa: TRY003  # fixed operator-facing text
        text_before = "".join(literal)
        if text_before:
            segments.append(Literal(text_before))
        literal = []
        segments.append(Placeholder(name))
    literal.append(text[position:])
    tail = "".join(literal)
    if tail:
        segments.append(Literal(tail))
    return tuple(segments)

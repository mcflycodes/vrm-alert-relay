"""Configuration errors and safe rendering of configuration paths."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

__all__ = ["ConfigError", "format_path", "mask_digits", "sanitize_identifier"]

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
_DIGIT_RUN = re.compile(r"\+?[0-9][0-9 ().-]*[0-9]")
_MAX_KEY_DISPLAY = 64
# Digit runs this long or longer are masked; shorter ones cannot be phone numbers.
_MIN_MASKED_DIGITS = 5


class ConfigError(Exception):
    """The configuration is invalid.

    ``problems`` holds one human-readable line per problem: a sanitized YAML path
    and a fixed message. Problems never contain configuration values, secret
    file contents, or complete phone numbers.
    """

    def __init__(self, problems: Iterable[str]) -> None:
        self.problems: tuple[str, ...] = tuple(problems) or ("invalid configuration",)
        super().__init__(self.problems)

    def __str__(self) -> str:
        lines = "\n".join(f"  - {problem}" for problem in self.problems)
        return f"invalid configuration:\n{lines}"


def mask_digits(text: str) -> str:
    """Mask every run of five or more digits down to its last four."""

    def _mask(match: re.Match[str]) -> str:
        digits = re.sub(r"[^0-9]", "", match.group(0))
        if len(digits) < _MIN_MASKED_DIGITS:
            return match.group(0)
        return f"***{digits[-4:]}"

    return _DIGIT_RUN.sub(_mask, text)


def sanitize_identifier(text: str) -> str:
    """Make an operator-supplied key safe to show: mask phone-shaped digit runs
    and truncate. Configuration values never pass through here; they are not shown.
    """
    masked = mask_digits(text)
    if len(masked) > _MAX_KEY_DISPLAY:
        masked = masked[:_MAX_KEY_DISPLAY] + "..."
    return masked


def _format_key(key: str) -> str:
    shown = sanitize_identifier(key)
    if _IDENTIFIER.fullmatch(shown):
        return f".{shown}"
    return f"[{json.dumps(shown)}]"


def format_path(loc: Sequence[str | int]) -> str:
    """Render a location tuple as a YAML path such as ``rules[2].levels[1]``."""
    out = ""
    for segment in loc:
        if isinstance(segment, int):
            out += f"[{segment}]"
        elif segment == "[key]":
            out += " (key)"
        else:
            out += _format_key(segment)
    return out.lstrip(".") or "<root>"

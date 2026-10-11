"""Configuration errors and safe rendering of configuration paths."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence

__all__ = ["ConfigError", "format_path", "mask_digits"]

_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
_DIGIT_RUN = re.compile(r"\+?[0-9][0-9 ().-]*[0-9]")
_MAX_KEY_DISPLAY = 64


class ConfigError(Exception):
    """The configuration is invalid.

    ``problems`` holds one human-readable line per problem, each prefixed with the
    YAML path it refers to. Problems never contain secret values or complete
    phone numbers.
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
        if len(digits) < 5:
            return match.group(0)
        return f"***{digits[-4:]}"

    return _DIGIT_RUN.sub(_mask, text)


def _format_key(key: str) -> str:
    if _IDENTIFIER.fullmatch(key):
        return f".{key}"
    shown = key if len(key) <= _MAX_KEY_DISPLAY else key[:_MAX_KEY_DISPLAY] + "..."
    return f"[{json.dumps(mask_digits(shown))}]"


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

"""Rendering configuration locations without echoing untrusted mapping keys.

A location segment is shown only when it is a field name from the schema, a list
index, or a recipient name that passes the identifier pattern and contains fewer
than five digits in total. Other recipient names appear as ``[#<position>]``,
and unrecognized keys end the path. Whenever something is withheld the problem
gives the YAML line number instead.
"""

from __future__ import annotations

import re
import types
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Annotated, Any, TypeAliasType, Union, get_args, get_origin

from pydantic import BaseModel

from .models import RelayConfig

__all__ = [
    "Loc",
    "SourceMap",
    "describe",
    "display_name",
    "is_displayable_key",
    "render_path",
]

Loc = tuple[str | int, ...]

_DISPLAYABLE_KEY = re.compile(r"[a-z0-9][a-z0-9_-]{0,62}")
_DIGIT = re.compile(r"[0-9]")
# Phone numbers have at least five digits however they are separated.
_MAX_DISPLAYED_DIGITS = 4
_KEY_SEGMENT = "[key]"


@dataclass(frozen=True)
class SourceMap:
    """Where each mapping key and list item sits in the YAML source.

    ``lines`` maps a location to the 1-based line of its key or item;
    ``positions`` maps a mapping-key location to its 0-based position among
    its siblings.
    """

    lines: dict[Loc, int] = field(default_factory=dict)
    positions: dict[Loc, int] = field(default_factory=dict)

    def line_of(self, loc: Sequence[str | int]) -> int | None:
        """Line of the deepest recorded location that ``loc`` starts with."""
        for end in range(len(loc), 0, -1):
            line = self.lines.get(tuple(loc[:end]))
            if line is not None:
                return line
        return None


_NO_SOURCE = SourceMap()


def is_displayable_key(key: str) -> bool:
    """Whether an operator-chosen name may be shown in operator-facing output."""
    return (
        _DISPLAYABLE_KEY.fullmatch(key) is not None
        and len(_DIGIT.findall(key)) <= _MAX_DISPLAYED_DIGITS
    )


def display_name(name: str, position: int | str) -> str:
    """``name`` if it may be shown, otherwise its placeholder ``[#<position>]``."""
    return name if is_displayable_key(name) else f"[#{position}]"


def _unwrap(annotation: Any) -> Any:
    while True:
        origin = get_origin(annotation)
        if isinstance(annotation, TypeAliasType):
            annotation = annotation.__value__
        elif origin is Annotated:
            annotation = get_args(annotation)[0]
        elif origin is Union or origin is types.UnionType:
            members = [a for a in get_args(annotation) if a is not type(None)]
            if len(members) != 1:
                return tuple(members)
            annotation = members[0]
        else:
            return annotation


def _model_fields(annotation: Any) -> dict[str, Any] | None:
    variants = annotation if isinstance(annotation, tuple) else (annotation,)
    fields: dict[str, Any] = {}
    for variant in variants:
        if not (isinstance(variant, type) and issubclass(variant, BaseModel)):
            return None
        for name, info in variant.model_fields.items():
            fields.setdefault(name, info.annotation)
    return fields


def _sequence_item(annotation: Any) -> Any | None:
    """Item type of ``tuple[X, ...]``, the only list shape in the schema."""
    return get_args(annotation)[0] if get_origin(annotation) is tuple else None


def _mapping_value(annotation: Any) -> Any | None:
    origin = get_origin(annotation)
    if isinstance(origin, type) and issubclass(origin, Mapping):
        return get_args(annotation)[1]
    return None


def render_path(
    loc: Sequence[str | int], source: SourceMap = _NO_SOURCE
) -> tuple[str, bool]:
    """Render ``loc`` safely. Returns the text and whether anything was withheld."""
    annotation: Any = RelayConfig
    text = ""
    withheld = False
    for index, segment in enumerate(loc):
        annotation = _unwrap(annotation)
        if segment == _KEY_SEGMENT:
            text += " (key)"
            break
        if isinstance(segment, int):
            next_annotation = _sequence_item(annotation)
            shown = f"[{segment}]"
        elif (fields := _model_fields(annotation)) is not None:
            next_annotation = fields.get(segment)
            shown = f".{segment}"
        else:
            next_annotation = _mapping_value(annotation)
            position = source.positions.get(tuple(loc[: index + 1]), "?")
            name = display_name(segment, position)
            withheld = withheld or name != segment
            shown = f".{name}" if name == segment else name
        if next_annotation is None:
            withheld = True
            break
        text += shown
        annotation = next_annotation
    return text.lstrip(".") or "<root>", withheld


def describe(
    loc: Sequence[str | int],
    message: str,
    source: SourceMap = _NO_SOURCE,
    *,
    line: int | None = None,
) -> str:
    """One problem line: the safe path, a fixed message, and a line number when
    part of the path was withheld or ``line`` is given."""
    text, withheld = render_path(loc, source)
    if line is None and withheld:
        line = source.line_of(loc)
    suffix = f" (line {line})" if line else ""
    return f"{text}: {message}{suffix}"

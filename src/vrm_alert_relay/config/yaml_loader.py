"""Hardened YAML parsing for the operator configuration file."""

from __future__ import annotations

from typing import Any

import yaml
from yaml.composer import ComposerError
from yaml.constructor import ConstructorError
from yaml.events import AliasEvent, NodeEvent
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode
from yaml.parser import ParserError
from yaml.reader import ReaderError
from yaml.scanner import ScannerError

from ._paths import Loc, SourceMap, describe
from .errors import ConfigError

__all__ = [
    "MAX_CONFIG_BYTES",
    "MAX_NESTING_DEPTH",
    "parse_yaml",
    "parse_yaml_with_source",
]

MAX_CONFIG_BYTES = 256 * 1024
MAX_NESTING_DEPTH = 16
MAX_COLLECTION_ITEMS = 1000

_STR_TAG = "tag:yaml.org,2002:str"
_MERGE_TAG = "tag:yaml.org,2002:merge"


class _Rejected(Exception):
    def __init__(self, message: str) -> None:
        self.message = message
        super().__init__(message)


def _line(node_or_event: Node | NodeEvent) -> int:
    mark = node_or_event.start_mark
    return int(mark.line) + 1 if mark is not None else 0


class _StrictLoader(yaml.SafeLoader):
    """``SafeLoader`` that refuses anchors, aliases, and deep nesting."""

    def __init__(self, stream: str) -> None:
        super().__init__(stream)
        self._depth = 0

    def compose_node(self, parent: Node | None, index: int) -> Node | None:
        event = self.peek_event()  # type: ignore[no-untyped-call]
        if isinstance(event, AliasEvent) or (
            isinstance(event, NodeEvent) and event.anchor is not None
        ):
            raise _Rejected(
                f"line {_line(event)}: YAML anchors and aliases are not allowed"
            )
        self._depth += 1
        try:
            if self._depth > MAX_NESTING_DEPTH:
                raise _Rejected(
                    f"line {_line(event)}: nesting is deeper than "
                    f"{MAX_NESTING_DEPTH} levels"
                )
            return super().compose_node(parent, index)
        finally:
            self._depth -= 1


def _check_tree(node: Node, loc: Loc, source: SourceMap) -> None:
    """Reject unsafe structure and record where every key and item sits.

    Problems name the parent path only; the offending key is identified by its
    line, never by its text.
    """
    if isinstance(node, SequenceNode):
        if len(node.value) > MAX_COLLECTION_ITEMS:
            raise _Rejected(
                describe(loc, f"more than {MAX_COLLECTION_ITEMS} items", source)
            )
        for index, item in enumerate(node.value):
            source.lines[(*loc, index)] = _line(item)
            _check_tree(item, (*loc, index), source)
    elif isinstance(node, MappingNode):
        if len(node.value) > MAX_COLLECTION_ITEMS:
            raise _Rejected(
                describe(loc, f"more than {MAX_COLLECTION_ITEMS} keys", source)
            )
        seen: set[str] = set()
        for position, (key_node, value_node) in enumerate(node.value):
            line = _line(key_node)
            if key_node.tag == _MERGE_TAG:
                message = "YAML merge keys ('<<') are not allowed"
                raise _Rejected(describe(loc, message, source, line=line))
            if not isinstance(key_node, ScalarNode) or key_node.tag != _STR_TAG:
                message = "mapping keys must be plain strings"
                raise _Rejected(describe(loc, message, source, line=line))
            key = str(key_node.value)
            if key in seen:
                raise _Rejected(describe(loc, "duplicate key", source, line=line))
            seen.add(key)
            source.lines[(*loc, key)] = line
            source.positions[(*loc, key)] = position
            _check_tree(value_node, (*loc, key), source)


# Fixed text per PyYAML exception class. PyYAML's own messages quote source
# text (values, tags, snippets), so only its line and column numbers are used.
_YAML_PROBLEMS: tuple[tuple[type[yaml.YAMLError], str], ...] = (
    (ScannerError, "invalid YAML syntax"),
    (ParserError, "invalid YAML structure"),
    (ComposerError, "the file must contain exactly one YAML document"),
    (ConstructorError, "unsupported YAML tag or value"),
    (ReaderError, "contains a character that is not allowed in YAML"),
)


def _yaml_problem(exc: yaml.YAMLError) -> str:
    problem = next(
        (text for kind, text in _YAML_PROBLEMS if isinstance(exc, kind)), "invalid YAML"
    )
    where = ""
    if isinstance(exc, yaml.MarkedYAMLError) and exc.problem_mark is not None:
        mark = exc.problem_mark
        where = f"line {int(mark.line) + 1}, column {int(mark.column) + 1}: "
    elif isinstance(exc, ReaderError):
        where = f"position {int(exc.position)}: "
    return f"YAML error: {where}{problem}"


def _decode(data: bytes) -> str | None:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


def _compose(text: str, source: SourceMap) -> Any:
    loader = _StrictLoader(text)
    try:
        node = loader.get_single_node()
        if node is None:
            return None
        _check_tree(node, (), source)
        return loader.construct_document(node)
    finally:
        loader.dispose()


def parse_yaml(data: bytes | str) -> Any:
    """Parse one YAML document into plain Python data, rejecting unsafe input."""
    return parse_yaml_with_source(data)[0]


def parse_yaml_with_source(data: bytes | str) -> tuple[Any, SourceMap]:
    """Like :func:`parse_yaml`, also returning where each key and item sits.

    Errors are raised outside ``except`` blocks so no exception holding source
    text is chained onto the :class:`ConfigError`.
    """
    size = len(data) if isinstance(data, bytes) else len(data.encode("utf-8"))
    if size > MAX_CONFIG_BYTES:
        raise ConfigError([f"configuration is larger than {MAX_CONFIG_BYTES} bytes"])
    text = _decode(data) if isinstance(data, bytes) else data
    if text is None:
        raise ConfigError(["configuration is not valid UTF-8"])

    problem: str | None = None
    result: Any = None
    source = SourceMap()
    try:
        result = _compose(text, source)
    except _Rejected as exc:
        problem = exc.message
    except yaml.YAMLError as exc:
        problem = _yaml_problem(exc)
    except (ValueError, TypeError, OverflowError, RecursionError):
        problem = "configuration contains a value that cannot be parsed"
    if problem is not None:
        raise ConfigError([problem])
    if result is None:
        raise ConfigError(["configuration is empty"])
    return result, source

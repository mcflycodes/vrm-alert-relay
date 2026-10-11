"""Hardened YAML parsing for the operator configuration file."""

from __future__ import annotations

from typing import Any

import yaml
from yaml.events import AliasEvent, NodeEvent
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from .errors import ConfigError, format_path, mask_digits

__all__ = ["MAX_CONFIG_BYTES", "MAX_NESTING_DEPTH", "parse_yaml"]

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


def _check_tree(node: Node, loc: tuple[str | int, ...]) -> None:
    if isinstance(node, SequenceNode):
        if len(node.value) > MAX_COLLECTION_ITEMS:
            raise _Rejected(
                f"{format_path(loc)}: more than {MAX_COLLECTION_ITEMS} items"
            )
        for index, item in enumerate(node.value):
            _check_tree(item, (*loc, index))
    elif isinstance(node, MappingNode):
        if len(node.value) > MAX_COLLECTION_ITEMS:
            raise _Rejected(
                f"{format_path(loc)}: more than {MAX_COLLECTION_ITEMS} keys"
            )
        seen: set[str] = set()
        for key_node, value_node in node.value:
            if key_node.tag == _MERGE_TAG:
                raise _Rejected(
                    f"{format_path(loc)} (line {_line(key_node)}): "
                    "YAML merge keys ('<<') are not allowed"
                )
            if not isinstance(key_node, ScalarNode) or key_node.tag != _STR_TAG:
                raise _Rejected(
                    f"{format_path(loc)} (line {_line(key_node)}): "
                    "mapping keys must be plain strings"
                )
            key = str(key_node.value)
            if key in seen:
                raise _Rejected(
                    f"{format_path((*loc, key))} (line {_line(key_node)}): "
                    "duplicate key"
                )
            seen.add(key)
            _check_tree(value_node, (*loc, key))


def _yaml_problem(exc: yaml.YAMLError) -> str:
    # Never include the source snippet that PyYAML attaches to its messages.
    if isinstance(exc, yaml.MarkedYAMLError):
        where = ""
        if exc.problem_mark is not None:
            mark = exc.problem_mark
            where = f"line {mark.line + 1}, column {mark.column + 1}: "
        problem = exc.problem or exc.context or "invalid YAML"
        return f"YAML syntax error: {where}{mask_digits(problem)}"
    return "YAML syntax error"


def parse_yaml(data: bytes | str) -> Any:
    """Parse one YAML document into plain Python data, rejecting unsafe input."""
    if isinstance(data, bytes):
        if len(data) > MAX_CONFIG_BYTES:
            raise ConfigError(
                [f"configuration is larger than {MAX_CONFIG_BYTES} bytes"]
            )
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise ConfigError(["configuration is not valid UTF-8"]) from None
    else:
        if len(data.encode("utf-8")) > MAX_CONFIG_BYTES:
            raise ConfigError(
                [f"configuration is larger than {MAX_CONFIG_BYTES} bytes"]
            )
        text = data

    loader = _StrictLoader(text)
    try:
        node = loader.get_single_node()
        result: Any = None
        if node is not None:
            _check_tree(node, ())
            result = loader.construct_document(node)
        if result is None:
            raise ConfigError(["configuration is empty"])
        return result
    except _Rejected as exc:
        raise ConfigError([exc.message]) from None
    except yaml.YAMLError as exc:
        raise ConfigError([_yaml_problem(exc)]) from None
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise ConfigError(
            ["configuration contains a value that cannot be parsed"]
        ) from None
    finally:
        loader.dispose()

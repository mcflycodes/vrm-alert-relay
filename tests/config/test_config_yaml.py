"""Hardened YAML loading: size, aliases, keys, nesting, and error hygiene."""

from __future__ import annotations

import errno
import os
import stat
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from vrm_alert_relay.config import ConfigError, load_config, parse_config
from vrm_alert_relay.config.yaml_loader import (
    MAX_COLLECTION_ITEMS,
    MAX_CONFIG_BYTES,
    MAX_NESTING_DEPTH,
    parse_yaml,
)

Problems = Callable[[Any], tuple[str, ...]]

BILLION_LAUGHS = """\
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h]
"""


def test_alias_expansion_bomb_is_rejected_quickly(problems: Problems) -> None:
    start = time.monotonic()
    found = problems(BILLION_LAUGHS)
    assert time.monotonic() - start < 1
    assert found == ("line 1: YAML anchors and aliases are not allowed",)


@pytest.mark.parametrize(
    "text",
    [
        "a: &anchor 1\n",
        "a: 1\nb: *undefined\n",
        "a: &x {k: v}\nb: *x\n",
        "a:\n  - &item one\n",
    ],
)
def test_anchors_and_aliases_are_rejected(problems: Problems, text: str) -> None:
    (problem,) = problems(text)
    assert "anchors and aliases are not allowed" in problem


def test_duplicate_top_level_key_is_rejected(problems: Problems) -> None:
    assert problems("vrm: {}\nsending: {}\nvrm: {}\n") == (
        "vrm (line 3): duplicate key",
    )


def test_duplicate_nested_key_reports_its_path(problems: Problems) -> None:
    text = "rules:\n  - id: a\n    levels:\n      - name: x\n        name: y\n"
    assert problems(text) == ("rules[0].levels[0].name (line 5): duplicate key",)


@pytest.mark.parametrize(
    "text",
    [
        "1: x\n",
        "on: x\n",
        "null: x\n",
        "? [a, b]\n: x\n",
        "sending:\n  2026-01-01: x\n",
    ],
)
def test_non_string_keys_are_rejected(problems: Problems, text: str) -> None:
    (problem,) = problems(text)
    assert problem.endswith("mapping keys must be plain strings")


def test_merge_keys_are_rejected(problems: Problems) -> None:
    (problem,) = problems("sending:\n  <<: {enabled: true}\n")
    assert problem == "sending (line 2): YAML merge keys ('<<') are not allowed"


@pytest.mark.parametrize(
    "text",
    [
        "a: " + "[" * 40 + "]" * 40 + "\n",
        "".join("  " * depth + f"k{depth}:\n" for depth in range(30))
        + "  " * 30
        + "v\n",
        "a: " + "[" * 100_000,
    ],
    ids=["flow", "block", "unterminated"],
)
def test_deep_nesting_is_rejected(problems: Problems, text: str) -> None:
    (problem,) = problems(text)
    assert f"nesting is deeper than {MAX_NESTING_DEPTH} levels" in problem


def test_nesting_at_the_limit_is_parsed() -> None:
    depth = MAX_NESTING_DEPTH - 1
    expected: list[Any] = []
    for _ in range(depth - 1):
        expected = [expected]
    assert parse_yaml("a: " + "[" * depth + "]" * depth) == {"a": expected}


def test_oversized_sequence_is_rejected(problems: Problems) -> None:
    text = "rules: [" + ",".join(["1"] * (MAX_COLLECTION_ITEMS + 1)) + "]\n"
    assert problems(text) == (f"rules: more than {MAX_COLLECTION_ITEMS} items",)


def test_oversized_mapping_is_rejected(problems: Problems) -> None:
    text = "recipients:\n" + "".join(
        f"  r{i}: x\n" for i in range(MAX_COLLECTION_ITEMS + 1)
    )
    assert problems(text) == (f"recipients: more than {MAX_COLLECTION_ITEMS} keys",)


def test_oversized_file_is_rejected(write_config: Callable[[Any], Path]) -> None:
    path = write_config("# padding\n" * (MAX_CONFIG_BYTES // 10 + 1))
    with pytest.raises(ConfigError) as caught:
        load_config(path)
    assert caught.value.problems == (
        f"{path}: configuration is larger than {MAX_CONFIG_BYTES} bytes",
    )


@pytest.mark.parametrize("as_bytes", [True, False])
def test_oversized_text_is_rejected(problems: Problems, as_bytes: bool) -> None:
    text = "#" * (MAX_CONFIG_BYTES + 1)
    found = problems(text.encode() if as_bytes else text)
    assert found == (f"configuration is larger than {MAX_CONFIG_BYTES} bytes",)


@pytest.mark.parametrize("text", ["", "# only a comment\n", "---\n", "~\n", "null\n"])
def test_empty_configuration_is_rejected(problems: Problems, text: str) -> None:
    assert problems(text) == ("configuration is empty",)


@pytest.mark.parametrize("text", ["- a\n- b\n", "just text\n", "42\n"])
def test_top_level_must_be_a_mapping(problems: Problems, text: str) -> None:
    assert problems(text) == ("configuration must be a YAML mapping at the top level",)


def test_multiple_documents_are_rejected(problems: Problems) -> None:
    (problem,) = problems("a: 1\n---\nb: 2\n")
    assert problem == (
        "YAML error: line 2, column 1: the file must contain exactly one YAML document"
    )


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a: b: c\n", "YAML error: line 1, column 5: invalid YAML syntax"),
        ("a: [1, 2\n", "YAML error: line 2, column 1: invalid YAML structure"),
        (
            "a: 1\n\x07b: 2\n",
            "YAML error: position 5: contains a character that is not allowed in YAML",
        ),
        (
            "vrm: !custom-tag {}\n",
            "YAML error: line 1, column 6: unsupported YAML tag or value",
        ),
    ],
)
def test_yaml_errors_use_fixed_messages(
    problems: Problems, text: str, expected: str
) -> None:
    assert problems(text) == (expected,)


def test_invalid_utf8_is_rejected(problems: Problems) -> None:
    assert problems(b"sending: {enabled: \xff}\n") == (
        "configuration is not valid UTF-8",
    )


def test_utf8_byte_order_mark_is_accepted() -> None:
    assert parse_yaml("\ufeffa: 1\n".encode()) == {"a": 1}


def test_unparseable_scalar_is_rejected(problems: Problems) -> None:
    assert problems("a: " + "1" * 5000 + "\n") == (
        "configuration contains a value that cannot be parsed",
    )


def test_python_tags_are_not_constructed(problems: Problems) -> None:
    (problem,) = problems("a: !!python/object/apply:os.system ['true']\n")
    assert problem == "YAML error: line 1, column 4: unsupported YAML tag or value"


def test_syntax_errors_do_not_echo_source_lines(problems: Problems) -> None:
    text = 'vrm:\n  note: "+1 202 555 0142 fake-secret-for-tests-only\n  x: [\n'
    (problem,) = problems(text)
    assert problem.startswith("YAML error: line ")
    assert "fake-secret" not in problem
    assert "2025550142" not in problem
    assert "555 0142" not in problem


def test_yaml_error_without_mark_has_generic_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import yaml

    from vrm_alert_relay.config import yaml_loader

    def explode(self: Any) -> None:
        raise yaml.YAMLError("raw message with fake-secret-for-tests-only")

    monkeypatch.setattr(yaml_loader._StrictLoader, "get_single_node", explode)
    with pytest.raises(ConfigError) as caught:
        parse_config("a: 1\n")
    assert caught.value.problems == ("YAML error: invalid YAML",)


def test_marked_error_without_problem_mark(monkeypatch: pytest.MonkeyPatch) -> None:
    import yaml

    from vrm_alert_relay.config import yaml_loader

    def explode(self: Any) -> None:
        raise yaml.MarkedYAMLError(context="while testing")

    monkeypatch.setattr(yaml_loader._StrictLoader, "get_single_node", explode)
    with pytest.raises(ConfigError) as caught:
        parse_config("a: 1\n")
    assert caught.value.problems == ("YAML error: invalid YAML",)


def test_load_config_missing_file(tmp_path: Path) -> None:
    path = tmp_path / "absent.yaml"
    with pytest.raises(ConfigError) as caught:
        load_config(path)
    assert caught.value.problems == (f"{path}: configuration file does not exist",)


def _load_within(path: Path, seconds: float = 5.0) -> ConfigError:
    """Run load_config in a daemon thread so a blocking open cannot hang the suite."""
    outcome: list[BaseException] = []

    def target() -> None:
        try:
            load_config(path)
        except BaseException as exc:  # noqa: BLE001 - handed back to the test
            outcome.append(exc)

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(seconds)
    assert not worker.is_alive(), "load_config blocked"
    (error,) = outcome
    assert isinstance(error, ConfigError)
    return error


def test_load_config_fifo_fails_fast(tmp_path: Path) -> None:
    fifo = tmp_path / "config.yaml"
    os.mkfifo(fifo)
    error = _load_within(fifo)
    assert error.problems == (f"{fifo}: configuration path is not a regular file",)


def test_load_config_directory_fails_fast(tmp_path: Path) -> None:
    error = _load_within(tmp_path)
    assert error.problems == (f"{tmp_path}: configuration path is not a regular file",)


def test_load_config_device_fails_fast() -> None:
    device = Path(os.devnull)
    assert stat.S_ISCHR(device.stat().st_mode)
    error = _load_within(device)
    assert error.problems == (f"{device}: configuration path is not a regular file",)


def test_load_config_oversize_fails_fast(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    path.write_bytes(b"#" * (MAX_CONFIG_BYTES + 1))
    error = _load_within(path)
    assert error.problems == (
        f"{path}: configuration is larger than {MAX_CONFIG_BYTES} bytes",
    )


@pytest.mark.parametrize(
    ("code", "reason"),
    [
        (errno.EACCES, "configuration file is not readable (permission denied)"),
        (errno.EIO, "configuration file cannot be read (EIO)"),
    ],
)
def test_load_config_open_errors_use_fixed_messages(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int, reason: str
) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("a: 1\n")

    def fail(*_args: Any) -> int:
        raise OSError(code, "raw OS text fake-secret-for-tests-only")

    monkeypatch.setattr("vrm_alert_relay.config._files.os.open", fail)
    with pytest.raises(ConfigError) as caught:
        load_config(path)
    assert caught.value.problems == (f"{path}: {reason}",)
    assert "fake-secret" not in str(caught.value)

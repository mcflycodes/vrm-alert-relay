"""State-file path safety. Every value here is fictitious."""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

import pytest

from vrm_alert_relay.state import paths

if TYPE_CHECKING:
    from pathlib import Path


def test_a_file_that_cannot_be_tightened_is_still_opened_with_a_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    target = tmp_path / "state-file"
    target.write_text("")
    target.chmod(0o644)

    def refuse(descriptor: int, mode: int) -> None:
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr(paths.os, "fchmod", refuse)
    with caplog.at_level(logging.WARNING, logger="vrm_alert_relay.state"):
        descriptor = paths.open_private(target, os.O_RDONLY)
    os.close(descriptor)
    assert "state.file_permissive" in [r.__dict__.get("event") for r in caplog.records]


def test_missing_files_are_not_created_by_the_check(tmp_path: Path) -> None:
    paths.secure_existing(tmp_path / "absent")
    assert not (tmp_path / "absent").exists()


def test_other_open_errors_propagate(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        paths.open_private(tmp_path / "missing" / "file", os.O_RDONLY)

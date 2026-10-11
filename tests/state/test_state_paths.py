"""State-file path safety. Every value here is fictitious."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from vrm_alert_relay.state import UnsafeStateError, paths


def test_a_file_that_cannot_be_restricted_is_not_used(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """L10: a world-readable state file that cannot be fixed is unusable, not a warning."""
    target = tmp_path / "state-file"
    target.write_text("")
    target.chmod(0o644)

    def refuse(descriptor: int, mode: int) -> None:
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr(paths.os, "fchmod", refuse)
    descriptors = Path("/proc/self/fd")
    before = len(list(descriptors.iterdir()))
    with pytest.raises(UnsafeStateError, match="0600"):
        paths.open_private(target, os.O_RDONLY)
    assert len(list(descriptors.iterdir())) == before  # the descriptor was closed


def test_missing_files_are_not_created_by_the_check(tmp_path: Path) -> None:
    paths.secure_existing(tmp_path / "absent")
    assert not (tmp_path / "absent").exists()


def test_other_open_errors_propagate(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        paths.open_private(tmp_path / "missing" / "file", os.O_RDONLY)


def test_identity_checks_catch_a_replaced_or_missing_file(tmp_path: Path) -> None:
    target = tmp_path / "state-file"
    target.write_text("")
    descriptor = paths.open_private(target, os.O_RDONLY)
    try:
        identity = paths.identity_of(descriptor)
        paths.check_identity(target, identity)
        target.unlink()
        with pytest.raises(UnsafeStateError, match="replaced"):
            paths.check_identity(target, identity)
        target.symlink_to(tmp_path)
        with pytest.raises(UnsafeStateError, match="replaced"):
            paths.check_identity(target, identity)
    finally:
        os.close(descriptor)


def test_open_descriptors_lists_regular_files_or_none_without_proc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "state-file"
    target.write_text("")
    descriptor = paths.open_private(target, os.O_RDONLY)
    try:
        found = paths.open_descriptors()
        assert found is not None
        assert found[descriptor] == paths.identity_of(descriptor)
    finally:
        os.close(descriptor)

    def missing(self: object) -> object:
        raise FileNotFoundError

    monkeypatch.setattr(paths.Path, "iterdir", missing)
    assert paths.open_descriptors() is None

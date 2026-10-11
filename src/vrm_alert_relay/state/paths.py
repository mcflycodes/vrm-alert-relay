"""Safe handling of the state directory and the files in it.

Every state file is opened without following symlinks, must be a regular
file, and is kept at mode 0600. A state directory that is a symlink or not a
directory is refused; a group- or world-writable one only draws a warning.
"""

from __future__ import annotations

import errno
import logging
import os
import stat
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from pathlib import Path

__all__ = [
    "SIDECAR_SUFFIXES",
    "StateLockedError",
    "UnsafeStateError",
    "check_directory",
    "open_private",
    "secure_existing",
]

logger = logging.getLogger(__name__)

PRIVATE_MODE: Final = 0o600
SIDECAR_SUFFIXES: Final = ("-wal", "-shm", "-journal")


class UnsafeStateError(RuntimeError):
    """A state path is a symlink or not the expected kind of file."""


class StateLockedError(RuntimeError):
    """Another relay process holds the state directory."""


def check_directory(path: Path) -> None:
    """Refuse a symlinked or non-directory state directory; warn if others can write it.

    A missing directory raises ``FileNotFoundError`` like any other storage failure.
    """
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode):
        raise UnsafeStateError("the state directory is a symlink")  # noqa: TRY003  # per-check validation message
    if not stat.S_ISDIR(info.st_mode):
        raise UnsafeStateError("the state directory is not a directory")  # noqa: TRY003  # per-check validation message
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        logger.warning(
            "the state directory is writable by group or others; restrict it to the relay user",
            extra={"event": "state.directory_permissive"},
        )


def open_private(path: Path, flags: int) -> int:
    """Open a state file without following symlinks; it must be a regular file.

    The file is created with mode 0600 and an existing one is reset to 0600.
    """
    try:
        descriptor = os.open(
            path, flags | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, PRIVATE_MODE
        )
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UnsafeStateError(f"state file {path.name} is a symlink") from exc  # noqa: TRY003  # per-check validation message
        raise
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise UnsafeStateError(f"state file {path.name} is not a regular file")  # noqa: TRY003, TRY301  # per-check validation message
        if stat.S_IMODE(info.st_mode) != PRIVATE_MODE:
            _tighten(descriptor)
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _tighten(descriptor: int) -> None:
    try:
        os.fchmod(descriptor, PRIVATE_MODE)
    except OSError:
        # A read-only volume cannot be changed; reading from it is still safe.
        logger.warning(
            "could not restrict a state file to mode 0600",
            extra={"event": "state.file_permissive"},
        )


def secure_existing(path: Path) -> None:
    """Check and tighten a state file that SQLite opens itself, if it exists."""
    try:
        descriptor = open_private(path, os.O_RDONLY)
    except FileNotFoundError:
        return
    os.close(descriptor)

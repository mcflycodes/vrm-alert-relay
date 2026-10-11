"""Safe handling of the state directory and the files in it.

Every state file is opened without following symlinks, must be a regular
file, and is kept at mode 0600; a file that cannot be restricted to 0600 is
not used. A state directory that is a symlink or not a directory is refused;
a group- or world-writable one only draws a warning. A refused path makes
that storage unavailable; the relay keeps alerting (ADR 0002).
"""

from __future__ import annotations

import errno
import logging
import os
import stat
from pathlib import Path
from typing import Final

__all__ = [
    "SIDECAR_SUFFIXES",
    "FileIdentity",
    "StateLockedError",
    "UnsafeStateError",
    "check_directory",
    "check_identity",
    "identity_of",
    "open_descriptors",
    "open_private",
    "secure_existing",
]

type FileIdentity = tuple[int, int]
"""A file's (device, inode)."""

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
    except OSError as exc:
        # Others may read or change this file: it is not used for state.
        raise UnsafeStateError("a state file could not be restricted to mode 0600") from exc  # noqa: TRY003  # per-check validation message


def secure_existing(path: Path) -> None:
    """Check and tighten a state file that SQLite opens itself, if it exists."""
    try:
        descriptor = open_private(path, os.O_RDONLY)
    except FileNotFoundError:
        return
    os.close(descriptor)


def identity_of(descriptor: int) -> FileIdentity:
    info = os.fstat(descriptor)
    return (info.st_dev, info.st_ino)


def check_identity(path: Path, expected: FileIdentity) -> None:
    """Raise :class:`UnsafeStateError` unless ``path`` is still the file validated earlier."""
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise UnsafeStateError(f"state file {path.name} was replaced") from exc  # noqa: TRY003  # per-check validation message
    if stat.S_ISLNK(info.st_mode) or (info.st_dev, info.st_ino) != expected:
        raise UnsafeStateError(f"state file {path.name} was replaced")  # noqa: TRY003  # per-check validation message


def open_descriptors() -> dict[int, FileIdentity] | None:
    """The process's open regular files by descriptor, or None where ``/proc`` is unavailable."""
    try:
        names = [entry.name for entry in Path("/proc/self/fd").iterdir()]
    except OSError:
        return None
    found: dict[int, FileIdentity] = {}
    for name in names:
        try:
            info = os.fstat(int(name))
        except (OSError, ValueError):
            continue  # Closed since listing, or the listing's own descriptor.
        if stat.S_ISREG(info.st_mode):
            found[int(name)] = (info.st_dev, info.st_ino)
    return found

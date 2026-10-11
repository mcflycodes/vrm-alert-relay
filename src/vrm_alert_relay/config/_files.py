"""Bounded, non-blocking reads of regular files."""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from enum import Enum

__all__ = ["FileContent", "FileProblem", "FileReadError", "read_regular_file"]

# O_NONBLOCK keeps open() from waiting on a FIFO with no writer.
_OPEN_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOCTTY


class FileProblem(Enum):
    MISSING = "missing"
    PERMISSION_DENIED = "permission_denied"
    NOT_REGULAR = "not_regular"
    TOO_LARGE = "too_large"
    OS_ERROR = "os_error"


class FileReadError(Exception):
    """A file could not be read. Carries only the kind of failure and errno name."""

    def __init__(self, problem: FileProblem, code: str | None = None) -> None:
        self.problem = problem
        self.code = code
        super().__init__(problem.value)


@dataclass(frozen=True, slots=True)
class FileContent:
    data: bytes
    mode: int


def _classify(exc: OSError) -> FileReadError:
    if exc.errno in (errno.ENOENT, errno.ENOTDIR):
        return FileReadError(FileProblem.MISSING)
    if exc.errno in (errno.EACCES, errno.EPERM):
        return FileReadError(FileProblem.PERMISSION_DENIED)
    code = errno.errorcode.get(exc.errno, "unknown") if exc.errno else "unknown"
    return FileReadError(FileProblem.OS_ERROR, code)


def read_regular_file(path: str | os.PathLike[str], max_bytes: int) -> FileContent:
    """Read at most ``max_bytes`` from a regular file without ever blocking on open.

    Raises :class:`FileReadError`; the error never contains OS message text.
    """
    error: FileReadError | None = None
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except OSError as exc:
        error = _classify(exc)
    if error is not None:
        raise error
    chunks: list[bytes] = []
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            error = FileReadError(FileProblem.NOT_REGULAR)
        elif info.st_size > max_bytes:
            error = FileReadError(FileProblem.TOO_LARGE)
        else:
            total = 0
            while total <= max_bytes:
                chunk = os.read(fd, max_bytes + 1 - total)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
            if total > max_bytes:
                error = FileReadError(FileProblem.TOO_LARGE)
    except OSError as exc:
        error = _classify(exc)
    finally:
        os.close(fd)
    if error is not None:
        raise error
    return FileContent(data=b"".join(chunks), mode=info.st_mode)

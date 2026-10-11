"""Secret values and safe reading of secret files."""

from __future__ import annotations

import errno
import hmac
import os
import re
import stat
from dataclasses import dataclass
from typing import Any, NoReturn

from pydantic import GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema

__all__ = [
    "MAX_SECRET_BYTES",
    "Secret",
    "SecretFile",
    "SecretFileError",
    "read_secret_file",
]

MAX_SECRET_BYTES = 4096
_MASK = "**********"
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")


class Secret:
    """A secret string that never reveals itself except through :meth:`reveal`.

    ``str``, ``repr``, ``format``, and pydantic serialization all produce a fixed
    mask. ``json.dumps`` and ``pickle`` refuse the object rather than leak it.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("Secret value must be a string")
        self._value = value

    def reveal(self) -> str:
        """Return the secret value. Only provider adapters should call this."""
        return self._value

    def __repr__(self) -> str:
        return f"Secret('{_MASK}')"

    def __str__(self) -> str:
        return _MASK

    def __format__(self, format_spec: str) -> str:
        return format(_MASK, format_spec)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secret):
            return NotImplemented
        return hmac.compare_digest(self._value.encode(), other._value.encode())

    __hash__ = None  # type: ignore[assignment]

    def __copy__(self) -> Secret:
        return self

    def __deepcopy__(self, memo: dict[int, Any]) -> Secret:
        return self

    def __reduce__(self) -> NoReturn:
        raise TypeError("Secret values cannot be pickled")

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: type[Any], handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls._validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                _mask_secret, when_used="always"
            ),
        )

    @classmethod
    def _validate(cls, value: object) -> Secret:
        if isinstance(value, Secret):
            return value
        raise ValueError("must be a Secret loaded from a secret file")


def _mask_secret(_value: object) -> str:
    return _MASK


class SecretFileError(Exception):
    """A secret file could not be used. The message never contains file content."""

    def __init__(self, reason: str, *, missing: bool = False) -> None:
        self.reason = reason
        self.missing = missing
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class SecretFile:
    """A secret read from a file, plus whether the file mode is too permissive."""

    secret: Secret
    group_or_world_readable: bool


_OPEN_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NOCTTY | os.O_NONBLOCK


def _fail_open(exc: OSError) -> NoReturn:
    if exc.errno in (errno.ENOENT, errno.ENOTDIR):
        raise SecretFileError("secret file does not exist", missing=True) from None
    if exc.errno in (errno.EACCES, errno.EPERM):
        raise SecretFileError(
            "secret file is not readable (permission denied)"
        ) from None
    reason = exc.strerror or "unknown error"
    raise SecretFileError(f"secret file cannot be read: {reason}") from None


def read_secret_file(path: str | os.PathLike[str]) -> SecretFile:
    """Read one secret from ``path``.

    The file must be a regular file of at most 4 KiB containing UTF-8 text. One
    trailing newline is stripped; the remaining value must be non-empty and free
    of line breaks and control characters.
    """
    try:
        fd = os.open(path, _OPEN_FLAGS)
    except OSError as exc:
        _fail_open(exc)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SecretFileError("secret file is not a regular file")
        if info.st_size > MAX_SECRET_BYTES:
            raise SecretFileError(
                f"secret file is larger than {MAX_SECRET_BYTES} bytes"
            )
        chunks: list[bytes] = []
        total = 0
        while total <= MAX_SECRET_BYTES:
            chunk = os.read(fd, MAX_SECRET_BYTES + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    except OSError as exc:
        _fail_open(exc)
    finally:
        os.close(fd)

    if total > MAX_SECRET_BYTES:
        raise SecretFileError(f"secret file is larger than {MAX_SECRET_BYTES} bytes")
    try:
        text = b"".join(chunks).decode("utf-8")
    except UnicodeDecodeError:
        raise SecretFileError("secret file is not valid UTF-8") from None
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if not text:
        raise SecretFileError("secret file is empty")
    if _CONTROL.search(text):
        raise SecretFileError("secret file contains line breaks or control characters")
    permissive = bool(info.st_mode & (stat.S_IRGRP | stat.S_IROTH))
    return SecretFile(secret=Secret(text), group_or_world_readable=permissive)

"""Secret values and safe reading of secret files."""

from __future__ import annotations

import hmac
import re
import stat
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, NoReturn

from pydantic_core import CoreSchema, core_schema

from ._files import FileProblem, FileReadError, read_regular_file

if TYPE_CHECKING:
    import os

    from pydantic import GetCoreSchemaHandler

__all__ = [
    "MAX_SECRET_BYTES",
    "Secret",
    "SecretFile",
    "SecretFileError",
    "SecretTypeError",
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
            raise TypeError("Secret value must be a string")  # noqa: TRY003 -- fixed text
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
        raise TypeError("Secret values cannot be pickled")  # noqa: TRY003 -- fixed text

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
        # TypeError is not wrapped by pydantic, so the rejected plaintext never
        # lands in a ValidationError's errors() or json() output.
        raise SecretTypeError()


class SecretTypeError(TypeError):
    """A plain value was given where a :class:`Secret` is required."""

    def __init__(self) -> None:
        super().__init__("secret fields accept only Secret values read from files")


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


_FILE_PROBLEMS = {
    FileProblem.MISSING: "secret file does not exist",
    FileProblem.PERMISSION_DENIED: "secret file is not readable (permission denied)",
    FileProblem.NOT_REGULAR: "secret file is not a regular file",
    FileProblem.TOO_LARGE: f"secret file is larger than {MAX_SECRET_BYTES} bytes",
}


def _decode(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def read_secret_file(path: str | os.PathLike[str]) -> SecretFile:
    """Read one secret from ``path``.

    The file must be a regular file of at most 4 KiB containing UTF-8 text. One
    trailing newline is stripped; the remaining value must be non-empty and free
    of line breaks and control characters. Errors never chain an exception that
    could hold the file's bytes.
    """
    failure: FileReadError | None = None
    try:
        content = read_regular_file(path, MAX_SECRET_BYTES)
    except FileReadError as exc:
        failure = exc
    if failure is not None:
        reason = _FILE_PROBLEMS.get(failure.problem, f"secret file cannot be read ({failure.code})")
        raise SecretFileError(reason, missing=failure.problem is FileProblem.MISSING)

    text = _decode(content.data)
    if text is None:
        raise SecretFileError("secret file is not valid UTF-8")  # noqa: TRY003 -- fixed text
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if not text:
        raise SecretFileError("secret file is empty")  # noqa: TRY003 -- fixed text
    if _CONTROL.search(text):
        raise SecretFileError(  # noqa: TRY003 -- fixed operator-facing text
            "secret file contains line breaks or control characters"
        )
    permissive = bool(content.mode & (stat.S_IRGRP | stat.S_IROTH))
    return SecretFile(secret=Secret(text), group_or_world_readable=permissive)

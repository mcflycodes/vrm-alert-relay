"""Typed failures of a VRM Diagnostics fetch.

Messages are built only from the operator's installation id (a validated
configuration name), the HTTP status, the timeout phase or transport cause
class name, and fixed text. They never include the token, the request URL,
the VRM site id, response headers or response bodies. Errors are raised
without ``__cause__`` or ``__context__`` so a traceback cannot reach the
underlying HTTP exception either.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Self


class FailureKind(StrEnum):
    """Why a fetch failed, which decides how the caller backs off."""

    AUTH = "auth"
    """401 or 403: the token is wrong, revoked or lacks access. Not transient."""

    RATE_LIMITED = "rate_limited"
    """429: the VRM rate limit applies to the whole token, not one installation."""

    UNAVAILABLE = "unavailable"
    """5xx, 408, timeouts and connection failures. Transient."""

    BAD_RESPONSE = "bad_response"
    """An unusable 2xx response, a redirect, or an unexpected status (1xx, 6xx). Transient."""

    REJECTED = "rejected"
    """Any other 4xx (not 401, 403, 408 or 429), or an unbuildable request. Not transient."""


TRANSIENT_KINDS = frozenset(
    {FailureKind.RATE_LIMITED, FailureKind.UNAVAILABLE, FailureKind.BAD_RESPONSE}
)


class VrmError(Exception):
    """Base class for every failure of a Diagnostics fetch."""

    kind: FailureKind

    def __init__(self, installation: str, detail: str) -> None:
        super().__init__()
        self._bind(installation, detail)

    def _bind(self, installation: str, detail: str) -> None:
        self.installation = installation
        self.detail = detail
        self.message = f"VRM {self.kind.value} for installation {installation!r}: {detail}"
        self.args = (self.message,)

    def for_installation(self, installation: str) -> Self:
        """Return a new error of the same class and fields, attributed to ``installation``.

        The copy has no traceback, ``__cause__`` or ``__context__``.
        """
        clone = type(self).__new__(type(self))
        clone.__dict__.update(self.__dict__)
        clone._bind(installation, self.detail)  # noqa: SLF001  # same class, private by convention
        return clone

    @property
    def transient(self) -> bool:
        """Whether retrying with exponential backoff is appropriate."""
        return self.kind in TRANSIENT_KINDS

    def __str__(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.message!r})"


class VrmAuthError(VrmError):
    """VRM refused the token (401) or access to the installation (403)."""

    kind = FailureKind.AUTH

    def __init__(self, installation: str, *, status: int) -> None:
        super().__init__(installation, f"HTTP {status}")
        self.status = status


class VrmRateLimitedError(VrmError):
    """VRM answered 429. ``retry_after`` is the bounded delay it asked for, if any."""

    kind = FailureKind.RATE_LIMITED

    def __init__(self, installation: str, *, retry_after: float | None) -> None:
        shown = "no Retry-After" if retry_after is None else f"Retry-After {retry_after:g}s"
        super().__init__(installation, f"HTTP 429 ({shown})")
        self.status = 429
        self.retry_after = retry_after


class VrmUnavailableError(VrmError):
    """VRM could not be reached or answered with a server error."""

    kind = FailureKind.UNAVAILABLE

    def __init__(self, installation: str, detail: str, *, status: int | None = None) -> None:
        super().__init__(installation, detail)
        self.status = status


class VrmResponseError(VrmError):
    """The response was oversize, malformed or not shaped like Diagnostics data."""

    kind = FailureKind.BAD_RESPONSE


class VrmRejectedError(VrmError):
    """VRM rejected the request with a non-transient 4xx, or it could not be built."""

    kind = FailureKind.REJECTED

    def __init__(self, installation: str, detail: str, *, status: int | None = None) -> None:
        super().__init__(installation, detail)
        self.status = status

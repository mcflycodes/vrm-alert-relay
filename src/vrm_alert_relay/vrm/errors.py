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


class FailureKind(StrEnum):
    """Why a fetch failed, which decides how the caller backs off."""

    AUTH = "auth"
    """401 or 403: the token is wrong, revoked or lacks access. Not transient."""

    RATE_LIMITED = "rate_limited"
    """429: the VRM rate limit applies to the whole token, not one installation."""

    UNAVAILABLE = "unavailable"
    """5xx, 408, timeouts and connection failures. Transient."""

    BAD_RESPONSE = "bad_response"
    """A 2xx (or unexpected 3xx) response that could not be used. Transient."""

    REJECTED = "rejected"
    """Any other 4xx, or a request that could not be built. Not transient."""


TRANSIENT_KINDS = frozenset(
    {FailureKind.RATE_LIMITED, FailureKind.UNAVAILABLE, FailureKind.BAD_RESPONSE}
)


class VrmError(Exception):
    """Base class for every failure of a Diagnostics fetch."""

    kind: FailureKind

    def __init__(self, installation: str, detail: str) -> None:
        self.installation = installation
        self.detail = detail
        self.message = f"VRM {self.kind.value} for installation {installation!r}: {detail}"
        super().__init__(self.message)

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

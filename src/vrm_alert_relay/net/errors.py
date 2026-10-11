"""Exceptions raised by the outbound HTTP client.

Every message is built only from the HTTP method, the endpoint's display form
(scheme, host, port and path, never the query string or userinfo) and the
status code. Header values, request and response bodies, and httpx's own
messages, which embed full URLs, never reach ``str()``, ``repr()`` or
``args``.
"""

from __future__ import annotations


class HttpError(Exception):
    """Base class for every error raised by :mod:`vrm_alert_relay.net`."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:
        return self.message

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.message!r})"


class InvalidUrlError(HttpError, ValueError):
    """A URL or endpoint failed validation. Raised before any network I/O."""


class InvalidHeaderError(HttpError, ValueError):
    """A header name or value failed validation. Raised before any network I/O."""


class InvalidRequestError(HttpError, ValueError):
    """The request could not be built, e.g. conflicting or unserializable bodies."""


class HttpRequestError(HttpError):
    """A request was attempted and failed."""

    def __init__(self, reason: str, method: str, target: str) -> None:
        super().__init__(f"{reason}: {method} {target}")
        self.method = method
        self.target = target


class HttpTimeout(HttpRequestError):
    """A connect, read, write or pool timeout, or the overall deadline, expired."""

    def __init__(self, method: str, target: str, *, phase: str) -> None:
        super().__init__(f"HTTP timeout ({phase})", method, target)
        self.phase = phase


class HttpTooLarge(HttpRequestError):
    """The response body exceeded the configured size cap."""

    def __init__(self, method: str, target: str, *, limit: int) -> None:
        super().__init__(f"HTTP response exceeded {limit} bytes", method, target)
        self.limit = limit


class HttpRedirectRefused(HttpRequestError):
    """The server answered with a 3xx status. Redirects are never followed."""

    def __init__(self, method: str, target: str, *, status: int) -> None:
        super().__init__(f"HTTP redirect refused ({status})", method, target)
        self.status = status


class HttpStatusError(HttpRequestError):
    """The server answered with a status outside 2xx and 3xx."""

    def __init__(
        self,
        method: str,
        target: str,
        *,
        status: int,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(f"HTTP {status}", method, target)
        self.status = status
        self.retry_after = retry_after


class HttpTransportError(HttpRequestError):
    """A connection, TLS or protocol failure. ``cause`` is the httpx class name."""

    def __init__(self, method: str, target: str, *, cause: str) -> None:
        super().__init__(f"HTTP transport error ({cause})", method, target)
        self.cause = cause


class HttpDecodeError(HttpError):
    """A response body could not be decoded as the requested format."""

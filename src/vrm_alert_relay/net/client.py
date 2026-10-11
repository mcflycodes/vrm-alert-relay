"""Hardened outbound HTTP client shared by every adapter.

Guarantees, none of which can be turned off by callers:

- HTTPS only, validated before any I/O; certificate verification always on.
  Two per-client options exist for providers whose operator opted in, and
  neither weakens any other guarantee: ``ca_file`` replaces the bundled trust
  store with the given PEM bundle (certificates are still verified, including
  the hostname), and ``allow_insecure_http`` also accepts plain ``http`` URLs.
- Redirects are never followed: any 3xx raises :class:`HttpRedirectRefused`.
- Proxy and TLS environment variables are ignored (``trust_env=False``).
- Connect, read, write and pool timeouts, plus an absolute per-request deadline
  enforced on name resolution, each connect attempt, the TLS handshake and
  every socket read and write by :class:`HardenedTransport`.
- The encoded request body is capped (default 64 KiB) before any I/O.
- Compression is refused: ``Accept-Encoding: identity`` is always sent and
  any other ``Content-Encoding`` is rejected before the body is read. The raw
  body is streamed and the request aborts as soon as it exceeds the size cap.
- Header names and values are validated; CR, LF, NUL and other control
  characters are rejected.
- Exceptions carry only the method, the endpoint's display form and the
  status, and have no ``__cause__`` or ``__context__``. Bodies, query strings
  and header values are never logged, and the httpx and httpcore loggers are
  limited to WARNING and above because their records embed full URLs and
  response headers.
"""

from __future__ import annotations

import codecs
import contextlib
import json as jsonlib
import logging
import math
import re
import ssl
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from time import monotonic
from typing import TYPE_CHECKING, Any, Final, Self

import certifi
import httpx

from vrm_alert_relay.net.endpoint import Endpoint
from vrm_alert_relay.net.errors import (
    HttpContentEncodingRefused,
    HttpDecodeError,
    HttpError,
    HttpRedirectRefused,
    HttpStatusError,
    HttpTimeout,
    HttpTooLarge,
    HttpTransportError,
    InvalidCaFileError,
    InvalidHeaderError,
    InvalidRequestError,
    InvalidUrlError,
    RequestTooLargeError,
)
from vrm_alert_relay.net.transport import DnsTimeout, HardenedTransport, deadline_scope

if TYPE_CHECKING:
    import os
    from types import TracebackType

DEFAULT_MAX_REQUEST_BYTES: Final = 64 * 1024
DEFAULT_MAX_RESPONSE_BYTES: Final = 1024 * 1024
DEFAULT_USER_AGENT: Final = "vrm-alert-relay"
MAX_HEADER_VALUE_LENGTH: Final = 8192
MAX_RETRY_AFTER_SECONDS: Final = 86400.0

_ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})
_RESERVED_HEADERS = frozenset(
    {"host", "content-length", "transfer-encoding", "connection", "accept-encoding"}
)
_DEADLINE_SLACK = 0.05
_LIBRARY_LOGGERS = (
    "httpx",
    "httpcore",
    "httpcore.connection",
    "httpcore.http11",
    "httpcore.http2",
    "httpcore.proxy",
    "httpcore.socks",
)
_HEADER_NAME_RE = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}")
_HEADER_VALUE_FORBIDDEN_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_CHARSET_RE = re.compile(r"charset=\"?([A-Za-z0-9._-]{1,40})", re.IGNORECASE)
_RETRY_AFTER_SECONDS_RE = re.compile(r"[0-9]{1,10}")
_TIMEOUT_PHASES: Mapping[type[httpx.TimeoutException], str] = {
    httpx.ConnectTimeout: "connect",
    httpx.ReadTimeout: "read",
    httpx.WriteTimeout: "write",
    httpx.PoolTimeout: "pool",
}

QueryValue = str | int | float | bool | None
QueryParams = (
    Mapping[str, QueryValue] | list[tuple[str, QueryValue]] | tuple[tuple[str, QueryValue], ...]
)
MultipartFile = tuple[str, bytes, str]
"""A file part: ``(filename, content, content_type)``."""
MultipartFields = Mapping[str, str | MultipartFile]

_log = logging.getLogger(__name__)


class _WarningsOnly(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= logging.WARNING


_LIBRARY_FILTER = _WarningsOnly()


def _quiet_library_loggers() -> None:
    for name in _LIBRARY_LOGGERS:
        logger = logging.getLogger(name)
        if _LIBRARY_FILTER not in logger.filters:
            logger.addFilter(_LIBRARY_FILTER)


def _verifying_context(cafile: str | os.PathLike[str]) -> ssl.SSLContext:
    """A client context that verifies certificates and hostnames against ``cafile``.

    Built by hand rather than with :func:`ssl.create_default_context` (which
    httpx also uses), because that function honours ``SSLKEYLOGFILE`` and
    would write TLS session secrets to the file it names. This context never
    has a key log file.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=cafile)
    return context


def _tls_context() -> ssl.SSLContext:
    """The default context: the bundled (certifi) trust store."""
    return _verifying_context(certifi.where())


def load_ca_file(path: str | os.PathLike[str]) -> ssl.SSLContext:
    """A verifying TLS context that trusts only the PEM certificates in ``path``.

    Hostname checking and certificate verification stay on. Raises
    :class:`InvalidCaFileError`, whose message never includes the path or the
    file's content, when the file cannot be read or holds no certificate.
    """
    try:
        return _verifying_context(path)
    except (OSError, ValueError, TypeError):
        pass
    # Raised outside the except block so no ssl or OS error, which can name
    # the path, is chained.
    raise InvalidCaFileError("CA file could not be loaded as PEM certificates")  # noqa: TRY003  # message is specific to this check


@dataclass(frozen=True, slots=True)
class Timeouts:
    """Per-operation timeouts and the overall per-request deadline, in seconds."""

    connect: float = 5.0
    read: float = 10.0
    write: float = 10.0
    pool: float = 5.0
    deadline: float = 30.0

    def __post_init__(self) -> None:
        for name in ("connect", "read", "write", "pool", "deadline"):
            value = getattr(self, name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int | float)
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(f"timeout {name!r} must be a positive finite number")  # noqa: TRY003  # message is specific to this check


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """A fully read 2xx response. ``repr()`` never includes headers or body."""

    status_code: int
    headers: httpx.Headers = field(repr=False)
    content: bytes = field(repr=False)

    def text(self) -> str:
        """Decode the body using the declared charset, falling back to UTF-8."""
        encoding = "utf-8"
        match = _CHARSET_RE.search(self.headers.get("content-type", ""))
        if match:
            with contextlib.suppress(LookupError):
                encoding = codecs.lookup(match.group(1)).name
        return self.content.decode(encoding, errors="replace")

    def json(self) -> Any:  # noqa: ANN401  # JSON payloads are arbitrary
        """Parse the body as JSON, raising :class:`HttpDecodeError` on failure."""
        try:
            return jsonlib.loads(self.content)
        except (ValueError, RecursionError):
            pass
        raise HttpDecodeError("response body is not valid JSON")  # noqa: TRY003  # message is specific to this check


class SafeHttpClient:
    """The only HTTP client adapters may use. See the module docstring."""

    def __init__(  # noqa: PLR0913  # keyword-only client options
        self,
        *,
        timeouts: Timeouts | None = None,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES,
        user_agent: str = DEFAULT_USER_AGENT,
        headers: Mapping[str, str] | None = None,
        ca_file: str | os.PathLike[str] | None = None,
        allow_insecure_http: bool = False,
    ) -> None:
        if not isinstance(allow_insecure_http, bool):
            raise TypeError("allow_insecure_http must be a bool")  # noqa: TRY003  # message is specific to this check
        self._allow_insecure_http = allow_insecure_http
        self._timeouts = timeouts if timeouts is not None else Timeouts()
        self._max_response_bytes = _validate_limit(max_response_bytes)
        self._max_request_bytes = _validate_limit(max_request_bytes, "max_request_bytes")
        _validate_header_value("User-Agent", user_agent)
        default_headers = {"User-Agent": user_agent}
        default_headers.update(_validate_headers(headers))
        default_headers["Accept-Encoding"] = "identity"
        _quiet_library_loggers()
        self._client = httpx.Client(
            transport=HardenedTransport(
                ssl_context=_tls_context() if ca_file is None else load_ca_file(ca_file)
            ),
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(
                connect=self._timeouts.connect,
                read=self._timeouts.read,
                write=self._timeouts.write,
                pool=self._timeouts.pool,
            ),
            headers=default_headers,
        )

    @property
    def timeouts(self) -> Timeouts:
        return self._timeouts

    @property
    def allow_insecure_http(self) -> bool:
        return self._allow_insecure_http

    @property
    def max_response_bytes(self) -> int:
        return self._max_response_bytes

    @property
    def max_request_bytes(self) -> int:
        return self._max_request_bytes

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def get(
        self,
        target: Endpoint | str,
        *,
        params: QueryParams | None = None,
        headers: Mapping[str, str] | None = None,
        max_response_bytes: int | None = None,
    ) -> HttpResponse:
        return self.request(
            "GET",
            target,
            params=params,
            headers=headers,
            max_response_bytes=max_response_bytes,
        )

    def post(  # noqa: PLR0913  # keyword-only request options
        self,
        target: Endpoint | str,
        *,
        params: QueryParams | None = None,
        headers: Mapping[str, str] | None = None,
        json: Any = None,  # noqa: ANN401  # JSON payloads are arbitrary
        form: Mapping[str, str] | None = None,
        multipart: MultipartFields | None = None,
        max_response_bytes: int | None = None,
    ) -> HttpResponse:
        return self.request(
            "POST",
            target,
            params=params,
            headers=headers,
            json=json,
            form=form,
            multipart=multipart,
            max_response_bytes=max_response_bytes,
        )

    def request(  # noqa: PLR0913  # keyword-only request options
        self,
        method: str,
        target: Endpoint | str,
        *,
        params: QueryParams | None = None,
        headers: Mapping[str, str] | None = None,
        json: Any = None,  # noqa: ANN401  # JSON payloads are arbitrary
        form: Mapping[str, str] | None = None,
        multipart: MultipartFields | None = None,
        max_response_bytes: int | None = None,
    ) -> HttpResponse:
        """Send a request and return the fully read 2xx response.

        At most one of ``json``, ``form`` (URL-encoded) and ``multipart`` may be
        given. ``params`` are merged into any query string the endpoint already
        has. Secrets may be passed in any of these; none of them appear in
        exceptions or logs raised by this client.
        """
        endpoint = (
            target
            if isinstance(target, Endpoint)
            else Endpoint(target, allow_http=self._allow_insecure_http)
        )
        if endpoint.scheme != "https" and not self._allow_insecure_http:
            raise InvalidUrlError("plain http is not allowed for this client")  # noqa: TRY003  # message is specific to this check
        method = _validate_method(method)
        limit = (
            self._max_response_bytes
            if max_response_bytes is None
            else _validate_limit(max_response_bytes)
        )
        request = self._build_request(method, endpoint, params, headers, json, form, multipart)
        shown = endpoint.display

        start = monotonic()
        deadline = start + self._timeouts.deadline
        with deadline_scope(deadline):
            response = self._send(request, method, shown, deadline)
            try:
                status = response.status_code
                if 300 <= status < 400:  # noqa: PLR2004  # HTTP status class boundaries
                    raise HttpRedirectRefused(method, shown, status=status)
                if not 200 <= status < 300:  # noqa: PLR2004  # HTTP status class boundaries
                    retry_after = _parse_retry_after(response.headers.get("retry-after"))
                    raise HttpStatusError(method, shown, status=status, retry_after=retry_after)
                content = _read_body(response, method, shown, limit, deadline)
            finally:
                with contextlib.suppress(httpx.HTTPError, httpx.StreamError):
                    response.close()

        _log.debug(
            "http request completed",
            extra={
                "http_method": method,
                "http_target": shown,
                "http_status": status,
                "http_bytes": len(content),
                "elapsed_ms": round((monotonic() - start) * 1000),
            },
        )
        return HttpResponse(status_code=status, headers=response.headers, content=content)

    def _send(
        self, request: httpx.Request, method: str, shown: str, deadline: float
    ) -> httpx.Response:
        # The sanitized error is raised after the except block so that it has
        # no __context__ pointing at httpx's exception, whose text has the URL.
        try:
            return self._client.send(request, stream=True)
        except httpx.TimeoutException as exc:
            error: HttpError = HttpTimeout(method, shown, phase=_timeout_phase(exc, deadline))
        except (httpx.HTTPError, httpx.InvalidURL, httpx.StreamError) as exc:
            error = HttpTransportError(method, shown, cause=type(exc).__name__)
        raise error

    def _build_request(  # noqa: PLR0913, PLR0917  # internal helper mirrors request()
        self,
        method: str,
        endpoint: Endpoint,
        params: QueryParams | None,
        headers: Mapping[str, str] | None,
        json: Any,  # noqa: ANN401  # JSON payloads are arbitrary
        form: Mapping[str, str] | None,
        multipart: MultipartFields | None,
    ) -> httpx.Request:
        bodies = sum(body is not None for body in (json, form, multipart))
        if bodies > 1:
            raise InvalidRequestError("only one of json, form and multipart may be given")  # noqa: TRY003  # message is specific to this check
        files = _multipart_files(multipart) if multipart is not None else None
        request_headers = _validate_headers(headers)
        _validate_params(params)

        url = endpoint.url
        try:
            if params:
                url = url.copy_merge_params(params)
            request = self._client.build_request(
                method,
                url,
                headers=request_headers,
                json=json,
                data=form,
                files=files,
            )
            size = len(request.read())
        except (TypeError, ValueError, RecursionError, httpx.InvalidURL):
            pass
        else:
            if size > self._max_request_bytes:
                raise RequestTooLargeError(method, endpoint.display, limit=self._max_request_bytes)
            return request
        raise InvalidRequestError(  # noqa: TRY003  # message is specific to this check
            f"request body or parameters could not be encoded: {method} {endpoint.display}"
        )


def _read_body(
    response: httpx.Response, method: str, shown: str, limit: int, deadline: float
) -> bytes:
    encodings = response.headers.get_list("content-encoding", split_commas=True)
    if any(token.strip().lower() not in ("", "identity") for token in encodings):
        raise HttpContentEncodingRefused(method, shown)
    declared = response.headers.get("content-length")
    if declared is not None and declared.isascii() and declared.isdigit() and int(declared) > limit:
        raise HttpTooLarge(method, shown, limit=limit)
    if monotonic() > deadline:
        raise HttpTimeout(method, shown, phase="deadline")

    body = bytearray()
    try:
        for chunk in response.iter_raw():
            body += chunk
            if len(body) > limit:
                raise HttpTooLarge(method, shown, limit=limit)
            if monotonic() > deadline:
                raise HttpTimeout(method, shown, phase="deadline")
        return bytes(body)
    except httpx.TimeoutException as exc:
        error: HttpError = HttpTimeout(method, shown, phase=_timeout_phase(exc, deadline))
    except (httpx.HTTPError, httpx.StreamError) as exc:
        error = HttpTransportError(method, shown, cause=type(exc).__name__)
    raise error


def _validate_method(method: object) -> str:
    if not isinstance(method, str) or method.upper() not in _ALLOWED_METHODS:
        raise InvalidRequestError("unsupported HTTP method")  # noqa: TRY003  # message is specific to this check
    return method.upper()


def _validate_limit(limit: object, name: str = "max_response_bytes") -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError(f"{name} must be a positive integer")  # noqa: TRY003  # message is specific to this check
    return limit


def _validate_params(params: QueryParams | None) -> None:
    if params is None:
        return
    pairs = params.items() if isinstance(params, Mapping) else params
    for pair in pairs:
        if not isinstance(pair, tuple) or len(pair) != 2:  # noqa: PLR2004  # (name, value) pair
            raise InvalidRequestError("query parameters must be (name, value) pairs")  # noqa: TRY003  # message is specific to this check
        name, value = pair
        if not isinstance(name, str) or not isinstance(value, str | int | float | None):
            raise InvalidRequestError(  # noqa: TRY003  # message is specific to this check
                "query parameter names must be str and values str, int, float, bool or None"
            )


def _validate_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    if headers is None:
        return {}
    validated: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not _HEADER_NAME_RE.fullmatch(name):
            raise InvalidHeaderError("invalid header name")  # noqa: TRY003  # message is specific to this check
        if name.lower() in _RESERVED_HEADERS:
            raise InvalidHeaderError(f"header {name!r} is managed by the client")  # noqa: TRY003  # message is specific to this check
        _validate_header_value(name, value)
        validated[name] = value
    return validated


def _validate_header_value(name: str, value: object) -> None:
    if not isinstance(value, str):
        raise InvalidHeaderError(f"value of header {name!r} must be a string")  # noqa: TRY003  # message is specific to this check
    if len(value) > MAX_HEADER_VALUE_LENGTH:
        raise InvalidHeaderError(f"value of header {name!r} is too long")  # noqa: TRY003  # message is specific to this check
    if _HEADER_VALUE_FORBIDDEN_RE.search(value):
        raise InvalidHeaderError(f"value of header {name!r} contains control characters")  # noqa: TRY003  # message is specific to this check


def _multipart_files(
    multipart: MultipartFields,
) -> list[tuple[str, tuple[str | None, str | bytes] | tuple[str, bytes, str]]]:
    if not multipart:
        raise InvalidRequestError("multipart body must have at least one field")  # noqa: TRY003  # message is specific to this check
    files: list[tuple[str, tuple[str | None, str | bytes] | tuple[str, bytes, str]]] = []
    for name, value in multipart.items():
        if not isinstance(name, str):
            raise InvalidRequestError("multipart field names must be strings")  # noqa: TRY003  # message is specific to this check
        if isinstance(value, str):
            files.append((name, (None, value)))
            continue
        if (
            not isinstance(value, tuple)
            or len(value) != 3  # noqa: PLR2004  # (filename, bytes, content_type) triple
            or not isinstance(value[0], str)
            or not isinstance(value[1], bytes)
            or not isinstance(value[2], str)
        ):
            raise InvalidRequestError(  # noqa: TRY003  # message is specific to this check
                f"multipart field {name!r} must be a str or (filename, bytes, content_type)"
            )
        _validate_header_value("Content-Type", value[2])
        files.append((name, value))
    return files


def _timeout_phase(exc: httpx.TimeoutException, deadline: float) -> str:
    if isinstance(exc, DnsTimeout):
        return "dns"
    if deadline - monotonic() <= _DEADLINE_SLACK:
        return "deadline"
    for exc_type, phase in _TIMEOUT_PHASES.items():
        if isinstance(exc, exc_type):
            return phase
    return "unknown"


def _parse_retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    value = value.strip()
    if _RETRY_AFTER_SECONDS_RE.fullmatch(value):
        seconds = float(value)
    else:
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError, OverflowError):
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        seconds = (when - datetime.now(UTC)).total_seconds()
    return min(max(seconds, 0.0), MAX_RETRY_AFTER_SECONDS)

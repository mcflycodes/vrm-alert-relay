"""Validated HTTPS base URLs that adapters join path segments onto."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import quote, urlsplit

import httpx

from vrm_alert_relay.net.errors import InvalidUrlError

MAX_URL_LENGTH = 2048
_REDACTED_PATH = "/[REDACTED]"
_SCHEME_RE = re.compile(r"[a-z][a-z0-9+.-]{0,15}")
_FORBIDDEN_CHAR_RE = re.compile(r"[\x00-\x20\x7f\\]")
_HOST_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
_HOSTNAME_RE = re.compile(rf"{_HOST_LABEL}(?:\.{_HOST_LABEL})*\.?")

PathSegment = str | int


class Endpoint:
    """An HTTPS base URL validated once, at configuration time.

    Only ``https`` with a non-empty host is accepted. Userinfo, fragments,
    whitespace, control characters and backslashes are rejected. A query
    string is allowed and kept, but never shown by :attr:`display`, ``str()``
    or ``repr()``.

    :meth:`join` percent-encodes every segment, including ``/``, ``%``, ``?``,
    ``#`` and ``@``, so untrusted data can extend the path but can never change
    the scheme, host, port or query.

    Set ``secret_path`` for URLs whose path carries a credential, such as
    webhook URLs with an embedded token; the path is then shown as
    ``/[REDACTED]``.
    """

    __slots__ = ("_secret_path", "_url")

    _url: httpx.URL
    _secret_path: bool

    def __init__(self, url: str, *, secret_path: bool = False) -> None:
        self._url = _parse(url)
        self._secret_path = secret_path

    @classmethod
    def _from_url(cls, url: httpx.URL, *, secret_path: bool) -> Endpoint:
        endpoint = cls.__new__(cls)
        endpoint._url = url
        endpoint._secret_path = secret_path
        return endpoint

    @property
    def url(self) -> httpx.URL:
        """The full URL, including any query string. Do not log it."""
        return self._url

    @property
    def host(self) -> str:
        """The host, IDNA-encoded for internationalized names."""
        return self._url.raw_host.decode("ascii")

    @property
    def port(self) -> int | None:
        return self._url.port

    @property
    def path(self) -> str:
        """The percent-encoded path, without the query string."""
        return self._url.raw_path.split(b"?", 1)[0].decode("ascii")

    @property
    def secret_path(self) -> bool:
        return self._secret_path

    @property
    def display(self) -> str:
        """Scheme, host, port and path, safe for logs and exception messages."""
        host = self.host
        if ":" in host:
            host = f"[{host}]"
        port = f":{self.port}" if self.port is not None else ""
        path = _REDACTED_PATH if self._secret_path else self.path
        return f"https://{host}{port}{path}"

    def join(self, *segments: PathSegment) -> Endpoint:
        """Return a new endpoint with ``segments`` appended to the path.

        Each segment is percent-encoded as a single path segment. Empty, ``.``
        and ``..`` segments are rejected because they would be collapsed or
        resolved and could escape the base path.
        """
        encoded: list[str] = []
        for segment in segments:
            if isinstance(segment, bool) or not isinstance(segment, str | int):
                raise InvalidUrlError("path segments must be str or int")
            text = str(segment)
            if text in ("", ".", ".."):
                raise InvalidUrlError("path segments must not be empty, '.' or '..'")
            encoded.append(quote(text, safe=""))
        if not encoded:
            return self
        base = self.path.rstrip("/")
        new_path = base + "/" + "/".join(encoded)
        joined = self._url.copy_with(path=new_path)
        if (
            joined.raw_host != self._url.raw_host or joined.port != self._url.port
        ):  # pragma: no cover
            raise InvalidUrlError("path join changed the destination")
        return Endpoint._from_url(joined, secret_path=self._secret_path)

    def __str__(self) -> str:
        return self.display

    def __repr__(self) -> str:
        return f"Endpoint({self.display!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Endpoint):
            return NotImplemented
        return self._url == other._url and self._secret_path == other._secret_path

    def __hash__(self) -> int:
        return hash((str(self._url), self._secret_path))


def _parse(url: object) -> httpx.URL:
    if not isinstance(url, str):
        raise InvalidUrlError("URL must be a string")
    if not url:
        raise InvalidUrlError("URL must not be empty")
    if len(url) > MAX_URL_LENGTH:
        raise InvalidUrlError(f"URL is longer than {MAX_URL_LENGTH} characters")
    if _FORBIDDEN_CHAR_RE.search(url):
        raise InvalidUrlError(
            "URL contains whitespace, control characters or backslashes"
        )
    if "#" in url:
        raise InvalidUrlError("URL must not contain a fragment")

    try:
        split = urlsplit(url)
    except ValueError:
        raise InvalidUrlError("URL could not be parsed") from None
    scheme = split.scheme.lower()
    if scheme != "https":
        shown = (
            repr(scheme) if _SCHEME_RE.fullmatch(scheme) else "an unsupported scheme"
        )
        raise InvalidUrlError(f"URL scheme must be https, not {shown}")
    if "@" in split.netloc:
        raise InvalidUrlError("URL must not contain userinfo")
    try:
        port = split.port
    except ValueError:
        port = 0
    if port is not None and not 1 <= port <= 65535:
        raise InvalidUrlError("URL port must be between 1 and 65535")

    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, ValueError, TypeError):
        raise InvalidUrlError("URL could not be parsed") from None

    if (
        parsed.scheme != "https" or parsed.userinfo
    ):  # pragma: no cover - urlsplit checks
        raise InvalidUrlError("URL scheme must be https, without userinfo")
    host = parsed.raw_host.decode("ascii")
    if not host:
        raise InvalidUrlError("URL must have a host")
    if not _valid_host(host):
        raise InvalidUrlError("URL host is not a valid hostname or IP address")
    if (parsed.port or 443) != (port or 443):  # pragma: no cover - parsers agree
        raise InvalidUrlError("URL port could not be parsed")
    return parsed


def _valid_host(host: str) -> bool:
    if ":" in host:
        try:
            ipaddress.IPv6Address(host)
        except ValueError:
            return False
        return "%" not in host
    return len(host) <= 253 and _HOSTNAME_RE.fullmatch(host) is not None

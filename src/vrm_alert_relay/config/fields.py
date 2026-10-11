"""Validated scalar types used by the configuration models."""

from __future__ import annotations

import ipaddress
import os
import re
from collections.abc import Callable
from typing import Annotated, Any
from urllib.parse import urlsplit

from pydantic import AfterValidator, GetCoreSchemaHandler
from pydantic_core import CoreSchema, core_schema

__all__ = [
    "MAX_TEMPLATE_CHARS",
    "BindAddress",
    "HaServiceName",
    "HeaderName",
    "HttpsUrl",
    "MeasurementCode",
    "MessageTemplate",
    "Name",
    "PhoneNumber",
    "SecretPath",
    "ServiceType",
]

MAX_TEMPLATE_CHARS = 320
MAX_URL_CHARS = 2048
MAX_PATH_CHARS = 4096

CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")
_HOST_LABELS = re.compile(
    r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?"
)
# Headers that control HTTP framing or routing; the transport owns them.
_RESERVED_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "content-type",
        "host",
        "keep-alive",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)


def _pattern(regex: str, description: str) -> Callable[[str], str]:
    compiled = re.compile(regex)

    def check(value: str) -> str:
        if not compiled.fullmatch(value):
            raise ValueError(description)
        return value

    return check


Name = Annotated[
    str,
    AfterValidator(
        _pattern(
            r"[a-z0-9][a-z0-9_-]{0,62}",
            "must be 1-63 lowercase letters, digits, '_' or '-', "
            "starting with a letter or digit",
        )
    ),
]

MeasurementCode = Annotated[
    str,
    AfterValidator(
        _pattern(r"[A-Za-z0-9_]{1,32}", "must be 1-32 letters, digits, or '_'")
    ),
]

ServiceType = Annotated[
    str,
    AfterValidator(
        _pattern(
            r"[A-Za-z0-9_.-]{1,64}",
            "must be 1-64 letters, digits, '_', '.', or '-'",
        )
    ),
]

HaServiceName = Annotated[
    str,
    AfterValidator(
        _pattern(
            r"[a-z0-9_]{1,255}",
            "must be a Home Assistant notify service name "
            "(lowercase letters, digits, '_'), without the 'notify.' prefix",
        )
    ),
]


def _check_header_name(value: str) -> str:
    if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}", value):
        raise ValueError("must be a valid HTTP header name of at most 64 characters")
    if value.lower() in _RESERVED_HEADERS or value.lower().startswith("proxy-"):
        raise ValueError("must not be a header that the HTTP transport controls")
    return value


HeaderName = Annotated[str, AfterValidator(_check_header_name)]


def _check_template(value: str) -> str:
    if not value:
        raise ValueError("must not be empty")
    if len(value) > MAX_TEMPLATE_CHARS:
        raise ValueError(f"must be at most {MAX_TEMPLATE_CHARS} characters")
    if CONTROL_CHARS.search(value):
        raise ValueError("must not contain line breaks or control characters")
    return value


MessageTemplate = Annotated[str, AfterValidator(_check_template)]


def _check_secret_path(value: str) -> str:
    # Never echo the value: an operator may have pasted the secret itself here.
    if not value:
        raise ValueError("must not be empty")
    if len(value) > MAX_PATH_CHARS:
        raise ValueError(f"must be at most {MAX_PATH_CHARS} characters")
    if CONTROL_CHARS.search(value):
        raise ValueError("must not contain line breaks or control characters")
    if not os.path.isabs(value):
        raise ValueError("must be an absolute path to a secret file")
    return value


SecretPath = Annotated[str, AfterValidator(_check_secret_path)]


def _check_host(host: str) -> None:
    if host.startswith("["):
        try:
            ipaddress.IPv6Address(host[1:-1] if host.endswith("]") else host)
        except ValueError:
            raise ValueError("has an invalid IPv6 host") from None
        return
    if not _HOST_LABELS.fullmatch(host):
        raise ValueError("has an invalid host name (use ASCII or punycode)")


def _check_https_url(value: str) -> str:
    # The value is not echoed in errors because query strings may carry tokens.
    if len(value) > MAX_URL_CHARS:
        raise ValueError(f"must be at most {MAX_URL_CHARS} characters")
    if CONTROL_CHARS.search(value) or any(c.isspace() for c in value) or "\\" in value:
        raise ValueError("must not contain whitespace, control characters, or '\\'")
    try:
        parts = urlsplit(value)
    except ValueError:
        raise ValueError("is not a valid URL") from None
    if parts.scheme != "https":
        raise ValueError("must be an https:// URL")
    if "#" in value:
        raise ValueError("must not contain a fragment ('#')")
    authority = parts.netloc
    if "@" in authority:
        raise ValueError("must not contain user info (credentials) before the host")
    host = authority
    if host.startswith("["):
        end = host.find("]")
        host = host[: end + 1] if end != -1 else host
    else:
        host = host.rsplit(":", 1)[0]
    if not host:
        raise ValueError("must include a host")
    _check_host(host)
    try:
        port = parts.port
    except ValueError:
        raise ValueError("has an invalid port") from None
    if port == 0:
        raise ValueError("has an invalid port")
    return value


HttpsUrl = Annotated[str, AfterValidator(_check_https_url)]


def _check_bind(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise ValueError("must be an IPv4 or IPv6 address") from None


BindAddress = Annotated[str, AfterValidator(_check_bind)]


_PHONE_SEPARATORS = re.compile(r"[ ().-]")
_PHONE_ERROR = "must be a 10-digit NANP number or a +1 E.164 number"


class PhoneNumber:
    """A validated North American phone number.

    ``str``, ``repr``, and serialization show only the last four digits. Use
    :attr:`e164` or :attr:`national` when the full number is required.
    """

    __slots__ = ("_national",)

    def __init__(self, national: str) -> None:
        if not re.fullmatch(r"[2-9][0-9]{2}[2-9][0-9]{6}", national):
            raise ValueError(_PHONE_ERROR)
        self._national = national

    @classmethod
    def parse(cls, value: str) -> PhoneNumber:
        """Parse a 10-digit NANP number or a +1 E.164 number, ignoring separators."""
        compact = _PHONE_SEPARATORS.sub("", value) if len(value) <= 32 else ""
        if compact.startswith("+1"):
            national = compact[2:]
        elif compact.startswith("+"):
            national = ""
        elif len(compact) == 11 and compact.startswith("1"):
            national = compact[1:]
        else:
            national = compact
        try:
            return cls(national)
        except ValueError:
            digits = re.sub(r"[^0-9]", "", value)
            hint = f" (value ending {digits[-4:]})" if len(digits) >= 4 else ""
            raise ValueError(f"{_PHONE_ERROR}{hint}") from None

    @property
    def national(self) -> str:
        """The ten-digit national number, for example ``2025550123``."""
        return self._national

    @property
    def e164(self) -> str:
        """The E.164 form, for example ``+12025550123``."""
        return f"+1{self._national}"

    @property
    def last4(self) -> str:
        return self._national[-4:]

    @property
    def masked(self) -> str:
        return f"***-***-{self.last4}"

    def __str__(self) -> str:
        return self.masked

    def __repr__(self) -> str:
        return f"PhoneNumber('{self.masked}')"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PhoneNumber):
            return NotImplemented
        return self._national == other._national

    def __hash__(self) -> int:
        return hash(self._national)

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: type[Any], handler: GetCoreSchemaHandler
    ) -> CoreSchema:
        return core_schema.no_info_plain_validator_function(
            cls._validate,
            serialization=core_schema.plain_serializer_function_ser_schema(
                _masked_phone, when_used="always"
            ),
        )

    @classmethod
    def _validate(cls, value: object) -> PhoneNumber:
        if isinstance(value, PhoneNumber):
            return value
        if isinstance(value, str):
            return cls.parse(value)
        # A ValueError (not TypeError) so pydantic reports it as a field problem.
        raise ValueError("must be a string (quote phone numbers in YAML)")


def _masked_phone(value: PhoneNumber) -> str:
    return value.masked

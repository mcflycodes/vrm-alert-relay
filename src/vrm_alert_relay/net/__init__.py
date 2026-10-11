"""Hardened outbound HTTP for VRM and notification-provider adapters."""

from vrm_alert_relay.net.client import (
    DEFAULT_MAX_RESPONSE_BYTES,
    HttpResponse,
    MultipartFields,
    MultipartFile,
    QueryParams,
    SafeHttpClient,
    Timeouts,
)
from vrm_alert_relay.net.endpoint import Endpoint
from vrm_alert_relay.net.errors import (
    HttpDecodeError,
    HttpError,
    HttpRedirectRefused,
    HttpRequestError,
    HttpStatusError,
    HttpTimeout,
    HttpTooLarge,
    HttpTransportError,
    InvalidHeaderError,
    InvalidRequestError,
    InvalidUrlError,
)

__all__ = [
    "DEFAULT_MAX_RESPONSE_BYTES",
    "Endpoint",
    "HttpDecodeError",
    "HttpError",
    "HttpRedirectRefused",
    "HttpRequestError",
    "HttpResponse",
    "HttpStatusError",
    "HttpTimeout",
    "HttpTooLarge",
    "HttpTransportError",
    "InvalidHeaderError",
    "InvalidRequestError",
    "InvalidUrlError",
    "MultipartFields",
    "MultipartFile",
    "QueryParams",
    "SafeHttpClient",
    "Timeouts",
]

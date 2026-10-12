"""Mapping HTTP failures to provider outcomes.

The rule is: a failure that happened before the request could have reached
the provider is ``FAILED`` (retryable when it may be transient); a failure
after the request may have been processed is ``AMBIGUOUS``, so the delivery
engine reconciles before it retries.
"""

from __future__ import annotations

from typing import Final

from vrm_alert_relay.delivery.protocol import SendResult, SendStatus
from vrm_alert_relay.net import (
    HttpError,
    HttpRedirectRefused,
    HttpStatusError,
    HttpTimeout,
    HttpTransportError,
    InvalidHeaderError,
    InvalidRequestError,
    InvalidUrlError,
)

__all__ = [
    "AMBIGUOUS",
    "DELIVERED",
    "FAILED",
    "FAILED_RETRYABLE",
    "result_for_error",
    "result_for_status",
]

DELIVERED: Final = SendResult(SendStatus.DELIVERED)
FAILED: Final = SendResult(SendStatus.FAILED, retryable=False)
FAILED_RETRYABLE: Final = SendResult(SendStatus.FAILED, retryable=True)
AMBIGUOUS: Final = SendResult(SendStatus.AMBIGUOUS, retryable=True)

# Timeouts in these phases happen before any byte of the request is sent.
_PRE_SEND_PHASES: Final = frozenset({"dns", "connect", "pool"})
# Transport failures of these httpx classes happen while connecting.
_PRE_SEND_CAUSES: Final = frozenset({"ConnectError", "ConnectTimeout", "DnsTimeout", "PoolTimeout"})
_RETRYABLE_CLIENT_STATUSES: Final = frozenset({408, 425, 429})
_CLIENT_ERROR: Final = 400
_SERVER_ERROR: Final = 500


def result_for_status(status: int) -> SendResult:
    """The outcome of a non-2xx, non-3xx response status."""
    if status in _RETRYABLE_CLIENT_STATUSES:
        return FAILED_RETRYABLE
    if _CLIENT_ERROR <= status < _SERVER_ERROR:
        return FAILED
    return AMBIGUOUS


def result_for_error(error: HttpError) -> SendResult:
    """The outcome of a request that raised ``error``."""
    if isinstance(error, HttpStatusError):
        return result_for_status(error.status)
    if isinstance(error, HttpRedirectRefused):
        # The request reached the endpoint, which may have acted on it before
        # answering with a redirect. The redirect itself is never followed.
        return AMBIGUOUS
    if isinstance(error, InvalidUrlError | InvalidHeaderError | InvalidRequestError):
        return FAILED
    if isinstance(error, HttpTimeout):
        return FAILED_RETRYABLE if error.phase in _PRE_SEND_PHASES else AMBIGUOUS
    if isinstance(error, HttpTransportError):
        return FAILED_RETRYABLE if error.cause in _PRE_SEND_CAUSES else AMBIGUOUS
    return AMBIGUOUS

"""How HTTP client errors map to provider outcomes."""

from __future__ import annotations

import pytest

from vrm_alert_relay.delivery.protocol import SendStatus
from vrm_alert_relay.net import (
    HttpContentEncodingRefused,
    HttpDecodeError,
    HttpError,
    HttpRedirectRefused,
    HttpStatusError,
    HttpTimeout,
    HttpTooLarge,
    HttpTransportError,
    InvalidHeaderError,
    InvalidRequestError,
    InvalidUrlError,
    RequestTooLargeError,
)
from vrm_alert_relay.providers._http import result_for_error

TARGET = "https://hooks.example.test/relay"


@pytest.mark.parametrize(
    ("error", "status", "retryable"),
    [
        (InvalidUrlError("fictitious"), SendStatus.FAILED, False),
        (InvalidHeaderError("fictitious"), SendStatus.FAILED, False),
        (InvalidRequestError("fictitious"), SendStatus.FAILED, False),
        (RequestTooLargeError("POST", TARGET, limit=1), SendStatus.FAILED, False),
        (HttpRedirectRefused("POST", TARGET, status=302), SendStatus.AMBIGUOUS, True),
        (HttpStatusError("POST", TARGET, status=503), SendStatus.AMBIGUOUS, True),
        (HttpStatusError("POST", TARGET, status=429), SendStatus.FAILED, True),
        (HttpStatusError("POST", TARGET, status=403), SendStatus.FAILED, False),
        (HttpTimeout("POST", TARGET, phase="dns"), SendStatus.FAILED, True),
        (HttpTimeout("POST", TARGET, phase="read"), SendStatus.AMBIGUOUS, True),
        (HttpTimeout("POST", TARGET, phase="deadline"), SendStatus.AMBIGUOUS, True),
        (HttpTransportError("POST", TARGET, cause="ConnectError"), SendStatus.FAILED, True),
        (HttpTransportError("POST", TARGET, cause="ReadError"), SendStatus.AMBIGUOUS, True),
        (HttpTooLarge("POST", TARGET, limit=1), SendStatus.AMBIGUOUS, True),
        (HttpContentEncodingRefused("POST", TARGET), SendStatus.AMBIGUOUS, True),
        (HttpDecodeError("fictitious"), SendStatus.AMBIGUOUS, True),
    ],
)
def test_result_for_error(error: HttpError, status: SendStatus, retryable: bool) -> None:
    result = result_for_error(error)
    assert (result.status, result.retryable) == (status, retryable)

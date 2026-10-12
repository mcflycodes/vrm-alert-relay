"""VRM Diagnostics adapter: fetch, normalise and back off. No scheduling."""

from vrm_alert_relay.vrm.adapter import (
    AUTH_HEADER,
    DEFAULT_MAX_RESPONSE_BYTES,
    DIAGNOSTICS_COUNT,
    InstallationOutcome,
    InstallationReading,
    PollResult,
    VrmAdapter,
)
from vrm_alert_relay.vrm.backoff import Backoff, BackoffPolicy, BackoffState
from vrm_alert_relay.vrm.diagnostics import (
    MAX_LABEL_LENGTH,
    MAX_RECORDS,
    MAX_UNIT_LENGTH,
    MeasurementResult,
    ReadingProblem,
    TimestampPolicy,
    parse_diagnostics,
    sanitize_label,
    unit_from_format,
)
from vrm_alert_relay.vrm.errors import (
    TRANSIENT_KINDS,
    FailureKind,
    VrmAuthError,
    VrmError,
    VrmRateLimitedError,
    VrmRejectedError,
    VrmResponseError,
    VrmUnavailableError,
)

__all__ = [
    "AUTH_HEADER",
    "DEFAULT_MAX_RESPONSE_BYTES",
    "DIAGNOSTICS_COUNT",
    "MAX_LABEL_LENGTH",
    "MAX_RECORDS",
    "MAX_UNIT_LENGTH",
    "TRANSIENT_KINDS",
    "Backoff",
    "BackoffPolicy",
    "BackoffState",
    "FailureKind",
    "InstallationOutcome",
    "InstallationReading",
    "MeasurementResult",
    "PollResult",
    "ReadingProblem",
    "TimestampPolicy",
    "VrmAdapter",
    "VrmAuthError",
    "VrmError",
    "VrmRateLimitedError",
    "VrmRejectedError",
    "VrmResponseError",
    "VrmUnavailableError",
    "parse_diagnostics",
    "sanitize_label",
    "unit_from_format",
]

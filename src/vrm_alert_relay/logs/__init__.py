"""Structured JSON logging with redaction of secrets and recipient identifiers."""

from vrm_alert_relay.logs.config import JsonFormatter, configure_logging
from vrm_alert_relay.logs.redaction import (
    REDACTED,
    SecretRegistry,
    mask_recipient,
    redact_mapping,
    redact_text,
    redact_value,
    register_secret,
)

__all__ = [
    "REDACTED",
    "JsonFormatter",
    "SecretRegistry",
    "configure_logging",
    "mask_recipient",
    "redact_mapping",
    "redact_text",
    "redact_value",
    "register_secret",
]

"""Structured JSON logging with redaction of secrets and recipient identifiers."""

from vrm_alert_relay.logs.config import JsonFormatter, configure_logging
from vrm_alert_relay.logs.redaction import (
    REDACTED,
    SecretRegistry,
    contains_secret,
    mask_recipient,
    redact_mapping,
    redact_secrets,
    redact_text,
    redact_value,
    register_derived_secret,
    register_secret,
)

__all__ = [
    "REDACTED",
    "JsonFormatter",
    "SecretRegistry",
    "configure_logging",
    "contains_secret",
    "mask_recipient",
    "redact_mapping",
    "redact_secrets",
    "redact_text",
    "redact_value",
    "register_derived_secret",
    "register_secret",
]

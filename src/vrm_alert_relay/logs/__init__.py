"""Structured JSON logging with redaction of secrets and recipient identifiers."""

from vrm_alert_relay.logs.config import JsonFormatter, configure_logging
from vrm_alert_relay.logs.redaction import (
    MAX_SECRET_LENGTH,
    MAX_SECRETS,
    REDACTED,
    SecretRegistrationError,
    SecretRegistry,
    SecretTooLongError,
    TooManySecretsError,
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
    "MAX_SECRETS",
    "MAX_SECRET_LENGTH",
    "REDACTED",
    "JsonFormatter",
    "SecretRegistrationError",
    "SecretRegistry",
    "SecretTooLongError",
    "TooManySecretsError",
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

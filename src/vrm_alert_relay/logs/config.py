"""JSON-lines logging with redaction applied to every record."""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import UTC, datetime
from typing import Final, TextIO

from vrm_alert_relay.logs.redaction import (
    DEFAULT_MAX_FIELD_LENGTH,
    MAX_KEY_LENGTH,
    MAX_SECRET_LENGTH,
    REDACTED,
    JsonValue,
    SecretRegistry,
    default_registry,
    escape_controls,
    redact_mapping,
    redact_text,
)

DEFAULT_MAX_EXCEPTION_LENGTH: Final = 8192
QUIET_LOGGERS: Final = ("httpx", "httpcore")
WITHHELD_MESSAGE: Final = "log record withheld by redaction"
FALLBACK_CODE_KEYS: Final = ("event", "code")

_CODE_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")

_STANDARD_ATTRS = frozenset(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {
    "message",
    "asctime",
    "taskName",
}
_OUTPUT_KEYS = frozenset({"ts", "level", "logger", "msg", "exc", "stack"})


class JsonFormatter(logging.Formatter):
    """Format each record as one redacted JSON object on a single line.

    Fields: ``ts`` (ISO-8601 UTC), ``level``, ``logger``, ``msg``, then any
    ``extra`` values, then ``exc`` and ``stack`` when present. An extra whose
    name collides with a standard field is emitted as ``extra_<name>``.
    Exception and stack text keep their tail when truncated, since the
    innermost frame and the message are at the end.

    Every key and value is redacted before serialization. The serialized
    line is then parsed back and each string token (key or value, decoded
    and JSON-escaped) is checked for registered secrets, without matching
    across tokens. A line that still contains one is replaced by a record
    with only ``ts``, ``level``, ``logger``, the ``event`` and ``code``
    extras when they are short identifiers, and the message
    ``log record withheld by redaction``.
    """

    def __init__(
        self,
        *,
        registry: SecretRegistry | None = None,
        max_field_length: int = DEFAULT_MAX_FIELD_LENGTH,
        max_exception_length: int = DEFAULT_MAX_EXCEPTION_LENGTH,
    ) -> None:
        super().__init__()
        self._registry = registry or default_registry
        self._max_field_length = max_field_length
        self._max_exception_length = max_exception_length

    def format(self, record: logging.LogRecord) -> str:
        try:
            line = self._format(record)
            leaked = self._leaks(json.loads(line))
        except Exception:  # noqa: BLE001 - a raw record must never reach Handler.handleError
            return self._fallback(record, "log record could not be formatted")
        if leaked:
            return self._fallback(record, WITHHELD_MESSAGE)
        return line

    def _leaks(self, parsed: object) -> bool:
        pending = [parsed]
        while pending:
            item = pending.pop()
            if isinstance(item, dict):
                pending.extend(item)
                pending.extend(item.values())
            elif isinstance(item, list):
                pending.extend(item)
            elif self._token_leaks(str(item)):
                return True
        return False

    def _token_leaks(self, token: str) -> bool:
        escaped = json.dumps(token, ensure_ascii=False)[1:-1]
        size = max(self._max_field_length, self._max_exception_length, 2 * MAX_SECRET_LENGTH)
        return any(
            self._registry.contains(chunk)
            for form in (token, escaped)
            for chunk in _chunks(form, size)
        )

    def _fallback(self, record: logging.LogRecord, message: str) -> str:
        fallback: dict[str, str] = {
            "ts": _timestamp(record),
            "level": self._metadata(record.levelname, 32),
            "logger": self._metadata(record.name, MAX_KEY_LENGTH),
            "msg": message,
        }
        for key in FALLBACK_CODE_KEYS:
            value = record.__dict__.get(key)
            if (
                isinstance(value, str)
                and _CODE_RE.fullmatch(value)
                and not self._token_leaks(value)
            ):
                fallback[key] = value
        return json.dumps(fallback, ensure_ascii=False, separators=(",", ":"))

    def _metadata(self, value: object, limit: int) -> str:
        text = escape_controls(str(value))[:limit]
        return REDACTED if self._token_leaks(text) else text

    def _format(self, record: logging.LogRecord) -> str:
        try:
            message = record.getMessage()
        except Exception:  # noqa: BLE001 - arbitrary __str__ and bad format args
            message = f"{record.msg} [log arguments could not be formatted]"

        payload: dict[str, JsonValue] = {
            "ts": _timestamp(record),
            "level": self._text(record.levelname),
            "logger": self._text(record.name),
            "msg": self._text(message),
        }

        extras = {
            key: value for key, value in record.__dict__.items() if key not in _STANDARD_ATTRS
        }
        redacted = redact_mapping(
            extras, registry=self._registry, max_length=self._max_field_length
        )
        for key, value in redacted.items():
            payload[f"extra_{key}" if key in _OUTPUT_KEYS else key] = value

        if record.exc_info:
            payload["exc"] = self._long_text(self.formatException(record.exc_info))
        elif record.exc_text:
            payload["exc"] = self._long_text(record.exc_text)
        if record.stack_info:
            payload["stack"] = self._long_text(self.formatStack(record.stack_info))

        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

    def _text(self, text: object) -> str:
        return redact_text(str(text), registry=self._registry, max_length=self._max_field_length)

    def _long_text(self, text: str) -> str:
        return redact_text(
            text,
            registry=self._registry,
            max_length=self._max_exception_length,
            keep="tail",
        )


def configure_logging(
    level: int | str = "INFO",
    *,
    stream: TextIO | None = None,
    registry: SecretRegistry | None = None,
    max_field_length: int = DEFAULT_MAX_FIELD_LENGTH,
    max_exception_length: int = DEFAULT_MAX_EXCEPTION_LENGTH,
) -> logging.Handler:
    """Send all logging to ``stream`` (default stdout) as redacted JSON lines.

    Replaces any handlers on the root logger, caps the ``httpx`` and
    ``httpcore`` loggers at WARNING (their request lines embed full URLs), and
    routes :mod:`warnings` through logging. Returns the installed handler.
    """
    numeric_level = _resolve_level(level)
    handler = logging.StreamHandler(stream if stream is not None else sys.stdout)
    handler.setFormatter(
        JsonFormatter(
            registry=registry,
            max_field_length=max_field_length,
            max_exception_length=max_exception_length,
        )
    )
    root = logging.getLogger()
    for existing in list(root.handlers):
        root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(numeric_level)
    for name in QUIET_LOGGERS:
        logging.getLogger(name).setLevel(max(logging.WARNING, numeric_level))
    logging.captureWarnings(True)
    return handler


def _resolve_level(level: int | str) -> int:
    if isinstance(level, bool):
        raise TypeError("log level must be an int or a level name")
    if isinstance(level, int):
        return level
    if isinstance(level, str):
        mapping = logging.getLevelNamesMapping()
        name = level.strip().upper()
        if name in mapping:
            return mapping[name]
    raise ValueError("invalid log level")


def _chunks(text: str, size: int) -> list[str]:
    """Slices of at most ``size`` overlapping by half, so that any substring
    of up to ``size // 2`` characters lies wholly within one of them."""
    if len(text) <= size:
        return [text]
    step = max(size // 2, 1)
    starts = range(0, len(text) - size + step, step)
    return [text[start : start + size] for start in starts]


def _timestamp(record: logging.LogRecord) -> str:
    moment = datetime.fromtimestamp(record.created, UTC)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")

from __future__ import annotations

import base64
import io
import json
import logging
import re
import warnings
from collections.abc import Iterator
from typing import Any
from urllib.parse import quote, quote_plus

import pytest

from vrm_alert_relay.logs import (
    REDACTED,
    JsonFormatter,
    SecretRegistry,
    configure_logging,
    register_secret,
)
from vrm_alert_relay.logs import redaction as redaction_module
from vrm_alert_relay.logs.config import WITHHELD_MESSAGE
from vrm_alert_relay.logs.redaction import TRUNCATED

CANARY = "fictitious-api-password-0001"
CANARY_BEARER = "fictitious-bearer-token-0002"
PHONE = "+1 202 555 0143"
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z")


@pytest.fixture(autouse=True)
def restore_logging() -> Iterator[None]:
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    quiet = {name: logging.getLogger(name).level for name in ("httpx", "httpcore")}
    yield
    for handler in list(root.handlers):
        root.removeHandler(handler)
    for handler in handlers:
        root.addHandler(handler)
    root.setLevel(level)
    for name, quiet_level in quiet.items():
        logging.getLogger(name).setLevel(quiet_level)
    logging.captureWarnings(False)


@pytest.fixture
def registry() -> SecretRegistry:
    instance = SecretRegistry()
    instance.register(CANARY)
    instance.register(CANARY_BEARER)
    return instance


@pytest.fixture
def stream(registry: SecretRegistry) -> io.StringIO:
    buffer = io.StringIO()
    configure_logging("DEBUG", stream=buffer, registry=registry)
    return buffer


def lines(stream: io.StringIO) -> list[dict[str, Any]]:
    output = stream.getvalue()
    assert output.endswith("\n")
    return [json.loads(line) for line in output.splitlines()]


def assert_clean(stream: io.StringIO) -> None:
    output = stream.getvalue()
    for leaked in (CANARY, CANARY_BEARER, PHONE, "2025550143", "202 555 0143"):
        assert leaked not in output


def test_one_json_object_per_line(stream: io.StringIO) -> None:
    log = logging.getLogger("vrm_alert_relay.test")
    log.info("first")
    log.warning("second\nline")
    records = lines(stream)
    assert len(records) == 2
    first = records[0]
    assert set(first) == {"ts", "level", "logger", "msg"}
    assert TS_RE.fullmatch(first["ts"])
    assert first["level"] == "INFO"
    assert first["logger"] == "vrm_alert_relay.test"
    assert first["msg"] == "first"
    assert records[1]["msg"] == "second\\nline"


def test_extras_are_structured_and_redacted(stream: io.StringIO) -> None:
    logging.getLogger("t").info(
        "sending",
        extra={
            "rule": "battery_low",
            "attempt": 2,
            "recipient": PHONE,
            "api_password": "keyed-value",
            "request": {
                "headers": {"Authorization": f"Bearer {CANARY_BEARER}"},
                "params": {"x": CANARY},
            },
            "url": f"https://voip.example.com/rest.php?api_password={CANARY}&did=2025550143",
        },
    )
    (record,) = lines(stream)
    assert record["rule"] == "battery_low"
    assert record["attempt"] == 2
    assert record["recipient"] == "***0143"
    assert record["api_password"] == REDACTED
    assert record["request"] == {
        "headers": {"Authorization": REDACTED},
        "params": {"x": REDACTED},
    }
    assert record["url"] == f"https://voip.example.com/rest.php?{REDACTED}"
    assert_clean(stream)


def test_extra_name_collisions_are_prefixed(stream: io.StringIO) -> None:
    logging.getLogger("t").info("real", extra={"ts": "fake", "level": "fake", "exc": "fake"})
    (record,) = lines(stream)
    assert record["msg"] == "real"
    assert record["level"] == "INFO"
    assert record["extra_ts"] == "fake"
    assert record["extra_level"] == "fake"
    assert record["extra_exc"] == "fake"


def test_message_and_args_redacted(stream: io.StringIO) -> None:
    log = logging.getLogger("t")
    log.info("login with %s to %s", CANARY, PHONE)
    log.info("params %r", {"api_password": "plain", "did": "2025550143"})
    log.info("header Authorization: Bearer %s", CANARY_BEARER)
    log.info("GET https://example.com/api?token=%s&x=1", "abc")
    log.info("bell\x07 escape\x1b[31m rtl\u202e nul\x00")
    records = lines(stream)
    assert records[0]["msg"] == f"login with {REDACTED} to ***0143"
    assert records[1]["msg"] == f"params {{'api_password': '{REDACTED}', 'did': '***0143'}}"
    assert records[2]["msg"] == f"header Authorization: {REDACTED}"
    assert records[3]["msg"] == f"GET https://example.com/api?{REDACTED}"
    assert records[4]["msg"] == "bell\\x07 escape\\x1b[31m rtl\\u202e nul\\x00"
    assert_clean(stream)


def test_exception_tracebacks_redacted(stream: io.StringIO) -> None:
    def fail() -> None:
        url = f"https://example.com/send?api_password={CANARY}"
        raise ValueError(f"failed {url} for {PHONE} token={CANARY_BEARER}\ninjected line")

    try:
        fail()
    except ValueError:
        logging.getLogger("t").exception("delivery failed")
    (record,) = lines(stream)
    assert record["msg"] == "delivery failed"
    assert record["exc"].startswith("Traceback (most recent call last):")
    assert "ValueError: failed https://example.com/send?[REDACTED]" in record["exc"]
    assert "***0143" in record["exc"]
    assert "\n" not in record["exc"]
    assert_clean(stream)


def test_chained_exception_redacted(stream: io.StringIO) -> None:
    try:
        try:
            raise KeyError(CANARY)
        except KeyError as inner:
            raise RuntimeError("wrapped") from inner
    except RuntimeError:
        logging.getLogger("t").exception("boom")
    (record,) = lines(stream)
    assert "KeyError" in record["exc"]
    assert "RuntimeError: wrapped" in record["exc"]
    assert_clean(stream)


def test_long_exception_keeps_tail(registry: SecretRegistry) -> None:
    buffer = io.StringIO()
    configure_logging(stream=buffer, registry=registry, max_exception_length=500)
    try:
        raise ValueError("x" * 5000 + " END-OF-MESSAGE")
    except ValueError:
        logging.getLogger("t").exception("long")
    (record,) = lines(buffer)
    assert len(record["exc"]) == 500
    assert record["exc"].startswith(TRUNCATED)
    assert record["exc"].endswith("END-OF-MESSAGE")


TAIL_LIMIT = 4096
FAKE_VALUE_UNIT = "fakeVal9Zq"
FAKE_FRAGMENT = "Zq"


def _long_value(length: int, newline_at: int | None = None) -> str:
    value = (FAKE_VALUE_UNIT * (length // len(FAKE_VALUE_UNIT) + 1))[:length]
    if newline_at is None:
        return value
    return value[:newline_at] + "\n" + value[newline_at + 1 :]


@pytest.mark.parametrize(
    ("opener", "closer", "newline_at"),
    [
        ('settings: password="', '"', None),
        ('{"token": "', '"}', 1800),
        ("api_key=", "", None),
        ("Authorization: Bearer ", "", None),
        ("GET https://example.test/v2/poll?token=", " HTTP/1.1", None),
    ],
    ids=["quoted", "quoted-multiline", "bare", "header", "url-query"],
)
def test_tail_truncation_inside_long_sensitive_value_does_not_leak(
    opener: str, closer: str, newline_at: int | None
) -> None:
    value = _long_value(3000, newline_at)
    head = "Traceback (most recent call last):\n" + "  frame line\n" * 40
    tail = "\n" + "  later frame line\n" * 160 + "RuntimeError: END-OF-TRACE"
    into_value = len(value) - (TAIL_LIMIT - len(closer) - len(tail))
    text = head + opener + value + closer + tail
    cut = len(text) - TAIL_LIMIT
    value_start = len(head) + len(opener)
    assert cut - value_start == into_value
    assert into_value > redaction_module._CUT_CONTEXT
    assert FAKE_FRAGMENT not in head + tail

    formatter = JsonFormatter(registry=SecretRegistry(), max_exception_length=TAIL_LIMIT)
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "failed", None, None)
    record.exc_text = text
    output = json.loads(formatter.format(record))
    assert output["msg"] == "failed"
    assert output["exc"].startswith(TRUNCATED)
    assert output["exc"].endswith("RuntimeError: END-OF-TRACE")
    assert FAKE_FRAGMENT not in output["exc"]


MULTILINE_VALUE = "SENSITIVEVALUEZq" * 700


@pytest.mark.parametrize(("ending", "kept"), [(" END", ""), ("\nEND", "END")])
@pytest.mark.parametrize("newline", ["\n", "\r", "\r\n"], ids=["lf", "cr", "crlf"])
@pytest.mark.parametrize("offset", [None, 1023, 1024, 1025, 8191, 8192, 8193])
def test_tail_truncation_after_multiline_separator_does_not_leak(
    offset: int | None, newline: str, ending: str, kept: str
) -> None:
    """The value line is longer than the line scan, so text after it on the
    same line is withheld; text on the next line is kept."""
    opener = "trace token=" + newline
    text = opener + MULTILINE_VALUE + ending
    if offset is None:
        formatter = JsonFormatter(registry=SecretRegistry())
    else:
        limit = len(text) - len(opener) - offset
        formatter = JsonFormatter(registry=SecretRegistry(), max_exception_length=limit)
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "failed", None, None)
    record.exc_text = text
    output = formatter.format(record)
    assert "SENSITIVE" not in output
    assert FAKE_FRAGMENT not in output
    assert json.loads(output)["exc"] == TRUNCATED + kept


def test_exc_text_without_exc_info(registry: SecretRegistry) -> None:
    formatter = JsonFormatter(registry=registry)
    record = logging.LogRecord("t", logging.ERROR, __file__, 1, "cached", None, None)
    record.exc_text = f"Traceback: secret {CANARY}"
    output = json.loads(formatter.format(record))
    assert output["exc"] == f"Traceback: secret {REDACTED}"


def test_stack_info_redacted(stream: io.StringIO) -> None:
    logging.getLogger("t").info("with stack %s", CANARY, stack_info=True)
    (record,) = lines(stream)
    assert record["stack"].startswith("Stack (most recent call last):")
    assert_clean(stream)


def test_long_fields_truncated(registry: SecretRegistry) -> None:
    buffer = io.StringIO()
    configure_logging(stream=buffer, registry=registry)
    logging.getLogger("t").info("m" * 50_000, extra={"field": "f" * 50_000})
    (record,) = lines(buffer)
    assert len(record["msg"]) == 2048
    assert record["msg"].endswith(TRUNCATED)
    assert len(record["field"]) == 2048
    assert len(buffer.getvalue()) < 10_000


def test_malicious_nested_extras_bounded(stream: io.StringIO) -> None:
    nested: dict[str, Any] = {"token": "x"}
    for _ in range(500):
        nested = {"child": nested, "list": list(range(1000))}
    logging.getLogger("t").info("nested", extra={"payload": nested})
    output = stream.getvalue()
    assert len(output) < 50_000
    (record,) = lines(stream)
    assert "payload" in record


def test_bad_format_args_do_not_leak(
    registry: SecretRegistry, capsys: pytest.CaptureFixture[str]
) -> None:
    # Handled directly: pytest's own capture handler would raise on the bad args.
    stream = io.StringIO()
    handler = configure_logging(stream=stream, registry=registry)
    handler.handle(
        logging.LogRecord("t", logging.INFO, __file__, 1, "value %d for " + CANARY, ("x",), None)
    )
    (output,) = lines(stream)
    assert output["msg"] == (f"value %d for {REDACTED} [log arguments could not be formatted]")
    assert CANARY not in capsys.readouterr().err
    assert_clean(stream)


def test_formatter_failure_falls_back(
    stream: io.StringIO,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def explode(self: JsonFormatter, record: logging.LogRecord) -> str:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(JsonFormatter, "_format", explode)
    logging.getLogger("t").warning("will not format %s", CANARY)
    (record,) = lines(stream)
    assert record["msg"] == "log record could not be formatted"
    assert record["level"] == "WARNING"
    assert CANARY not in capsys.readouterr().err
    assert_clean(stream)


TRICKY = 'fictitious"pa\\ss/wörd'


class HostileStr:
    def __str__(self) -> str:
        return json.dumps({"detail": TRICKY})

    def __repr__(self) -> str:
        return f"HostileStr({TRICKY!r}, {base64.b64encode(TRICKY.encode()).decode()})"


@pytest.fixture
def tricky_stream() -> io.StringIO:
    registry = SecretRegistry()
    registry.register(TRICKY)
    buffer = io.StringIO()
    configure_logging("DEBUG", stream=buffer, registry=registry)
    return buffer


def assert_no_tricky(stream: io.StringIO) -> None:
    output = stream.getvalue()
    for line in output.splitlines():
        json.loads(line)
    assert "fictitious" not in output
    assert "w\\u00f6rd" not in output
    assert "wörd" not in output


def test_hostile_str_and_repr_redacted(tricky_stream: io.StringIO) -> None:
    hostile = HostileStr()
    log = logging.getLogger("t")
    log.info("str %s", hostile)
    log.info("repr %r", hostile)
    log.info("extra", extra={"obj": hostile, "nested": {"items": [hostile]}})
    log.info(hostile)
    records = lines(tricky_stream)
    assert records[0]["msg"] == f'str {{"detail": "{REDACTED}"}}'
    assert records[1]["msg"] == f"repr HostileStr('{REDACTED}', {REDACTED})"
    assert_no_tricky(tricky_stream)


@pytest.mark.parametrize(
    "rendered",
    [
        json.dumps(TRICKY),
        json.dumps(TRICKY, ensure_ascii=False),
        repr(TRICKY),
        quote(TRICKY, safe=""),
        quote(TRICKY, safe="").lower(),
        quote_plus(TRICKY, safe="").lower(),
        base64.b64encode(TRICKY.encode()).decode(),
        base64.urlsafe_b64encode(TRICKY.encode()).decode().rstrip("="),
    ],
)
def test_encoded_variants_redacted_in_every_field(
    tricky_stream: io.StringIO, rendered: str
) -> None:
    try:
        raise ValueError(rendered)
    except ValueError:
        logging.getLogger("t").exception(
            "value %s", rendered, extra={"field": rendered, "list": [rendered]}
        )
    assert_no_tricky(tricky_stream)


def stream_with(*secrets: str) -> io.StringIO:
    registry = SecretRegistry()
    for secret in secrets:
        registry.register(secret)
    buffer = io.StringIO()
    configure_logging(stream=buffer, registry=registry)
    return buffer


def test_secret_spanning_json_tokens_does_not_suppress_record() -> None:
    buffer = stream_with(
        '"msg":"monitoring degraded"',
        '"msg":"harmless"',
        '"rule":"battery_low"',
        'degraded","rule"',
    )
    log = logging.getLogger("t")
    log.warning("monitoring degraded", extra={"rule": "battery_low"})
    log.info("harmless")
    first, second = lines(buffer)
    assert first["msg"] == "monitoring degraded"
    assert first["rule"] == "battery_low"
    assert second["msg"] == "harmless"


def test_secret_revealed_by_json_escaping_withholds_record() -> None:
    # Field redaction sees a newline; escape_controls and JSON then yield
    # the registered backslash sequence inside one token.
    buffer = stream_with("fictitious\\\\ncomposite")
    logging.getLogger("relay.poll").warning(
        "value fictitious\ncomposite",
        extra={"event": "poll.failed", "code": "E42", "detail": "kept out"},
    )
    output = buffer.getvalue()
    (record,) = lines(buffer)
    assert record == {
        "ts": record["ts"],
        "level": "WARNING",
        "logger": "relay.poll",
        "msg": WITHHELD_MESSAGE,
        "event": "poll.failed",
        "code": "E42",
    }
    assert TS_RE.fullmatch(record["ts"])
    assert "fictitious" not in output
    assert "kept out" not in output


def test_verification_covers_whole_escaped_token_in_bounded_chunks() -> None:
    registry = SecretRegistry()
    registry.register("fictitious\\\\ncomposite")
    buffer = io.StringIO()
    configure_logging(
        stream=buffer,
        registry=registry,
        max_field_length=12_000,
        max_exception_length=1024,
    )
    message = 'x"' * 3995 + "value fictitious\ncomposite"
    escaped = json.dumps(message.replace("\n", "\\n"))[1:-1]
    start = escaped.index("fictitious")
    assert len(message) < 12_000
    assert start < 12_000 < start + len("fictitious\\\\ncomposite")
    logging.getLogger("t").warning(message)
    (record,) = lines(buffer)
    assert record["msg"] == WITHHELD_MESSAGE


def test_fallback_keeps_only_safe_codes_and_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    buffer = stream_with(CANARY)

    def explode(self: JsonFormatter, record: logging.LogRecord) -> str:
        raise RuntimeError(CANARY)

    monkeypatch.setattr(JsonFormatter, "_format", explode)
    logging.getLogger(f"relay.{CANARY}").error(
        "boom", extra={"event": "has spaces", "code": CANARY}
    )
    logging.getLogger("relay").error("boom", extra={"event": 42, "code": "x" * 65})
    first, second = lines(buffer)
    assert first["logger"] == REDACTED
    assert first["msg"] == "log record could not be formatted"
    assert "event" not in first
    assert "code" not in first
    assert set(second) == {"ts", "level", "logger", "msg"}
    assert CANARY not in buffer.getvalue()


def test_floats_checked_for_secrets() -> None:
    buffer = stream_with("123456.789")
    logging.getLogger("t").info(
        "reading",
        extra={"reading": 123456.789, "voltage": 52.4, "ts_epoch": 1760000000.5},
    )
    (record,) = lines(buffer)
    assert record["reading"] == REDACTED
    assert record["voltage"] == 52.4
    assert record["ts_epoch"] == 1760000000.5


def test_globally_registered_secret(capsys: pytest.CaptureFixture[str]) -> None:
    value = "fictitious-global-secret-0099"
    register_secret(value)
    configure_logging("INFO")
    logging.getLogger("t").info("using %s", value)
    out = capsys.readouterr().out
    assert value not in out
    assert json.loads(out)["msg"] == f"using {REDACTED}"


def test_configure_replaces_handlers_and_sets_levels() -> None:
    root = logging.getLogger()
    stale = logging.StreamHandler(io.StringIO())
    root.addHandler(stale)
    handler = configure_logging(logging.DEBUG, stream=io.StringIO())
    assert root.handlers == [handler]
    assert isinstance(handler.formatter, JsonFormatter)
    assert root.level == logging.DEBUG
    assert logging.getLogger("httpx").level == logging.WARNING
    assert logging.getLogger("httpcore").level == logging.WARNING
    configure_logging("error", stream=io.StringIO())
    assert root.level == logging.ERROR
    assert logging.getLogger("httpx").level == logging.ERROR


def test_level_filtering(stream: io.StringIO) -> None:
    configure_logging(" warning ", stream=stream)
    log = logging.getLogger("t")
    log.info("hidden")
    log.warning("shown")
    assert [record["msg"] for record in lines(stream)] == ["shown"]


def test_httpx_request_lines_suppressed_and_redacted(stream: io.StringIO) -> None:
    httpx_log = logging.getLogger("httpx")
    httpx_log.info(
        'HTTP Request: GET https://example.com/?api_password=%s "HTTP/1.1 200 OK"',
        CANARY,
    )
    httpx_log.warning(
        'HTTP Request: GET https://example.com/?api_password=%s "HTTP/1.1 500"', CANARY
    )
    records = lines(stream)
    assert len(records) == 1
    assert records[0]["msg"] == f'HTTP Request: GET https://example.com/?{REDACTED} "HTTP/1.1 500"'


def test_warnings_routed_through_logging(stream: io.StringIO) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("always")
        warnings.warn(f"careful with {CANARY}", UserWarning, stacklevel=1)
    (record,) = lines(stream)
    assert record["logger"] == "py.warnings"
    assert "UserWarning" in record["msg"]
    assert_clean(stream)


@pytest.mark.parametrize("level", ["LOUD", "", "5x"])
def test_invalid_level_names(level: str) -> None:
    with pytest.raises(ValueError, match="invalid log level"):
        configure_logging(level)


def test_invalid_level_types() -> None:
    with pytest.raises(TypeError):
        configure_logging(True)
    with pytest.raises(ValueError, match="invalid log level"):
        configure_logging(1.5)  # type: ignore[arg-type]

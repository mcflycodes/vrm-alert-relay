"""The VoIP.ms SMS provider against a mocked VoIP.ms API."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import TYPE_CHECKING, Any

import httpx
import pytest
from provider_helpers import (
    DID,
    HA,
    MESSAGE,
    NOW,
    SMS,
    VOIPMS_PASSWORD,
    VOIPMS_URL,
    VOIPMS_USER,
    StubTransport,
    assert_no_secrets,
    multipart_fields,
    secret,
)

from vrm_alert_relay.config import PhoneNumber, VoipmsRecipient
from vrm_alert_relay.delivery.protocol import (
    Message,
    ReconcileQuery,
    ReconcileStatus,
    ReconcilingProvider,
    SendStatus,
)
from vrm_alert_relay.providers import VoipmsSmsProvider, sms_text
from vrm_alert_relay.providers.voipms import (
    MAX_SMS_CHARS,
    NON_RETRYABLE_STATUSES,
    RECONCILE_LIMIT,
    RETRYABLE_STATUSES,
)

if TYPE_CHECKING:
    from vrm_alert_relay.logs.redaction import SecretRegistry
    from vrm_alert_relay.net import SafeHttpClient


@pytest.fixture
def provider(http: SafeHttpClient, registry: SecretRegistry) -> VoipmsSmsProvider:
    return VoipmsSmsProvider(
        http,
        username=secret(VOIPMS_USER),
        password=secret(VOIPMS_PASSWORD),
        did=DID,
        base_url=VOIPMS_URL,
        registry=registry,
    )


def test_implements_the_reconciling_protocol(provider: VoipmsSmsProvider) -> None:
    assert isinstance(provider, ReconcilingProvider)


def test_registers_credentials_for_redaction(
    provider: VoipmsSmsProvider, registry: SecretRegistry
) -> None:
    assert {VOIPMS_USER, VOIPMS_PASSWORD} <= set(registry.secrets)
    assert registry.redact(f"user={VOIPMS_USER} pass={VOIPMS_PASSWORD}") == (
        "user=[REDACTED] pass=[REDACTED]"
    )


def test_registers_with_the_default_registry(
    http: SafeHttpClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[str] = []
    monkeypatch.setattr("vrm_alert_relay.providers.voipms.register_secret", seen.append)
    VoipmsSmsProvider(http, username=secret(VOIPMS_USER), password=secret(VOIPMS_PASSWORD), did=DID)
    assert seen == [VOIPMS_USER, VOIPMS_PASSWORD]


def test_send_posts_multipart_credentials_and_succeeds(
    provider: VoipmsSmsProvider, transport: StubTransport
) -> None:
    transport.json({"status": "success", "sms": 23434})
    result = provider.send(MESSAGE, SMS)
    assert result.status is SendStatus.DELIVERED
    assert result.provider_message_id == "23434"
    (request,) = transport.requests
    assert request.method == "POST"
    assert str(request.url) == VOIPMS_URL
    assert request.url.query == b""
    assert request.headers["content-type"].startswith("multipart/form-data; boundary=")
    assert multipart_fields(request) == {
        "api_username": VOIPMS_USER,
        "api_password": VOIPMS_PASSWORD,
        "method": "sendSMS",
        "did": "2025550100",
        "dst": "2025550142",
        "message": MESSAGE.text,
    }


@pytest.mark.parametrize(
    ("sms", "expected"),
    [
        ("98765", "98765"),
        (0, "0"),
        (-1, None),
        (True, None),
        ("12a", None),
        ("1" * 21, None),
        (None, None),
        ([1], None),
    ],
)
def test_message_id_is_validated(
    provider: VoipmsSmsProvider, transport: StubTransport, sms: object, expected: str | None
) -> None:
    transport.json({"status": "success", "sms": sms})
    result = provider.send(MESSAGE, SMS)
    assert result.status is SendStatus.DELIVERED
    assert result.provider_message_id == expected


@pytest.mark.parametrize("status", sorted(NON_RETRYABLE_STATUSES))
def test_http_200_refusals_fail_without_retry(
    provider: VoipmsSmsProvider, transport: StubTransport, status: str
) -> None:
    transport.json({"status": status})
    result = provider.send(MESSAGE, SMS)
    assert (result.status, result.retryable) == (SendStatus.FAILED, False)


@pytest.mark.parametrize("status", sorted(RETRYABLE_STATUSES))
def test_http_200_transient_refusals_are_retryable(
    provider: VoipmsSmsProvider, transport: StubTransport, status: str
) -> None:
    transport.json({"status": status})
    result = provider.send(MESSAGE, SMS)
    assert (result.status, result.retryable) == (SendStatus.FAILED, True)


@pytest.mark.parametrize(
    "payload",
    [
        {"status": "Success"},
        {"status": "fictitious_new_status"},
        {"status": 1},
        {"sms": 1},
        ["success"],
        "success",
        None,
    ],
)
def test_anything_but_exact_success_is_never_delivered(
    provider: VoipmsSmsProvider, transport: StubTransport, payload: Any
) -> None:
    transport.json(payload)
    result = provider.send(MESSAGE, SMS)
    assert result.status is SendStatus.AMBIGUOUS
    assert result.retryable is True


@pytest.mark.parametrize("body", [b"<soap:Envelope/>", b"{not json", b""])
def test_malformed_body_is_ambiguous(
    provider: VoipmsSmsProvider, transport: StubTransport, body: bytes
) -> None:
    transport.respond(lambda _r: httpx.Response(200, content=body))
    assert provider.send(MESSAGE, SMS).status is SendStatus.AMBIGUOUS


def test_invalid_credentials_fail_and_never_leak(
    provider: VoipmsSmsProvider, transport: StubTransport, caplog: pytest.LogCaptureFixture
) -> None:
    transport.json({"status": "invalid_credentials"})
    with caplog.at_level(logging.DEBUG):
        result = provider.send(MESSAGE, SMS)
    assert (result.status, result.retryable) == (SendStatus.FAILED, False)
    (record,) = [r for r in caplog.records if r.name.endswith("voipms")]
    assert record.levelno == logging.WARNING
    assert record.reason == "invalid_credentials"  # type: ignore[attr-defined]
    assert record.recipient == "sms:***-***-0142"  # type: ignore[attr-defined]
    assert_no_secrets(caplog.records, provider, result)


def test_unrecognised_status_text_is_not_logged(
    provider: VoipmsSmsProvider, transport: StubTransport, caplog: pytest.LogCaptureFixture
) -> None:
    transport.json({"status": "\nforged log line 2025550199"})
    provider.send(MESSAGE, SMS)
    (record,) = caplog.records
    assert record.reason == "unrecognized"  # type: ignore[attr-defined]
    assert "forged" not in repr(record.__dict__)


@pytest.mark.parametrize(
    ("raise_error", "status", "retryable"),
    [
        (httpx.ReadTimeout("fictitious"), SendStatus.AMBIGUOUS, True),
        (httpx.WriteTimeout("fictitious"), SendStatus.AMBIGUOUS, True),
        (httpx.ConnectTimeout("fictitious"), SendStatus.FAILED, True),
        (httpx.PoolTimeout("fictitious"), SendStatus.FAILED, True),
        (httpx.ConnectError("fictitious"), SendStatus.FAILED, True),
        (httpx.RemoteProtocolError("fictitious"), SendStatus.AMBIGUOUS, True),
        (httpx.ReadError("fictitious"), SendStatus.AMBIGUOUS, True),
    ],
)
def test_transport_failures(
    provider: VoipmsSmsProvider,
    transport: StubTransport,
    raise_error: Exception,
    status: SendStatus,
    retryable: bool,
) -> None:
    def fail(_request: httpx.Request) -> httpx.Response:
        raise raise_error

    transport.respond(fail)
    result = provider.send(MESSAGE, SMS)
    assert (result.status, result.retryable) == (status, retryable)


@pytest.mark.parametrize(
    ("http_status", "status", "retryable"),
    [
        (500, SendStatus.AMBIGUOUS, True),
        (503, SendStatus.AMBIGUOUS, True),
        (429, SendStatus.FAILED, True),
        (401, SendStatus.FAILED, False),
        (404, SendStatus.FAILED, False),
        (302, SendStatus.AMBIGUOUS, True),
    ],
)
def test_http_status_failures(
    provider: VoipmsSmsProvider,
    transport: StubTransport,
    http_status: int,
    status: SendStatus,
    retryable: bool,
) -> None:
    transport.respond(
        lambda _r: httpx.Response(http_status, headers={"Location": "https://evil.example.test/"})
    )
    result = provider.send(MESSAGE, SMS)
    assert (result.status, result.retryable) == (status, retryable)
    assert len(transport.requests) == 1


def test_oversized_response_is_ambiguous(
    provider: VoipmsSmsProvider, transport: StubTransport
) -> None:
    transport.respond(lambda _r: httpx.Response(200, content=b"x" * (300 * 1024)))
    assert provider.send(MESSAGE, SMS).status is SendStatus.AMBIGUOUS


def test_message_is_trimmed_to_160_characters(
    provider: VoipmsSmsProvider, transport: StubTransport
) -> None:
    transport.json({"status": "success", "sms": 1})
    long_text = "word " * 100
    provider.send(Message(MESSAGE.delivery_id, long_text), SMS)
    sent = multipart_fields(transport.requests[0])["message"]
    assert len(sent) <= MAX_SMS_CHARS
    assert sent.endswith("...")
    assert sent == sms_text(long_text)


def test_sms_text_boundaries() -> None:
    exact = "x" * MAX_SMS_CHARS
    assert sms_text(exact) == exact
    over = "y" * (MAX_SMS_CHARS + 1)
    assert sms_text(over) == "y" * (MAX_SMS_CHARS - 3) + "..."


def test_other_recipient_types_are_refused_without_a_request(
    provider: VoipmsSmsProvider, transport: StubTransport
) -> None:
    result = provider.send(MESSAGE, HA)
    assert (result.status, result.retryable) == (SendStatus.FAILED, False)
    assert transport.requests == []


def test_requires_a_strict_https_client(insecure_http: SafeHttpClient) -> None:
    with pytest.raises(ValueError, match="limited to https"):
        VoipmsSmsProvider(
            insecure_http, username=secret(VOIPMS_USER), password=secret(VOIPMS_PASSWORD), did=DID
        )


def test_repr_shows_only_the_endpoint(provider: VoipmsSmsProvider) -> None:
    assert repr(provider) == f"VoipmsSmsProvider('{VOIPMS_URL}')"


def test_response_cannot_redirect_a_later_message(
    provider: VoipmsSmsProvider, transport: StubTransport
) -> None:
    transport.json(
        {"status": "success", "sms": 1, "dst": "2025550199", "did": "2025550198", "url": "x"}
    )
    provider.send(MESSAGE, SMS)
    provider.send(MESSAGE, SMS)
    for request in transport.requests:
        assert str(request.url) == VOIPMS_URL
        fields = multipart_fields(request)
        assert (fields["did"], fields["dst"]) == ("2025550100", "2025550142")


# Reconcile ------------------------------------------------------------------


def query(message_id: str | None = None, text: str = MESSAGE.text) -> ReconcileQuery:
    return ReconcileQuery(
        message=Message(MESSAGE.delivery_id, text),
        recipient=SMS,
        provider_message_id=message_id,
        attempted_at=NOW,
    )


def record(**overrides: Any) -> dict[str, Any]:
    base = {
        "id": "777",
        "date": "2026-01-15 12:00:05",
        "type": "0",
        "did": "2025550100",
        "contact": "2025550142",
        "message": MESSAGE.text,
    }
    base.update(overrides)
    return {key: value for key, value in base.items() if value is not ...}


def test_reconcile_window_query_parameters(
    provider: VoipmsSmsProvider, transport: StubTransport
) -> None:
    transport.json({"status": "no_sms"})
    assert provider.reconcile(query()) is ReconcileStatus.NOT_DELIVERED
    fields = multipart_fields(transport.requests[0])
    assert fields["method"] == "getSMS"
    assert (fields["did"], fields["contact"], fields["type"]) == ("2025550100", "2025550142", "0")
    assert (fields["from"], fields["to"], fields["timezone"]) == ("2026-01-15", "2026-01-15", "0")
    assert fields["limit"] == str(RECONCILE_LIMIT)
    assert "sms" not in fields


def test_same_text_without_an_id_is_never_delivered(
    provider: VoipmsSmsProvider, transport: StubTransport
) -> None:
    """An earlier, distinct SMS with the same DID, contact and text in the
    window must not suppress the retry of this one."""
    transport.json({"status": "success", "sms": [record(), record(id="778")]})
    assert provider.reconcile(query()) is ReconcileStatus.UNKNOWN


@pytest.mark.parametrize(
    "records",
    [[], [record(message="another message")], ["not a record", 7, None]],
)
def test_without_an_id_only_no_sms_is_not_delivered(
    provider: VoipmsSmsProvider, transport: StubTransport, records: list[object]
) -> None:
    transport.json({"status": "success", "sms": records})
    assert provider.reconcile(query()) is ReconcileStatus.UNKNOWN


@pytest.mark.parametrize(
    ("message_id", "outcome"),
    [(None, ReconcileStatus.NOT_DELIVERED), ("777", ReconcileStatus.UNKNOWN)],
)
def test_reconcile_no_sms(
    provider: VoipmsSmsProvider,
    transport: StubTransport,
    message_id: str | None,
    outcome: ReconcileStatus,
) -> None:
    transport.json({"status": "no_sms"})
    assert provider.reconcile(query(message_id)) is outcome


@pytest.mark.parametrize("record_id", ["777", 777])
def test_exact_id_match_is_delivered(
    provider: VoipmsSmsProvider, transport: StubTransport, record_id: object
) -> None:
    transport.json({"status": "success", "sms": [record(id=record_id, message="other text")]})
    assert provider.reconcile(query("777")) is ReconcileStatus.DELIVERED
    fields = multipart_fields(transport.requests[0])
    assert fields["sms"] == "777"
    assert "from" not in fields


@pytest.mark.parametrize("message_type", ["0", 0])
def test_outbound_type_forms(
    provider: VoipmsSmsProvider, transport: StubTransport, message_type: object
) -> None:
    transport.json({"status": "success", "sms": [record(type=message_type)]})
    assert provider.reconcile(query("777")) is ReconcileStatus.DELIVERED


@pytest.mark.parametrize(
    "bad",
    [
        record(type=...),
        record(type="1"),
        record(type=1),
        record(type=False),
        record(type=None),
        record(type="00"),
        record(did=...),
        record(did="2025550198"),
        record(did=True),
        record(did=2025550100.0),
        record(contact=...),
        record(contact="2025550199"),
        record(contact="+12025550142"),
        record(contact=None),
    ],
)
def test_id_match_with_missing_or_wrong_route_is_unknown(
    provider: VoipmsSmsProvider, transport: StubTransport, bad: dict[str, Any]
) -> None:
    transport.json({"status": "success", "sms": [bad]})
    assert provider.reconcile(query("777")) is ReconcileStatus.UNKNOWN


def test_numeric_route_fields_are_accepted(
    provider: VoipmsSmsProvider, transport: StubTransport
) -> None:
    transport.json(
        {"status": "success", "sms": [record(did=2025550100, contact=2025550142, type=0)]}
    )
    assert provider.reconcile(query("777")) is ReconcileStatus.DELIVERED


@pytest.mark.parametrize(
    "records",
    [[], [record(id="778")], [record(id=None)], ["junk"], [record(id="7770")]],
)
def test_id_not_found_is_unknown(
    provider: VoipmsSmsProvider, transport: StubTransport, records: list[object]
) -> None:
    transport.json({"status": "success", "sms": records})
    assert provider.reconcile(query("777")) is ReconcileStatus.UNKNOWN


def test_reconcile_ignores_an_invalid_known_id(
    provider: VoipmsSmsProvider, transport: StubTransport
) -> None:
    transport.json({"status": "no_sms"})
    assert provider.reconcile(query("not-an-id")) is ReconcileStatus.NOT_DELIVERED
    assert "sms" not in multipart_fields(transport.requests[0])


def test_reconcile_examines_a_bounded_number_of_records(
    provider: VoipmsSmsProvider, transport: StubTransport
) -> None:
    filler = [record(id="1")] * RECONCILE_LIMIT
    transport.json({"status": "success", "sms": [*filler, record()]})
    assert provider.reconcile(query("777")) is ReconcileStatus.UNKNOWN


@pytest.mark.parametrize(
    "payload",
    [
        {"status": "invalid_credentials"},
        {"status": "success", "sms": "not a list"},
        {"status": "success"},
        ["success"],
    ],
)
def test_reconcile_uncertain_answers_are_unknown(
    provider: VoipmsSmsProvider, transport: StubTransport, payload: Any
) -> None:
    transport.json(payload)
    assert provider.reconcile(query()) is ReconcileStatus.UNKNOWN
    assert provider.reconcile(query("777")) is ReconcileStatus.UNKNOWN


@pytest.mark.parametrize(
    "respond",
    [
        lambda _r: httpx.Response(500),
        lambda _r: httpx.Response(302, headers={"Location": "https://evil.example.test/"}),
        lambda _r: httpx.Response(200, content=b"<soap/>"),
    ],
)
def test_reconcile_failures_are_unknown(
    provider: VoipmsSmsProvider, transport: StubTransport, respond: Any
) -> None:
    transport.respond(respond)
    assert provider.reconcile(query()) is ReconcileStatus.UNKNOWN


def test_reconcile_timeout_is_unknown(
    provider: VoipmsSmsProvider, transport: StubTransport
) -> None:
    def fail(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("fictitious")

    transport.respond(fail)
    assert provider.reconcile(query()) is ReconcileStatus.UNKNOWN


def test_reconcile_other_recipient_types_is_unknown_without_a_request(
    provider: VoipmsSmsProvider, transport: StubTransport
) -> None:
    other = ReconcileQuery(MESSAGE, HA, None, NOW)
    assert provider.reconcile(other) is ReconcileStatus.UNKNOWN
    assert transport.requests == []


def test_reconcile_uses_utc_dates(provider: VoipmsSmsProvider, transport: StubTransport) -> None:
    transport.json({"status": "no_sms"})
    late = ReconcileQuery(MESSAGE, SMS, None, NOW.replace(hour=23, minute=55))
    provider.reconcile(late)
    fields = multipart_fields(transport.requests[0])
    assert (fields["from"], fields["to"]) == ("2026-01-15", "2026-01-16")
    early = ReconcileQuery(MESSAGE, SMS, None, NOW.replace(hour=0, minute=5))
    provider.reconcile(early)
    fields = multipart_fields(transport.requests[1])
    assert fields["from"] == (NOW - timedelta(days=1)).date().isoformat()


def test_reconcile_never_queries_another_number(
    provider: VoipmsSmsProvider, transport: StubTransport
) -> None:
    transport.json({"status": "success", "sms": [record(contact="2025550199")]})
    other = VoipmsRecipient(provider="voipms", phone=PhoneNumber.parse("2025550143"))
    assert provider.reconcile(ReconcileQuery(MESSAGE, other, "777", NOW)) is (
        ReconcileStatus.UNKNOWN
    )
    assert multipart_fields(transport.requests[0])["contact"] == "2025550143"

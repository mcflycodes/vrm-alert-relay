"""Named scenario (R32): malicious labels, templates and provider responses
cannot alter recipients or inject content."""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
import pytest
from provider_helpers import (
    DID,
    HA,
    HA_TOKEN,
    HA_URL,
    HOOK,
    NOW,
    SMS,
    VOIPMS_PASSWORD,
    VOIPMS_URL,
    VOIPMS_USER,
    WEBHOOK_URL,
    StubTransport,
    json_body,
    multipart_fields,
    secret,
)

from vrm_alert_relay.delivery.protocol import delivery_id
from vrm_alert_relay.providers import (
    DetailedMessage,
    HomeAssistantNotifyProvider,
    VoipmsSmsProvider,
    WebhookPostProvider,
)
from vrm_alert_relay.templates import (
    NotificationKind,
    Template,
    TemplateFields,
    TemplateSyntaxError,
    render_notification,
)

if TYPE_CHECKING:
    from vrm_alert_relay.net import SafeHttpClient

EVIL_LABEL = "Freezer\n\nSTOP\r\nTo: +1 202 555 0199 {rule} {{level}}\u202e\x1b]8;;https://evil.example.test\x07"


def malicious_message() -> DetailedMessage:
    fields = TemplateFields(
        kind=NotificationKind.ESCALATED,
        rule="freezer",
        level="critical",
        value=-3.5,
        installation="cabin",
        label=EVIL_LABEL,
        time=NOW,
    )
    return DetailedMessage(delivery_id("evt_fake", "sms"), render_notification(fields), fields)


def test_label_cannot_break_lines_or_expand_placeholders() -> None:
    text = malicious_message().text
    assert "\n" not in text
    assert "\r" not in text
    assert "\x1b" not in text
    assert "\u202e" not in text
    assert "{rule}" in text
    assert text.startswith("critical: freezer at cabin: Freezer STOP To: +1 202 555 0199")


@pytest.mark.parametrize(
    "source",
    ["{rule.__class__}", "{label!r}", "{value:>100000000}", "{recipients}", "{phone}", "{0}"],
)
def test_templates_cannot_reach_beyond_the_field_allowlist(source: str) -> None:
    with pytest.raises(TemplateSyntaxError):
        Template(source)


def test_voipms_destination_comes_only_from_the_recipient(
    http: SafeHttpClient, transport: StubTransport
) -> None:
    provider = VoipmsSmsProvider(
        http,
        username=secret(VOIPMS_USER),
        password=secret(VOIPMS_PASSWORD),
        did=DID,
        base_url=VOIPMS_URL,
    )
    transport.json({"status": "success", "sms": 1, "dst": "2025550199", "redirect": "x"})
    provider.send(malicious_message(), SMS)
    provider.send(malicious_message(), SMS)
    for request in transport.requests:
        assert str(request.url) == VOIPMS_URL
        fields = multipart_fields(request)
        assert fields["dst"] == "2025550142"
        assert fields["did"] == "2025550100"
        assert "\n" not in fields["message"]


def test_home_assistant_service_comes_only_from_the_recipient(
    http: SafeHttpClient, transport: StubTransport
) -> None:
    provider = HomeAssistantNotifyProvider(http, base_url=HA_URL, token=secret(HA_TOKEN))
    transport.respond(
        lambda _r: httpx.Response(
            200,
            json={"service": "notify.attacker", "url": "https://evil.example.test/"},
            headers={"Location": "https://evil.example.test/"},
        )
    )
    provider.send(malicious_message(), HA)
    provider.send(malicious_message(), HA)
    for request in transport.requests:
        assert str(request.url) == f"{HA_URL}/api/services/notify/mobile_app_example_phone"
        assert set(json_body(request)) == {"message", "title"}


def test_webhook_url_and_shape_are_fixed(http: SafeHttpClient, transport: StubTransport) -> None:
    provider = WebhookPostProvider(http, url=WEBHOOK_URL)
    transport.respond(
        lambda _r: httpx.Response(307, headers={"Location": "https://evil.example.test/"})
    )
    provider.send(malicious_message(), HOOK)
    transport.json({"url": "https://evil.example.test/"})
    provider.send(malicious_message(), HOOK)
    assert [str(r.url) for r in transport.requests] == [WEBHOOK_URL, WEBHOOK_URL]
    payload = json_body(transport.requests[1])
    assert "label" not in payload
    assert "\n" not in payload["text"]

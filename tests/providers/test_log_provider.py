"""The dry-run log provider."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import pytest
from provider_helpers import HA, HOOK, LOG, MESSAGE, SMS, StubTransport, assert_no_secrets

from vrm_alert_relay.delivery.protocol import Message, Provider, SendStatus
from vrm_alert_relay.providers import DryRunLogProvider, describe_recipient

if TYPE_CHECKING:
    from vrm_alert_relay.config import Recipient


@pytest.mark.parametrize(
    ("recipient", "shown"),
    [
        (SMS, "sms:***-***-0142"),
        (HA, "notify.mobile_app_example_phone"),
        (HOOK, "webhook"),
        (LOG, "log"),
    ],
)
def test_logs_what_would_be_sent(
    recipient: Recipient,
    shown: str,
    caplog: pytest.LogCaptureFixture,
    transport: StubTransport,
) -> None:
    provider = DryRunLogProvider()
    assert isinstance(provider, Provider)
    with caplog.at_level(logging.INFO):
        result = provider.send(MESSAGE, recipient)
    assert result.status is SendStatus.DELIVERED
    (record,) = caplog.records
    assert record.event == "provider.dry_run"  # type: ignore[attr-defined]
    assert record.provider == recipient.provider  # type: ignore[attr-defined]
    assert record.recipient == shown  # type: ignore[attr-defined]
    assert record.delivery_id == MESSAGE.delivery_id  # type: ignore[attr-defined]
    assert record.text == MESSAGE.text  # type: ignore[attr-defined]
    assert describe_recipient(recipient) == shown
    assert transport.requests == []
    assert_no_secrets(caplog.records)


def test_sms_dry_run_shows_the_trimmed_text(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO):
        DryRunLogProvider().send(Message("dlv_long", "x" * 500), SMS)
        DryRunLogProvider().send(Message("dlv_long", "x" * 500), HA)
    sms, ha = caplog.records
    assert len(sms.text) == 160  # type: ignore[attr-defined]
    assert len(ha.text) == 500  # type: ignore[attr-defined]


def test_repr() -> None:
    assert repr(DryRunLogProvider()) == "DryRunLogProvider()"

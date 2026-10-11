"""Fake providers, configuration, and a switchable failing SQLite connection.

Every identifier, number, and address here is fictitious.
"""

from __future__ import annotations

import random
import sqlite3
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from vrm_alert_relay.config import RelayConfig, parse_config
from vrm_alert_relay.delivery import (
    DeliveryEngine,
    DeliveryLimits,
    Message,
    Notification,
    RecipientTarget,
    ReconcileQuery,
    ReconcileStatus,
    RuleTarget,
    SendResult,
    SendStatus,
)
from vrm_alert_relay.state import StateStore

if TYPE_CHECKING:
    from pathlib import Path

    from vrm_alert_relay.config import Recipient

BASE = datetime(2035, 1, 1, tzinfo=UTC)

CONFIG_TEMPLATE = """
version: 1
sending: {{enabled: {sending}}}
vrm:
  token_file: /run/secrets/fictitious-vrm-token
  installations: [{{id: cabin, site_id: 123456}}]
rate_limits: {{global_per_hour: {per_hour}, global_per_day: {per_day}, retries: {retries}}}
recipients:
  owner_sms: {{provider: voipms, phone: "+1 202 555 0142"}}
  partner_sms: {{provider: voipms, phone: "+1 202 555 0177"}}
  audit: {{provider: log}}
  hook: {{provider: webhook}}
providers:
  voipms:
    enabled: {voipms}
    username_file: /run/secrets/fictitious-voipms-user
    password_file: /run/secrets/fictitious-voipms-password
    did: "2025550100"
  webhook: {{enabled: false, url: "https://hooks.example.com/relay"}}
rules:
  - id: freezer
    installation: cabin
    measurement: {{code: tsT, instance: 20}}
    direction: rising
    levels: [{{name: warning, threshold: -12}}, {{name: critical, threshold: -4.5}}]
    recipients: [owner_sms]
  - id: battery
    installation: cabin
    measurement: {{code: bs, instance: 512}}
    direction: falling
    levels: [{{name: warning, threshold: 40}}]
    recipients: [owner_sms, partner_sms, audit]
"""


def make_config(
    *,
    sending: bool = True,
    voipms: bool = True,
    per_hour: int = 20,
    per_day: int = 60,
    retries: int = 3,
) -> RelayConfig:
    return parse_config(
        CONFIG_TEMPLATE.format(
            sending=str(sending).lower(),
            voipms=str(voipms).lower(),
            per_hour=per_hour,
            per_day=per_day,
            retries=retries,
        )
    )


@dataclass
class Sent:
    message: Message
    recipient: Recipient
    result: SendResult | None


@dataclass
class FakeProvider:
    """Records every send; returns scripted results, then ``default``."""

    results: deque[SendResult | BaseException | Any] = field(default_factory=deque)
    default: SendResult = field(default_factory=lambda: SendResult(SendStatus.DELIVERED, "msg-1"))
    sent: list[Sent] = field(default_factory=list)

    def script(self, *results: SendResult | BaseException | Any) -> None:
        self.results.extend(results)

    def send(self, message: Message, recipient: Recipient) -> SendResult:
        outcome = self.results.popleft() if self.results else self.default
        if isinstance(outcome, BaseException):
            self.sent.append(Sent(message, recipient, None))
            raise outcome
        self.sent.append(Sent(message, recipient, outcome))
        return outcome  # type: ignore[no-any-return]


@dataclass
class FakeReconcilingProvider(FakeProvider):
    """A provider with a lookup; returns scripted reconcile outcomes."""

    lookups: deque[ReconcileStatus | BaseException | Any] = field(default_factory=deque)
    queries: list[ReconcileQuery] = field(default_factory=list)

    def reconcile(self, query: ReconcileQuery) -> ReconcileStatus:
        self.queries.append(query)
        outcome = self.lookups.popleft() if self.lookups else ReconcileStatus.UNKNOWN
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome  # type: ignore[no-any-return]


class FailSwitch:
    """While ``on``, statements fail (all, or those containing ``only``), except ROLLBACK."""

    def __init__(self, error: str = "database or disk is full", only: str | None = None) -> None:
        self.on = False
        self.error = error
        self.only = only
        self.failures = 0

    def check(self, sql: str) -> None:
        if (
            self.on
            and not sql.lstrip().upper().startswith("ROLLBACK")
            and (self.only is None or self.only in sql)
        ):
            self.failures += 1
            raise sqlite3.OperationalError(self.error)


class FlakyConnection:
    """A real SQLite connection whose statements fail on demand."""

    def __init__(self, inner: sqlite3.Connection, switch: FailSwitch) -> None:
        self._inner = inner
        self._switch = switch

    def execute(self, sql: str, params: Any = ()) -> sqlite3.Cursor:
        self._switch.check(sql)
        return self._inner.execute(sql, params)

    def executemany(self, sql: str, params: Any) -> sqlite3.Cursor:
        self._switch.check(sql)
        return self._inner.executemany(sql, params)

    def close(self) -> None:
        self._inner.close()


def flaky_store(state_dir: Path, switch: FailSwitch, **kwargs: Any) -> StateStore:
    def connect(path: Path) -> Any:
        return FlakyConnection(sqlite3.connect(path, autocommit=True), switch)

    return StateStore(state_dir, connect=connect, **kwargs)


def make_engine(
    store: StateStore,
    *,
    config: RelayConfig | None = None,
    voipms: FakeProvider | None = None,
    dry_run: FakeProvider | None = None,
    now: datetime = BASE,
    limits: DeliveryLimits | None = None,
    seed: int = 7,
) -> DeliveryEngine:
    return DeliveryEngine.from_config(
        config or make_config(),
        providers={"voipms": voipms or FakeProvider()},
        dry_run=dry_run or FakeProvider(),
        store=store,
        now=now,
        rng=random.Random(seed),  # noqa: S311  # deterministic jitter, not cryptography
        limits=limits,
    )


def event_id(n: int) -> str:
    return f"evt_{n:064x}"


def rule_note(n: int, rule_id: str = "freezer", text: str = "Freezer warming") -> Notification:
    return Notification(event_id=event_id(n), text=text, target=RuleTarget(rule_id))


def direct_note(n: int, name: str, text: str = "Test notification") -> Notification:
    return Notification(event_id=event_id(n), text=text, target=RecipientTarget(name))

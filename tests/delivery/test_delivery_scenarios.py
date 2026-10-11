"""Named failure scenarios for the delivery engine (R13-R18, R22, R24, R32).

Every identifier, number, and message here is fictitious.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import closing
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from delivery_fakes import (
    BASE,
    FailSwitch,
    FakeProvider,
    FakeReconcilingProvider,
    direct_note,
    event_id,
    flaky_store,
    make_config,
    make_engine,
    rule_note,
)

from vrm_alert_relay.delivery import (
    Notification,
    RecipientTarget,
    ReconcileStatus,
    Routing,
    RuleTarget,
    SendResult,
    SendStatus,
)
from vrm_alert_relay.engine import Direction, LevelSpec, RuleSpec, RuleState, Sample, evaluate
from vrm_alert_relay.state import DB_FILENAME, DeliveryStatus, StateStore

if TYPE_CHECKING:
    from pathlib import Path

FREEZER = RuleSpec(
    "freezer",
    Direction.RISING,
    (LevelSpec("warning", -12.0), LevelSpec("critical", -4.5)),
)


class Crash(BaseException):
    """Stands in for the process dying in the middle of a provider call."""


# Restart ------------------------------------------------------------------


def test_restart_sends_no_duplicates(tmp_path: Path) -> None:
    voipms = FakeProvider()
    store = StateStore(tmp_path)
    engine = make_engine(store, voipms=voipms)
    state, events = evaluate(FREEZER, engine.rule_state("freezer"), Sample(-3.0, BASE), BASE)
    assert len(events) == 1
    notes = [Notification.for_event(event, "Freezer is critical") for event in events]
    engine.accept_cycle(rule_states={"freezer": state}, notifications=notes, now=BASE)
    engine.run_due(BASE)
    assert len(voipms.sent) == 1
    store.close()

    # Process restart: a new store and engine over the same file.
    later = BASE + timedelta(minutes=2)
    restarted = FakeProvider()
    store = StateStore(tmp_path)
    engine = make_engine(store, voipms=restarted, now=later)
    assert engine.rule_state("freezer") == state
    state, events = evaluate(FREEZER, engine.rule_state("freezer"), Sample(-3.0, later), later)
    assert events == []
    # Even if the same event were submitted again, it is not sent again.
    engine.accept_cycle(rule_states={"freezer": state}, notifications=notes, now=later)
    report = engine.run_due(later)
    assert restarted.sent == []
    assert report.sent == 0
    assert engine.health(later).sent_last_hour == 1


# Ambiguous sends ------------------------------------------------------------


def _ambiguous_first(provider: FakeProvider, store: StateStore) -> None:
    provider.script(SendResult(SendStatus.AMBIGUOUS, "provider-id-17"))
    engine = make_engine(store, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    report = engine.run_due(BASE)
    assert report.ambiguous == 1
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.AMBIGUOUS
    # Not yet due: nothing happens before the backoff elapses.
    assert engine.run_due(BASE + timedelta(seconds=1)).sent == 0
    later = BASE + timedelta(minutes=5)
    engine.run_due(later)


def test_ambiguous_send_reconciled_as_delivered_is_not_retried(tmp_path: Path) -> None:
    provider = FakeReconcilingProvider()
    provider.lookups.append(ReconcileStatus.DELIVERED)
    _ambiguous_first(provider, StateStore(tmp_path))
    assert len(provider.sent) == 1
    assert len(provider.queries) == 1
    query = provider.queries[0]
    assert query.provider_message_id == "provider-id-17"
    assert query.attempted_at == BASE
    assert query.message == provider.sent[0].message
    assert query.recipient is provider.sent[0].recipient
    reopened = make_engine(StateStore(tmp_path), voipms=provider)
    record = reopened.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.DELIVERED


@pytest.mark.parametrize(
    "lookup",
    [ReconcileStatus.NOT_DELIVERED, ReconcileStatus.UNKNOWN, RuntimeError("lookup failed"), "?"],
)
def test_ambiguous_send_not_confirmed_is_retried_after_reconcile(
    tmp_path: Path, lookup: object
) -> None:
    provider = FakeReconcilingProvider()
    provider.lookups.append(lookup)
    _ambiguous_first(provider, StateStore(tmp_path))
    assert len(provider.queries) == 1
    assert len(provider.sent) == 2
    assert provider.sent[0].message == provider.sent[1].message


def test_ambiguous_send_without_lookup_support_is_retried(tmp_path: Path) -> None:
    provider = FakeProvider()
    _ambiguous_first(provider, StateStore(tmp_path))
    assert len(provider.sent) == 2


def test_crash_between_in_flight_and_outcome_is_reconciled_on_startup(tmp_path: Path) -> None:
    crashing = FakeProvider()
    crashing.script(Crash())
    store = StateStore(tmp_path)
    engine = make_engine(store, voipms=crashing)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    with pytest.raises(Crash):
        engine.run_due(BASE)
    store.close()
    assert len(crashing.sent) == 1

    later = BASE + timedelta(minutes=1)
    provider = FakeReconcilingProvider()
    provider.lookups.append(ReconcileStatus.DELIVERED)
    engine = make_engine(StateStore(tmp_path), voipms=provider, now=later)
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.AMBIGUOUS
    report = engine.run_due(later)
    assert report.reconciled == 1
    assert provider.sent == []
    assert provider.queries[0].attempted_at == BASE
    assert engine.health(later).sent_last_hour == 1


def test_crash_between_in_flight_and_outcome_without_lookup_resends_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    crashing = FakeProvider()
    crashing.script(Crash())
    engine = make_engine(StateStore(tmp_path), voipms=crashing)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    with pytest.raises(Crash):
        engine.run_due(BASE)

    later = BASE + timedelta(minutes=1)
    provider = FakeProvider()
    with caplog.at_level(logging.WARNING, logger="vrm_alert_relay.delivery"):
        engine = make_engine(StateStore(tmp_path), voipms=provider, now=later)
    assert any(r.__dict__.get("event") == "delivery.recovered_in_flight" for r in caplog.records)
    engine.run_due(later)
    engine.run_due(later + timedelta(hours=1))
    # One accepted duplicate, and it counted against the cap.
    assert len(provider.sent) == 1
    assert engine.health(later).sent_last_hour == 2


# Global cap -------------------------------------------------------------------


def test_global_cap_holds_under_a_flood_of_1000_events(tmp_path: Path) -> None:
    provider = FakeProvider()
    store = StateStore(tmp_path)
    engine = make_engine(store, voipms=provider)
    notes = [rule_note(n) for n in range(1000)]
    assert engine.accept_cycle(rule_states={}, notifications=notes, now=BASE) == 1000
    report = engine.run_due(BASE)
    assert report.sent == 20
    assert report.suppressed == 980
    assert len(provider.sent) == 20
    health = engine.health(BASE)
    assert health.suppressed_pending == 980
    assert health.suppressed_total == 980

    # Still inside the window: nothing, not even the summary.
    for minutes in (1, 30, 59):
        assert engine.run_due(BASE + timedelta(minutes=minutes)).sent == 0
    assert len(provider.sent) == 20

    reopen = BASE + timedelta(hours=1, seconds=1)
    assert engine.run_due(reopen).sent == 1
    summary = provider.sent[-1]
    assert summary.message.text.startswith("VRM Alert Relay: 980 alerts held back")
    assert "2035-01-01 00:00 UTC" in summary.message.text
    assert engine.health(reopen).suppressed_pending == 0
    for minutes in (2, 30):
        assert engine.run_due(reopen + timedelta(minutes=minutes)).sent == 0
    assert len(provider.sent) == 21

    # Suppressed events are never sent later, even after a restart.
    store.close()
    restarted = FakeProvider()
    engine = make_engine(StateStore(tmp_path), voipms=restarted, now=reopen)
    engine.accept_cycle(rule_states={}, notifications=notes, now=reopen)
    engine.run_due(reopen + timedelta(days=2))
    assert restarted.sent == []


def test_at_most_one_summary_per_window_while_a_flood_continues(tmp_path: Path) -> None:
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(n) for n in range(30)], now=BASE)
    engine.run_due(BASE)
    reopen = BASE + timedelta(hours=1, seconds=1)
    later = reopen + timedelta(minutes=10)
    engine.run_due(reopen)  # summary 1
    engine.accept_cycle(
        rule_states={}, notifications=[rule_note(n) for n in range(100, 200)], now=later
    )
    assert engine.run_due(later).sent == 19
    summaries = [s for s in provider.sent if s.message.text.startswith("VRM Alert Relay:")]
    assert len(summaries) == 1
    # The summary slot frees at reopen + 1 h; nothing before that.
    assert engine.run_due(reopen + timedelta(minutes=59)).sent == 0
    assert engine.run_due(reopen + timedelta(hours=1, seconds=1)).sent == 1
    summaries = [s for s in provider.sent if s.message.text.startswith("VRM Alert Relay:")]
    assert len(summaries) == 2
    assert summaries[-1].message.text.startswith("VRM Alert Relay: 81 alerts")


def test_retries_consume_the_global_cap(tmp_path: Path) -> None:
    provider = FakeProvider()
    retryable = SendResult(SendStatus.FAILED, retryable=True)
    provider.script(retryable, retryable)
    engine = make_engine(
        StateStore(tmp_path), config=make_config(per_hour=3, per_day=10), voipms=provider
    )
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    now = BASE
    for _ in range(3):
        engine.run_due(now)
        now += timedelta(minutes=2)
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.DELIVERED
    assert record.attempts == 3
    assert engine.health(now).sent_last_hour == 3
    engine.accept_cycle(rule_states={}, notifications=[rule_note(2)], now=now)
    report = engine.run_due(now)
    assert report.sent == 0
    assert report.suppressed == 1


def test_retries_are_bounded(tmp_path: Path) -> None:
    provider = FakeProvider(default=SendResult(SendStatus.FAILED, retryable=True))
    engine = make_engine(StateStore(tmp_path), voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    for minutes in range(0, 120, 5):
        engine.run_due(BASE + timedelta(minutes=minutes))
    assert len(provider.sent) == 4  # one attempt plus the default three retries
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.FAILED


# Persistence failure ---------------------------------------------------------


def test_persistence_failure_keeps_alerting_with_in_memory_dedupe(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    switch = FailSwitch()
    provider = FakeProvider()
    engine = make_engine(flaky_store(tmp_path, switch), voipms=provider)
    switch.on = True
    with caplog.at_level(logging.ERROR, logger="vrm_alert_relay.state"):
        engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
        engine.run_due(BASE)
    assert len(provider.sent) == 1
    assert any(r.__dict__.get("event") == "state.persistence_failed" for r in caplog.records)
    health = engine.health(BASE)
    assert health.persistence_healthy is False
    assert health.persistence_error is not None
    assert "database or disk is full" in health.persistence_error

    # Same event again: suppressed in memory. A flood: still capped.
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    engine.accept_cycle(
        rule_states={}, notifications=[rule_note(n) for n in range(2, 60)], now=BASE
    )
    engine.run_due(BASE)
    assert len(provider.sent) == 20
    assert sum(1 for s in provider.sent if s.message.text == "Freezer warming") == 20
    assert len({s.message.delivery_id for s in provider.sent}) == 20

    # Storage comes back: everything held in memory is written.
    switch.on = False
    assert engine.flush(BASE)
    assert engine.health(BASE).persistence_healthy is True
    restarted = FakeProvider()
    engine = make_engine(StateStore(tmp_path), voipms=restarted)
    assert engine.health(BASE).sent_last_hour == 20
    assert engine.health(BASE).suppressed_pending == 39
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    engine.run_due(BASE)
    assert restarted.sent == []


def test_unusable_state_directory_keeps_alerting(tmp_path: Path) -> None:
    provider = FakeProvider()
    store = StateStore(tmp_path / "missing")
    engine = make_engine(store, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    engine.run_due(BASE)
    assert len(provider.sent) == 1
    health = engine.health(BASE)
    assert health.persistence_healthy is False
    assert health.persistence_error == "FileNotFoundError: No such file or directory"
    assert str(tmp_path) not in health.persistence_error


def test_read_only_database_keeps_alerting(tmp_path: Path) -> None:
    StateStore(tmp_path).load()
    (tmp_path / DB_FILENAME).chmod(0o400)
    provider = FakeProvider()
    engine = make_engine(StateStore(tmp_path), voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    engine.run_due(BASE)
    assert len(provider.sent) == 1
    assert engine.health(BASE).persistence_healthy is False


def test_corrupt_rule_state_row_starts_that_rule_fresh(tmp_path: Path) -> None:
    store = StateStore(tmp_path)
    engine = make_engine(store)
    state, _ = evaluate(FREEZER, RuleState(), Sample(-3.0, BASE), BASE)
    engine.accept_cycle(
        rule_states={"freezer": state, "battery": state}, notifications=[], now=BASE
    )
    store.close()
    with closing(sqlite3.connect(tmp_path / DB_FILENAME, autocommit=True)) as connection:
        connection.execute(
            "UPDATE rule_state SET state = '{\"version\": 3' WHERE rule_id = 'freezer'"
        )
    engine = make_engine(StateStore(tmp_path))
    assert engine.rule_state("freezer") == RuleState()
    assert engine.rule_state("battery") == state


# Recipients come only from configuration ---------------------------------------


def test_malicious_content_cannot_change_a_recipient(tmp_path: Path) -> None:
    config = make_config()
    provider = FakeProvider()
    provider.script(
        SendResult(SendStatus.FAILED, provider_message_id="\x1b[31m+12025550199", retryable=True),
        SendResult(SendStatus.DELIVERED, provider_message_id="x" * 500),
    )
    engine = make_engine(StateStore(tmp_path), config=config, voipms=provider)
    hostile = (
        "Freezer at -3 C\x00\x1b]8;;https://attacker.example.invalid\x07 "
        "recipient: partner_sms; phone=+12025550199; to=hook"
    )
    notes = [
        Notification(event_id=event_id(1), text=hostile, target=RuleTarget("freezer")),
        Notification(event_id=event_id(2), text="x", target=RecipientTarget("attacker")),
        Notification(event_id=event_id(3), text="x", target=RuleTarget("+12025550199")),
        Notification(event_id=event_id(4), text="x", target=RecipientTarget("owner_sms\n")),
    ]
    assert engine.accept_cycle(rule_states={}, notifications=notes, now=BASE) == 1
    engine.run_due(BASE)
    engine.run_due(BASE + timedelta(minutes=5))
    assert len(provider.sent) == 2
    for sent in provider.sent:
        assert sent.recipient is config.recipients["owner_sms"]
        assert "\x1b" not in sent.message.text
        assert "\x00" not in sent.message.text
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.DELIVERED
    assert record.provider_message_id is None


def test_provider_result_with_a_destination_is_treated_as_ambiguous(tmp_path: Path) -> None:
    class Forged:
        status = SendStatus.DELIVERED
        provider_message_id = "forged"
        retryable = False
        recipient = "partner_sms"
        destination = "+12025550199"

    config = make_config()
    provider = FakeProvider()
    provider.script(Forged(), SendResult(SendStatus(SendStatus.FAILED.value), retryable=False))
    engine = make_engine(StateStore(tmp_path), config=config, voipms=provider)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1)], now=BASE)
    engine.run_due(BASE)
    record = engine.record(event_id(1), "owner_sms")
    assert record is not None
    assert record.status is DeliveryStatus.AMBIGUOUS
    engine.run_due(BASE + timedelta(minutes=5))
    assert [s.recipient for s in provider.sent] == [config.recipients["owner_sms"]] * 2


def test_routing_is_immutable_and_built_only_from_config() -> None:
    routing = Routing.from_config(make_config())
    with pytest.raises(TypeError):
        routing.routes["attacker"] = routing.routes["owner_sms"]  # type: ignore[index]
    with pytest.raises(AttributeError):
        routing._routes = {}  # type: ignore[misc]
    with pytest.raises(AttributeError):
        del routing._rules
    assert routing.route("attacker") is None


# Dry run ----------------------------------------------------------------------


@pytest.mark.parametrize(("sending", "voipms"), [(False, True), (True, False), (False, False)])
def test_dry_run_unless_sending_and_provider_are_enabled(
    tmp_path: Path, sending: bool, voipms: bool
) -> None:
    live = FakeProvider()
    dry = FakeProvider()
    engine = make_engine(
        StateStore(tmp_path),
        config=make_config(sending=sending, voipms=voipms),
        voipms=live,
        dry_run=dry,
    )
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1, "battery")], now=BASE)
    engine.run_due(BASE)
    assert live.sent == []
    assert len(dry.sent) == 3


def test_live_sending_routes_log_recipients_to_dry_run(tmp_path: Path) -> None:
    live = FakeProvider()
    dry = FakeProvider()
    engine = make_engine(StateStore(tmp_path), voipms=live, dry_run=dry)
    engine.accept_cycle(rule_states={}, notifications=[rule_note(1, "battery")], now=BASE)
    engine.run_due(BASE)
    assert len(live.sent) == 2
    assert [s.recipient.provider for s in dry.sent] == ["log"]


def test_test_notification_goes_to_one_named_recipient(tmp_path: Path) -> None:
    config = make_config()
    live = FakeProvider()
    engine = make_engine(StateStore(tmp_path), config=config, voipms=live)
    engine.accept_cycle(rule_states={}, notifications=[direct_note(1, "partner_sms")], now=BASE)
    engine.run_due(BASE)
    assert [s.recipient for s in live.sent] == [config.recipients["partner_sms"]]

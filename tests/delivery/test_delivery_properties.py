"""Property tests: the global cap and at-most-once delivery hold for any history.

Histories mix submissions to several recipients (live and dry-run), real and
wall-clock-only time steps, restarts, crashes mid-send, SQLite and journal
failures, corrupt rows, and providers with and without a lookup.

Every identifier and message here is fictitious.
"""

from __future__ import annotations

import sqlite3
import tempfile
from contextlib import closing, suppress
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from delivery_fakes import (
    FailSwitch,
    FakeClock,
    FlakyConnection,
    direct_note,
    make_config,
    make_engine,
    rule_note,
)
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from vrm_alert_relay.delivery import (
    STORAGE_NOTICE_TEXT,
    Message,
    ReconcileQuery,
    ReconcileStatus,
    SendResult,
    SendStatus,
    delivery_id,
)
from vrm_alert_relay.state import (
    DB_FILENAME,
    JOURNAL_FILENAME,
    Changes,
    DeliveryStatus,
    JournalEntry,
    StateStore,
)

if TYPE_CHECKING:
    from datetime import datetime

    from vrm_alert_relay.config import Recipient
    from vrm_alert_relay.delivery import DeliveryEngine

PER_HOUR = 2
PER_DAY = 4
RETRIES = 2
MAX_SKEW = timedelta(days=1)


class Crash(BaseException):
    """The process dies during a provider call."""


OUTCOMES = st.sampled_from(
    [
        SendResult(SendStatus.DELIVERED, "provider-id"),
        SendResult(SendStatus.FAILED, retryable=True),
        SendResult(SendStatus.FAILED, retryable=False),
        SendResult(SendStatus.AMBIGUOUS),
        "raise",
        "crash",
    ]
)
TARGETS = st.sampled_from(["freezer", "battery", "pump", "audit"])
KINDS = (
    *("submit",) * 4,
    *("run",) * 4,
    *("restart",) * 2,
    *("advance",) * 2,
    "jump",
    "sqlite",
    "journal",
    "corrupt",
)
OPERATION = st.tuples(
    st.sampled_from(KINDS),
    st.integers(0, 3),
    TARGETS,
    st.integers(0, 3600),
    st.integers(-2 * 86_400, 2 * 86_400),
    st.sampled_from([None, "INSERT", "FROM", ""]),
    st.booleans(),
)
OPERATIONS = st.lists(OPERATION, min_size=10, max_size=60)


@dataclass
class World:
    """The provider's view of what happened, in order."""

    clock: FakeClock
    outcomes: list[Any]
    lookups: list[ReconcileStatus]
    log: list[tuple[str, str, Any]] = field(default_factory=list)
    real_sends: list[float] = field(default_factory=list)
    notices: int = 0


class Recorder:
    """A live provider without a lookup."""

    def __init__(self, world: World) -> None:
        self.world = world

    def send(self, message: Message, recipient: Recipient) -> SendResult:
        world = self.world
        if message.text == STORAGE_NOTICE_TEXT:
            world.notices += 1
            return SendResult(SendStatus.DELIVERED)
        world.real_sends.append(world.clock.mono)
        outcome = world.outcomes.pop(0) if world.outcomes else SendResult(SendStatus.DELIVERED)
        world.log.append(("send", message.delivery_id, outcome))
        if outcome == "crash":
            raise Crash
        if outcome == "raise":
            raise RuntimeError("connection reset")
        return outcome  # type: ignore[no-any-return]


class ReconcilingRecorder(Recorder):
    """A live provider with a lookup."""

    def reconcile(self, query: ReconcileQuery) -> ReconcileStatus:
        world = self.world
        outcome = world.lookups.pop(0) if world.lookups else ReconcileStatus.UNKNOWN
        if outcome is ReconcileStatus.DELIVERED:
            world.log.append(("confirmed", query.message.delivery_id, None))
        return outcome


class DryRun:
    def send(self, message: Message, recipient: Recipient) -> SendResult:
        return SendResult(SendStatus.DELIVERED)


class TrackingStore(StateStore):
    """Remembers the last status of each delivery that reached durable storage."""

    def __init__(self, path: Path, switch: FailSwitch, durable: dict[str, Any]) -> None:
        def connect(db: Path) -> Any:
            return FlakyConnection(sqlite3.connect(db, autocommit=True), switch)

        super().__init__(path, connect=connect)
        self.durable = durable

    def flush(self, changes: Changes, now: datetime) -> bool:
        ok = super().flush(changes, now)
        if ok:
            for record in changes.deliveries:
                self.durable[_delivery_id(record.event_id, record.recipient)] = record.status
        return ok

    def journal(self, entries: tuple[JournalEntry, ...]) -> bool:
        ok = super().journal(entries)
        if ok:
            for entry in entries:
                record = entry.record
                self.durable[_delivery_id(record.event_id, record.recipient)] = record.status
        return ok


def _delivery_id(event: str, recipient: str) -> str:
    return delivery_id(event, recipient)


def _block_journal(directory: Path, *, blocked: bool) -> None:
    """Make the journal unreadable and unwritable, or usable again."""
    path = directory / JOURNAL_FILENAME
    if blocked:
        path.touch()
        path.chmod(0o000)
    elif path.exists():
        path.chmod(0o600)


def _corrupt(directory: Path, kind: str, world: World) -> None:
    with suppress(sqlite3.Error), closing(sqlite3.connect(directory / DB_FILENAME)) as connection:
        if kind == "attempt":
            connection.execute(
                "INSERT INTO send_attempt (event_id, recipient, attempt, at, live) "
                "VALUES ('evt_corrupt', 'owner_sms', 1, 'garbage', 1)"
            )
        else:
            row = connection.execute(
                "SELECT event_id, recipient, status FROM delivery LIMIT 1"
            ).fetchone()
            if row is None:
                return
            connection.execute(
                "UPDATE delivery SET created_at = 'garbage' WHERE event_id = ? AND recipient = ?",
                row[:2],
            )
            if not DeliveryStatus(row[2]).terminal:
                world.log.append(("credit", _delivery_id(row[0], row[1]), "corrupt"))
        connection.commit()


def _assert_cap(times: list[float]) -> None:
    times = sorted(times)
    for index, start in enumerate(times):
        assert len([t for t in times[index:] if t < start + 3600]) <= PER_HOUR
        assert len([t for t in times[index:] if t < start + 86_400]) <= PER_DAY


def _assert_at_most_once_except_after_ambiguous(log: list[tuple[str, str, Any]]) -> None:
    """After a delivery is confirmed, another send needs a fresh ambiguity."""
    confirmed: set[str] = set()
    pending_credits: dict[str, int] = {}
    for kind, delivery, outcome in log:
        if kind == "credit":
            pending_credits[delivery] = pending_credits.get(delivery, 0) + 1
            continue
        if kind == "send" and delivery in confirmed:
            assert pending_credits.get(delivery, 0) > 0, f"{delivery} sent again after delivery"
            pending_credits[delivery] -= 1
        delivered = kind == "confirmed" or (
            isinstance(outcome, SendResult) and outcome.status is SendStatus.DELIVERED
        )
        if delivered:
            confirmed.add(delivery)
            pending_credits[delivery] = 0
        elif kind == "send" and outcome in ("raise", "crash", SendResult(SendStatus.AMBIGUOUS)):
            pending_credits[delivery] = pending_credits.get(delivery, 0) + 1


def _start(
    directory: Path, switch: FailSwitch, durable: dict[str, Any], world: World, provider: Recorder
) -> tuple[DeliveryEngine, StateStore]:
    for delivery, status in durable.items():
        if status is DeliveryStatus.IN_FLIGHT:  # the outcome never became durable
            world.log.append(("credit", delivery, "restart"))
    store = TrackingStore(directory, switch, durable)
    config = make_config(per_hour=PER_HOUR, per_day=PER_DAY, retries=RETRIES)
    engine = make_engine(
        store,
        clock=world.clock,
        config=config,
        voipms=provider,  # type: ignore[arg-type]
        dry_run=DryRun(),  # type: ignore[arg-type]
    )
    return engine, store


def _step(  # noqa: C901  # one branch per operation
    operation: tuple[Any, ...], state: dict[str, Any]
) -> None:
    world: World = state["world"]
    clock = world.clock
    kind, number, target, seconds, jump, mode, flag = operation
    match kind:
        case "submit":
            note = direct_note(number, "audit") if target == "audit" else rule_note(number, target)
            state["engine"].accept_cycle(rule_states={}, notifications=[note])
        case "advance":
            clock.advance(timedelta(seconds=seconds))
        case "jump":
            skew = state["skew"] + timedelta(seconds=jump)
            if -MAX_SKEW <= skew <= MAX_SKEW:
                clock.jump_wall(timedelta(seconds=jump))
                state["skew"] = skew
        case "run":
            try:
                state["engine"].run_due()
            except Crash:
                _restart(state)
        case "restart":
            _restart(state)
        case "sqlite":
            state["switch"].on = mode is not None
            state["switch"].only = mode or None
        case "journal":
            _block_journal(state["dir"], blocked=flag)
        case _:
            if not state["switch"].on:
                _corrupt(state["dir"], "attempt" if flag else "delivery", world)


def _restart(state: dict[str, Any]) -> None:
    state["store"].close()
    clock: FakeClock = state["world"].clock
    if state["skew"] > timedelta(0):
        # A forward jump is corrected before a restart (ADR 0002 accepted risk).
        clock.jump_wall(-state["skew"])
        state["skew"] = timedelta(0)
    state["engine"], state["store"] = _start(
        state["dir"], state["switch"], state["durable"], state["world"], state["provider"]
    )
    state["processes"] += 1


@settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large],
)
@given(
    operations=OPERATIONS,
    outcomes=st.lists(OUTCOMES, max_size=30),
    lookups=st.lists(st.sampled_from(list(ReconcileStatus)), max_size=15),
    reconciles=st.booleans(),
)
def test_cap_and_at_most_once_hold_for_any_history(
    operations: list[tuple[Any, ...]],
    outcomes: list[Any],
    lookups: list[ReconcileStatus],
    reconciles: bool,
) -> None:
    world = World(FakeClock(), list(outcomes), list(lookups))
    provider = ReconcilingRecorder(world) if reconciles else Recorder(world)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        switch = FailSwitch()
        durable: dict[str, Any] = {}
        engine, store = _start(path, switch, durable, world, provider)
        state: dict[str, Any] = {
            "world": world,
            "dir": path,
            "switch": switch,
            "durable": durable,
            "provider": provider,
            "engine": engine,
            "store": store,
            "skew": timedelta(0),
            "processes": 1,
        }
        try:
            for operation in operations:
                _step(operation, state)
        finally:
            state["store"].close()
            _block_journal(path, blocked=False)
    _assert_cap(world.real_sends)
    _assert_at_most_once_except_after_ambiguous(world.log)
    assert world.notices <= state["processes"]

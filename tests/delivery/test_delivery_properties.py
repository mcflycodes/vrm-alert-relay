"""Property tests: the global cap and at-most-once delivery hold for any history.

Histories mix submissions to several recipients (live and dry-run), real and
wall-clock-only time steps, restarts, crashes mid-send, SQLite and journal
failures, corrupt rows, a corrupt database, and providers with and without a
lookup. Every real provider call counts: alerts, summaries, storage notices.

The cap must hold across the whole history unless a failure mode occurred
that ADR 0002 accepts (a restart that cannot read the stored history, a send
recorded nowhere, a lost database, or a forward clock jump across a
restart); then it must hold within every process.

Every identifier and message here is fictitious.
"""

from __future__ import annotations

import os
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
from hypothesis import HealthCheck, example, given, settings
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
READ_FAILURES = (None, "FROM", "")
"""SQLite failure modes in which a restart cannot read the stored history."""


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
    "quarantine",
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
OPERATIONS = st.lists(OPERATION, min_size=10, max_size=120)

# Found by a worker on a branch stacked on ff292ae: two sends fill the hour,
# the journal is unreadable at a restart, the wall clock then jumps forward,
# and merging the history mid-process re-derived the held slots from the
# wall clock, freeing them. A third send followed in the same second.
REGRESSION_C6 = [
    *[("submit", 0, "freezer", 0, 0, None, False)] * 22,
    ("submit", 0, "battery", 0, 0, None, False),
    ("submit", 2, "freezer", 0, 0, None, False),
    ("run", 0, "freezer", 0, 0, None, False),
    ("journal", 0, "freezer", 0, 0, None, True),
    ("restart", 0, "freezer", 0, 0, None, False),
    ("jump", 0, "freezer", 0, 11205, None, False),
    ("journal", 0, "freezer", 0, 0, None, False),
    ("run", 0, "freezer", 0, 0, None, False),
]


@dataclass
class World:
    """The provider's view of what happened, in order."""

    clock: FakeClock
    outcomes: list[Any]
    lookups: list[ReconcileStatus]
    log: list[tuple[str, str, Any]] = field(default_factory=list)
    real_sends: list[tuple[int, float]] = field(default_factory=list)
    """(process, monotonic time) of every real provider call: alerts, summaries, notices."""
    notices: list[tuple[int, float]] = field(default_factory=list)
    process: int = 0
    unrecordable: Any = None
    """Returns whether nothing could record a send right now (set by the test)."""
    unrecorded: set[str] = field(default_factory=set)
    """Deliveries last sent while nothing could record the send."""
    impaired: bool = False
    """Whether a failure mode made the cross-restart cap a per-process cap (ADR 0002)."""


class Recorder:
    """A live provider without a lookup."""

    def __init__(self, world: World) -> None:
        self.world = world

    def send(self, message: Message, recipient: Recipient) -> SendResult:
        world = self.world
        world.real_sends.append((world.process, world.clock.mono))
        if message.text == STORAGE_NOTICE_TEXT:
            world.notices.append((world.process, world.clock.mono))
        outcome = world.outcomes.pop(0) if world.outcomes else SendResult(SendStatus.DELIVERED)
        world.log.append(("send", message.delivery_id, outcome))
        if world.unrecordable is not None and world.unrecordable():
            world.unrecorded.add(message.delivery_id)
        else:
            world.unrecorded.discard(message.delivery_id)
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


@dataclass
class Durable:
    """The last status of each delivery in SQLite and in the journal."""

    sqlite: dict[str, DeliveryStatus] = field(default_factory=dict)
    journal: dict[str, DeliveryStatus] = field(default_factory=dict)

    def visible(self, *, sqlite: bool, journal: bool) -> dict[str, DeliveryStatus]:
        view = dict(self.sqlite) if sqlite else {}
        if journal:
            view.update(self.journal)
        return view


class TrackingStore(StateStore):
    """Remembers the status of each delivery that reached durable storage."""

    def __init__(self, path: Path, switch: FailSwitch, durable: Durable) -> None:
        def connect(db: Path) -> Any:
            return FlakyConnection(sqlite3.connect(db, autocommit=True), switch)

        super().__init__(path, connect=connect)
        self.durable = durable

    def flush(self, changes: Changes, now: datetime) -> bool:
        ok = super().flush(changes, now)
        if ok:
            self.durable.sqlite.update(self.durable.journal)  # merged, then cleared
            self.durable.journal.clear()
            for record in changes.deliveries:
                self.durable.sqlite[_delivery_id(record.event_id, record.recipient)] = record.status
        return ok

    def journal(self, entries: tuple[JournalEntry, ...], now: datetime) -> bool:
        ok = super().journal(entries, now)
        if ok:
            for entry in entries:
                record = entry.record
                self.durable.journal[_delivery_id(record.event_id, record.recipient)] = (
                    record.status
                )
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


def _journal_blocked(directory: Path) -> bool:
    path = directory / JOURNAL_FILENAME
    return path.exists() and not os.access(path, os.R_OK)


def _corrupt(directory: Path, kind: str, world: World) -> None:
    with suppress(sqlite3.Error), closing(sqlite3.connect(directory / DB_FILENAME)) as connection:
        if kind == "attempt":
            connection.execute(
                "INSERT INTO send_attempt (event_id, recipient, attempt, at) "
                "VALUES ('evt_corrupt', 'owner_sms', 1, 'garbage')"
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


def _assert_caps(world: World) -> None:
    """The cap is hard unless a failure mode occurred; then it holds in every process."""
    for process in {p for p, _ in world.real_sends}:
        _assert_cap([t for p, t in world.real_sends if p == process])
    if not world.impaired:
        _assert_cap([t for _, t in world.real_sends])


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


def _start(state: dict[str, Any]) -> tuple[DeliveryEngine, StateStore]:
    world: World = state["world"]
    switch: FailSwitch = state["switch"]
    durable: Durable = state["durable"]
    directory: Path = state["dir"]
    sqlite_readable = not (switch.on and switch.only in READ_FAILURES)
    journal_readable = not _journal_blocked(directory)
    visible = durable.visible(sqlite=sqlite_readable, journal=journal_readable)
    for delivery in sorted(world.unrecorded | set(durable.visible(sqlite=True, journal=True))):
        # Anything the new process cannot see as finished may be sent again:
        # a send recorded nowhere, an outcome that never became durable, or
        # one it cannot read yet (accepted, ADR 0002).
        seen = visible.get(delivery)
        if seen is None or not seen.terminal:
            world.log.append(("credit", delivery, "restart"))
    store = TrackingStore(directory, switch, durable)
    world.unrecordable = lambda: _journal_blocked(directory) and (switch.on or not store.readable)
    config = make_config(per_hour=PER_HOUR, per_day=PER_DAY, retries=RETRIES)
    engine = make_engine(
        store,
        clock=world.clock,
        config=config,
        voipms=state["provider"],
        dry_run=DryRun(),  # type: ignore[arg-type]
    )
    return engine, store


def _step(  # noqa: C901, PLR0912  # one branch per operation
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
        case "quarantine":
            state["store"].close()
            (state["dir"] / DB_FILENAME).write_bytes(b"not a database" * 64)
            for delivery in state["durable"].sqlite:
                # A lost database forgets what was delivered (accepted, ADR 0002).
                world.log.append(("credit", delivery, "quarantine"))
            state["durable"].sqlite.clear()
            _restart(state, close=False)
        case _:
            if not state["switch"].on:
                _corrupt(state["dir"], "attempt" if flag else "delivery", world)
    if state["switch"].on and _journal_blocked(state["dir"]):
        world.impaired = True  # a send now may be recorded nowhere


def _restart(state: dict[str, Any], *, close: bool = True) -> None:
    world: World = state["world"]
    switch: FailSwitch = state["switch"]
    if close:
        state["store"].close()
    journal = state["dir"] / JOURNAL_FILENAME
    if (
        (switch.on and switch.only in READ_FAILURES)
        or (_journal_blocked(state["dir"]) and journal.stat().st_size > 0)
        or state["skew"] > timedelta(0)  # a forward jump across a restart (accepted risk)
        or not close  # the database was lost
    ):
        world.impaired = True
    world.process += 1
    state["engine"], state["store"] = _start(state)


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
@example(operations=REGRESSION_C6, outcomes=[], lookups=[], reconciles=False)
def test_cap_and_at_most_once_hold_for_any_history(
    operations: list[tuple[Any, ...]],
    outcomes: list[Any],
    lookups: list[ReconcileStatus],
    reconciles: bool,
) -> None:
    world = World(FakeClock(), list(outcomes), list(lookups))
    provider = ReconcilingRecorder(world) if reconciles else Recorder(world)
    with tempfile.TemporaryDirectory() as directory:
        state: dict[str, Any] = {
            "world": world,
            "dir": Path(directory),
            "switch": FailSwitch(),
            "durable": Durable(),
            "provider": provider,
            "skew": timedelta(0),
        }
        state["engine"], state["store"] = _start(state)
        started = {0: world.clock.mono}
        try:
            for operation in operations:
                process = world.process
                _step(operation, state)
                if world.process != process:
                    started[world.process] = world.clock.mono
        finally:
            state["store"].close()
            _block_journal(state["dir"], blocked=False)
    _assert_caps(world)
    _assert_at_most_once_except_after_ambiguous(world.log)
    for process, began in started.items():
        # One notice per process start, then at most one per day (ADR 0002).
        sent = [t for p, t in world.notices if p == process]
        lasted = (sent[-1] - began) if sent else 0.0
        assert len(sent) <= 1 + int(lasted // 86_400)


def test_the_c6_regression_is_a_normal_operation_history() -> None:
    """The pinned example has no failure mode that weakens the cap: the hard cap applies."""
    world = World(FakeClock(), [], [])
    with tempfile.TemporaryDirectory() as directory:
        state: dict[str, Any] = {
            "world": world,
            "dir": Path(directory),
            "switch": FailSwitch(),
            "durable": Durable(),
            "provider": Recorder(world),
            "skew": timedelta(0),
        }
        state["engine"], state["store"] = _start(state)
        try:
            for operation in REGRESSION_C6:
                _step(operation, state)
        finally:
            state["store"].close()
            _block_journal(state["dir"], blocked=False)
    assert not world.impaired
    assert len(world.real_sends) == PER_HOUR
    _assert_caps(world)

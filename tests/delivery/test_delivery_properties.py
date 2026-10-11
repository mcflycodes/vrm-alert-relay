"""Property tests: the global cap and at-most-once delivery hold for any history.

Every identifier and message here is fictitious.
"""

from __future__ import annotations

import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING, Any

from delivery_fakes import BASE, make_config, make_engine, rule_note
from hypothesis import given, settings
from hypothesis import strategies as st

from vrm_alert_relay.delivery import (
    Message,
    ReconcileQuery,
    ReconcileStatus,
    SendResult,
    SendStatus,
)
from vrm_alert_relay.state import StateStore

if TYPE_CHECKING:
    from vrm_alert_relay.config import Recipient

PER_HOUR = 3
PER_DAY = 7
RETRIES = 2

OUTCOMES = st.sampled_from(
    [
        SendResult(SendStatus.DELIVERED, "provider-id"),
        SendResult(SendStatus.FAILED, retryable=True),
        SendResult(SendStatus.FAILED, retryable=False),
        SendResult(SendStatus.AMBIGUOUS),
        RuntimeError("connection reset"),
    ]
)
LOOKUPS = st.sampled_from(list(ReconcileStatus))
OPERATIONS = st.lists(
    st.one_of(
        st.tuples(st.just("submit"), st.integers(0, 12), st.sampled_from(["freezer", "battery"])),
        st.tuples(st.just("advance"), st.integers(0, 3 * 3600)),
        st.tuples(st.just("run")),
        st.tuples(st.just("restart")),
    ),
    min_size=1,
    max_size=60,
)


@dataclass
class Clock:
    now: datetime = BASE


@dataclass
class Recorder:
    """A provider that logs every call with the current fake time."""

    clock: Clock
    outcomes: list[Any]
    lookups: list[ReconcileStatus]
    reconciles: bool
    calls: list[tuple[datetime, str, Any]] = field(default_factory=list)
    confirmed: dict[str, int] = field(default_factory=dict)
    """Delivery IDs confirmed by a lookup, with the number of sends made before."""

    def send(self, message: Message, recipient: Recipient) -> SendResult:
        outcome = self.outcomes.pop(0) if self.outcomes else SendResult(SendStatus.DELIVERED)
        self.calls.append((self.clock.now, message.delivery_id, outcome))
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome  # type: ignore[no-any-return]

    def reconcile(self, query: ReconcileQuery) -> ReconcileStatus:
        if not self.reconciles:
            return ReconcileStatus.UNKNOWN
        outcome = self.lookups.pop(0) if self.lookups else ReconcileStatus.UNKNOWN
        if outcome is ReconcileStatus.DELIVERED:
            delivery = query.message.delivery_id
            self.confirmed[delivery] = sum(1 for call in self.calls if call[1] == delivery)
        return outcome


def _assert_cap(times: list[datetime]) -> None:
    times = sorted(times)
    for index, start in enumerate(times):
        in_hour = [t for t in times[index:] if t < start + timedelta(hours=1)]
        in_day = [t for t in times[index:] if t < start + timedelta(days=1)]
        assert len(in_hour) <= PER_HOUR
        assert len(in_day) <= PER_DAY


def _assert_at_most_once(calls: list[tuple[datetime, str, Any]], confirmed: dict[str, int]) -> None:
    by_delivery: dict[str, list[Any]] = defaultdict(list)
    for _, delivery, outcome in calls:
        by_delivery[delivery].append(outcome)
    for delivery, outcomes in by_delivery.items():
        assert len(outcomes) <= 1 + RETRIES
        delivered_at = [
            index
            for index, outcome in enumerate(outcomes)
            if isinstance(outcome, SendResult) and outcome.status is SendStatus.DELIVERED
        ]
        # Nothing is sent again after a confirmed delivery.
        assert not delivered_at or delivered_at[0] == len(outcomes) - 1
        # Nothing is sent again after a lookup confirmed delivery.
        if delivery in confirmed:
            assert len(outcomes) == confirmed[delivery]
            assert not delivered_at


@settings(max_examples=60, deadline=None)
@given(
    operations=OPERATIONS,
    outcomes=st.lists(OUTCOMES, max_size=40),
    lookups=st.lists(LOOKUPS, max_size=20),
    reconciles=st.booleans(),
)
def test_cap_and_at_most_once_hold_for_any_history(
    operations: list[tuple[Any, ...]],
    outcomes: list[Any],
    lookups: list[ReconcileStatus],
    reconciles: bool,
) -> None:
    clock = Clock()
    provider = Recorder(clock, list(outcomes), list(lookups), reconciles)
    config = make_config(per_hour=PER_HOUR, per_day=PER_DAY, retries=RETRIES)
    with tempfile.TemporaryDirectory() as directory:
        store = StateStore(Path(directory))
        engine = make_engine(store, config=config, voipms=provider, dry_run=provider)  # type: ignore[arg-type]
        for operation in operations:
            match operation:
                case ("submit", number, rule):
                    engine.accept_cycle(
                        rule_states={}, notifications=[rule_note(number, rule)], now=clock.now
                    )
                case ("advance", seconds):
                    clock.now += timedelta(seconds=seconds)
                case ("run",):
                    engine.run_due(clock.now)
                case _:
                    store.close()
                    store = StateStore(Path(directory))
                    engine = make_engine(
                        store,
                        config=config,
                        voipms=provider,  # type: ignore[arg-type]
                        dry_run=provider,  # type: ignore[arg-type]
                        now=clock.now,
                    )
        store.close()
    _assert_cap([at for at, _, _ in provider.calls])
    _assert_at_most_once(provider.calls, provider.confirmed)

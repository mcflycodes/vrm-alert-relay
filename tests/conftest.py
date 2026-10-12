"""Fixtures shared by every test package."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from vrm_alert_relay.state import StateStore

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture(autouse=True)
def _close_state_stores(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Close every store a test opened, so no SQLite connection leaks a warning."""
    opened: list[StateStore] = []
    original = StateStore.__init__

    def tracking_init(self: StateStore, *args: Any, **kwargs: Any) -> None:
        original(self, *args, **kwargs)
        opened.append(self)

    monkeypatch.setattr(StateStore, "__init__", tracking_init)
    yield
    for store in opened:
        store.close()

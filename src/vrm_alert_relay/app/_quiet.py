"""Logging that can never stop the relay.

Operator-visibility records (startup details, held escalations, cycle
summaries) are informative only. A logging handler that raises must not
stop startup or a cycle, or delay an alert, so these records go through
:func:`log_info`, which drops a record whose logging fails.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import logging
    from collections.abc import Mapping

__all__ = ["log_info"]


def log_info(log: logging.Logger, message: str, extra: Mapping[str, object]) -> None:
    """Log ``message`` at INFO with ``extra``; a failure to log is swallowed."""
    with contextlib.suppress(Exception):
        log.info(message, extra=dict(extra))

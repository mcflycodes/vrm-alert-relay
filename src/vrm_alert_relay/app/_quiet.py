"""Logging that can never stop the relay.

Operator-visibility records (startup details, held escalations, cycle
summaries, notifications an operator chose to log only, monitoring
notices) are informative only. A logging handler that raises must not
stop startup or a cycle, or delay an alert, so these records go through
:func:`log_info`, :func:`log_warning` or :func:`log_error`, which drop a
record whose logging fails.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import logging
    from collections.abc import Mapping

__all__ = ["log_error", "log_info", "log_warning"]


def log_info(log: logging.Logger, message: str, extra: Mapping[str, object]) -> None:
    """Log ``message`` at INFO with ``extra``; a failure to log is swallowed."""
    with contextlib.suppress(Exception):
        log.info(message, extra=dict(extra))


def log_warning(log: logging.Logger, message: str, extra: Mapping[str, object]) -> None:
    """Log ``message`` at WARNING with ``extra``; a failure to log is swallowed."""
    with contextlib.suppress(Exception):
        log.warning(message, extra=dict(extra))


def log_error(log: logging.Logger, message: str, extra: Mapping[str, object]) -> None:
    """Log ``message`` at ERROR with ``extra``; a failure to log is swallowed."""
    with contextlib.suppress(Exception):
        log.error(message, extra=dict(extra))

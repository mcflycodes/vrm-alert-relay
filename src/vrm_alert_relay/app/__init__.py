"""The relay service: the poll loop, monitoring notifications and the health endpoint.

:mod:`~vrm_alert_relay.app.service` builds the service from configuration;
:mod:`~vrm_alert_relay.app.relay` runs one poll cycle;
:mod:`~vrm_alert_relay.app.scheduler` repeats cycles until stopped;
:mod:`~vrm_alert_relay.app.monitoring` turns polling failures into monitoring
degraded and restored notifications; :mod:`~vrm_alert_relay.app.health` serves
the optional health endpoint.
"""

from .health import HealthServer, HealthState, health_document
from .monitoring import DEGRADED_AFTER_CYCLES, MonitoringTracker, PollHealth, assess
from .relay import CycleReport, Poller, Relay, RelayStatus
from .scheduler import Scheduler
from .service import (
    CONFIG_ENV,
    DEFAULT_CONFIG_PATH,
    DEFAULT_STATE_DIR,
    STATE_DIR_ENV,
    ExitCode,
    Runtime,
    Service,
    StartupError,
    TestOutcome,
    open_runtime,
    send_test_notification,
)

__all__ = [
    "CONFIG_ENV",
    "DEFAULT_CONFIG_PATH",
    "DEFAULT_STATE_DIR",
    "DEGRADED_AFTER_CYCLES",
    "STATE_DIR_ENV",
    "CycleReport",
    "ExitCode",
    "HealthServer",
    "HealthState",
    "MonitoringTracker",
    "PollHealth",
    "Poller",
    "Relay",
    "RelayStatus",
    "Runtime",
    "Scheduler",
    "Service",
    "StartupError",
    "TestOutcome",
    "assess",
    "health_document",
    "open_runtime",
    "send_test_notification",
]

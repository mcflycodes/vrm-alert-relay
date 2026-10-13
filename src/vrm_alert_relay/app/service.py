"""Building the relay from configuration, running it, and shutting it down.

:func:`open_runtime` loads the configuration and its secrets, builds the
providers, opens the state store and builds the delivery engine; the
``run`` and ``test-notification`` commands share it. :class:`Service` adds
the VRM adapter, the poll loop and the optional health endpoint.

Startup fails only when the configuration (or a secret or provider it
needs) is unusable, or when another relay process holds the state
directory (ADR 0002). Every other storage problem leaves the relay running
and alerting, with its health reporting the problem.
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING, Final

from vrm_alert_relay import __version__
from vrm_alert_relay.config import ConfigError, Secret, display_name, load_config, load_secrets
from vrm_alert_relay.delivery import (
    DeliveryEngine,
    Notification,
    RecipientTarget,
    SystemClock,
)
from vrm_alert_relay.net import InvalidCaFileError, SafeHttpClient
from vrm_alert_relay.providers import ProviderSetupError, build_providers
from vrm_alert_relay.state import DeliveryStatus, StateLockedError, StateStore
from vrm_alert_relay.vrm import VrmAdapter

from ._quiet import log_info
from .health import HealthServer, HealthState, health_document
from .relay import Relay
from .rules import config_fingerprint, log_loaded_rules
from .scheduler import Scheduler

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

    from vrm_alert_relay.config import RelayConfig
    from vrm_alert_relay.delivery import Clock, RunReport
    from vrm_alert_relay.providers import ProviderSet
    from vrm_alert_relay.vrm import Backoff

    from .scheduler import Stopper

__all__ = [
    "CONFIG_ENV",
    "DEFAULT_CONFIG_PATH",
    "DEFAULT_STATE_DIR",
    "STATE_DIR_ENV",
    "ExitCode",
    "Runtime",
    "Service",
    "StartupError",
    "TestOutcome",
    "open_runtime",
    "send_test_notification",
]

logger = logging.getLogger(__name__)

CONFIG_ENV: Final = "VRM_ALERT_RELAY_CONFIG"
STATE_DIR_ENV: Final = "VRM_ALERT_RELAY_STATE_DIR"
DEFAULT_CONFIG_PATH: Final = "/etc/vrm-alert-relay/config.yaml"
DEFAULT_STATE_DIR: Final = "/var/lib/vrm-alert-relay"
TEST_MESSAGE: Final = (
    "VRM Alert Relay: test notification. If you can read this, delivery to this recipient works."
)


class ExitCode(IntEnum):
    """Process exit codes, documented in docs/operations.md."""

    OK = 0
    NOT_DELIVERED = 1
    """``test-notification``: the message was not (or not known to be) delivered."""
    USAGE = 2
    """Invalid command-line usage (argparse's own code)."""
    CONFIG = 3
    """The configuration, a secret file or a provider setting is unusable."""
    STATE_LOCKED = 4
    """Another relay process holds the state directory."""


class StartupError(Exception):
    """The relay cannot start. ``problems`` are safe to show to the operator."""

    def __init__(self, code: ExitCode, problems: Sequence[str]) -> None:
        super().__init__(*problems)
        self.code = code
        self.problems = tuple(problems)


def resolve_config_path(flag: str | None) -> str:
    return flag or os.environ.get(CONFIG_ENV) or DEFAULT_CONFIG_PATH


def resolve_state_dir(flag: str | None) -> str:
    return flag or os.environ.get(STATE_DIR_ENV) or DEFAULT_STATE_DIR


@dataclass(slots=True)
class Runtime:
    """Configuration, providers, state and delivery, ready for use. Close it."""

    config: RelayConfig
    providers: ProviderSet
    store: StateStore
    delivery: DeliveryEngine
    vrm_token: Secret = field(repr=False)
    clock: Clock

    def close(self) -> None:
        try:
            self.delivery.flush()
        finally:
            self.store.close()
            self.providers.close()


def open_runtime(
    config_path: str | os.PathLike[str],
    state_dir: str | os.PathLike[str],
    *,
    clock: Clock | None = None,
) -> Runtime:
    """Load and build everything except VRM polling. Raises :class:`StartupError`."""
    clock = clock if clock is not None else SystemClock()
    try:
        config = load_config(config_path)
        secrets, warnings = load_secrets(config)
    except ConfigError as exc:
        raise StartupError(ExitCode.CONFIG, exc.problems) from None
    if secrets.vrm_token is None:
        raise StartupError(ExitCode.CONFIG, ["vrm.token_file: the token was not loaded"])
    token = secrets.vrm_token
    for warning in warnings:
        logger.warning(warning, extra={"event": "config.warning"})
    try:
        providers = build_providers(config, secrets)
    except (ProviderSetupError, InvalidCaFileError) as exc:
        raise StartupError(ExitCode.CONFIG, [str(exc)]) from None
    store = StateStore(Path(state_dir))
    try:
        delivery = DeliveryEngine.from_config(
            config,
            providers=providers.providers,
            dry_run=providers.dry_run,
            store=store,
            clock=clock,
        )
    except StateLockedError:
        store.close()
        providers.close()
        raise StartupError(
            ExitCode.STATE_LOCKED,
            ["state directory: another relay process is using it; stop that process first"],
        ) from None
    except BaseException:
        store.close()
        providers.close()
        raise
    return Runtime(
        config=config,
        providers=providers,
        store=store,
        delivery=delivery,
        vrm_token=token,
        clock=clock,
    )


class Service:
    """The running relay: poll loop, delivery and the optional health endpoint."""

    def __init__(
        self,
        runtime: Runtime,
        *,
        backoff: Backoff | None = None,
        http: SafeHttpClient | None = None,
    ) -> None:
        self.runtime = runtime
        self.config = runtime.config
        self._http = http if http is not None else SafeHttpClient()
        clock = runtime.clock
        self.adapter = VrmAdapter(
            self._http,
            runtime.vrm_token,
            base_url=self.config.vrm.base_url,
            backoff=backoff,
            clock=clock.monotonic,
            wall_clock=clock.wall,
        )
        self.relay = Relay(self.config, poller=self.adapter, delivery=runtime.delivery, clock=clock)
        self.health_state = HealthState()
        self.health_server: HealthServer | None = None
        self.dry_run = not self.config.live_providers()
        self.config_fingerprint = config_fingerprint(self.config)
        self._cycle_failed = False

    def run_cycle(self) -> None:
        """Run one cycle, remembering whether it raised (for health)."""
        try:
            self.relay.run_cycle()
        except BaseException:
            self._cycle_failed = True
            raise
        self._cycle_failed = False

    def publish_health(self) -> None:
        self.health_state.publish(
            health_document(
                version=__version__,
                dry_run=self.dry_run,
                config_fingerprint=self.config_fingerprint,
                status=self.relay.status,
                delivery=self.runtime.delivery.health(),
                cycle_failed=self._cycle_failed or self.relay.status.monitoring_failed,
            )
        )

    def start_health(self, *, port: int | None = None) -> None:
        """Start the health endpoint when enabled; a failure to bind is logged, not fatal."""
        settings = self.config.health
        if not settings.enabled:
            return
        self.publish_health()
        try:
            server = HealthServer(
                settings.bind, settings.port if port is None else port, self.health_state
            )
        except OSError as exc:
            logger.error(  # noqa: TRY400  # the cause is shown without a traceback
                "health endpoint could not start; the relay keeps running without it",
                extra={"event": "health.bind_failed", "error": type(exc).__name__},
            )
            return
        server.start()
        self.health_server = server

    def run(
        self,
        stop: Stopper,
        *,
        max_cycles: int | None = None,
        clock: Callable[[], float] | None = None,
        rng: Callable[[], float] | None = None,
    ) -> int:
        """Run cycles until ``stop`` is set (or ``max_cycles``); returns cycles run.

        The startup and stop records are informative only: a failure to log
        them never keeps the relay from running.
        """
        log_info(
            logger,
            "relay started",
            {
                "event": "service.started",
                "version": __version__,
                "dry_run": self.dry_run,
                "live_providers": list(self.config.live_providers()),
                "installations": len(self.config.vrm.installations),
                "rules": len(self.config.rules),
                "poll_interval": self.config.vrm.poll_interval,
                "config_fingerprint": self.config_fingerprint,
            },
        )
        log_loaded_rules(self.config)
        scheduler_options: dict[str, Callable[[], float]] = {}
        if clock is not None:
            scheduler_options["clock"] = clock
        if rng is not None:
            scheduler_options["rng"] = rng
        scheduler = Scheduler(
            self.run_cycle,
            interval=float(self.config.vrm.poll_interval),
            stop=stop,
            after_cycle=self.publish_health,
            **scheduler_options,
        )
        cycles = scheduler.run(max_cycles=max_cycles)
        log_info(logger, "relay stopping", {"event": "service.stopping", "cycles": cycles})
        return cycles

    def close(self) -> None:
        """Stop the health endpoint, flush and close state, and close every client."""
        try:
            if self.health_server is not None:
                self.health_server.close()
        finally:
            try:
                self._http.close()
            finally:
                self.runtime.close()
        log_info(logger, "relay stopped", {"event": "service.stopped"})


@dataclass(frozen=True, slots=True)
class TestOutcome:
    """The result of ``test-notification``, safe to print."""

    recipient: str
    """The recipient as ``check-config`` displays it."""
    live: bool
    status: DeliveryStatus | None
    report: RunReport

    @property
    def delivered(self) -> bool:
        return self.status is DeliveryStatus.DELIVERED

    def describe(self) -> str:
        mode = "live" if self.live else "dry run"
        if self.status is DeliveryStatus.DELIVERED:
            if self.live:
                return f"delivered to {self.recipient} ({mode})"
            return (
                f"dry run: the message to {self.recipient} was written to the log, not sent "
                "(sending is not enabled for its provider)"
            )
        if self.status is DeliveryStatus.SUPPRESSED:
            return (
                f"held back by the global rate limit: nothing was sent to {self.recipient} "
                f"({mode}); it will be counted in the next held-back summary"
            )
        if self.status is DeliveryStatus.AMBIGUOUS:
            return (
                f"outcome unknown for {self.recipient} ({mode}): the provider did not confirm "
                "the message; the relay reconciles or retries it on its next run"
            )
        if self.status is DeliveryStatus.PENDING:
            return (
                f"not delivered to {self.recipient} ({mode}): the provider refused it for now; "
                "the relay retries it on its next run"
            )
        return f"not delivered to {self.recipient} ({mode}): the provider refused the message"


def send_test_notification(runtime: Runtime, recipient: str) -> TestOutcome:
    """Send one test message to one named recipient (R26).

    The message goes through the delivery engine like any other: the global
    cap, dry-run routing, attempt records and reconciliation all apply, and
    nothing else due is sent. Raises :class:`StartupError` for a recipient
    that is not configured.
    """
    config = runtime.config
    names = list(config.recipients)
    if recipient not in config.recipients:
        raise StartupError(
            ExitCode.CONFIG,
            ["--recipient: not a configured recipient (see check-config for the names)"],
        )
    shown = display_name(recipient, names.index(recipient))
    wall = runtime.clock.wall()
    digest = hashlib.sha256(
        f"test|{wall.isoformat()}|{runtime.clock.monotonic()!r}|{recipient}".encode()
    ).hexdigest()
    event_id = f"test_{digest[:32]}"
    delivery = runtime.delivery
    delivery.accept_cycle(
        rule_states={},
        notifications=[Notification(event_id, TEST_MESSAGE, RecipientTarget(recipient))],
    )
    report = delivery.run_only(event_id)
    record = delivery.record(event_id, recipient)
    status = record.status if record is not None else None
    outcome = TestOutcome(
        recipient=shown,
        live=config.provider_is_live(config.recipients[recipient].provider),
        status=status,
        report=report,
    )
    logger.info(
        "test notification processed",
        extra={
            "event": "service.test_notification",
            "recipient": shown,
            "live": outcome.live,
            "outcome": None if status is None else status.value,
        },
    )
    return outcome

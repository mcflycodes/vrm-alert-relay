"""Command-line entry point for VRM Alert Relay.

Commands: ``run`` (the service), ``check-config``, ``test-notification`` and
``--version``. Exit codes are :class:`~vrm_alert_relay.app.service.ExitCode`
and are documented in docs/operations.md.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
from contextlib import contextmanager
from typing import TYPE_CHECKING, Final

from vrm_alert_relay import __version__
from vrm_alert_relay.app.service import (
    CONFIG_ENV,
    DEFAULT_CONFIG_PATH,
    DEFAULT_STATE_DIR,
    STATE_DIR_ENV,
    ExitCode,
    Service,
    StartupError,
    open_runtime,
    resolve_config_path,
    resolve_state_dir,
    send_test_notification,
)
from vrm_alert_relay.config import check_config
from vrm_alert_relay.logs import configure_logging

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence
    from types import FrameType

    from vrm_alert_relay.config import CheckReport

PROG: Final = "vrm-alert-relay"
LOG_LEVEL_ENV: Final = "VRM_ALERT_RELAY_LOG_LEVEL"
LOG_LEVELS: Final = ("DEBUG", "INFO", "WARNING", "ERROR")
STOP_SIGNALS: Final = (signal.SIGTERM, signal.SIGINT)

logger = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Unofficial alert relay for Victron VRM measurements. "
            "Not affiliated with or endorsed by Victron Energy."
        ),
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")

    config = argparse.ArgumentParser(add_help=False)
    config.add_argument(
        "--config",
        metavar="PATH",
        help=f"configuration file (default: ${CONFIG_ENV}, else {DEFAULT_CONFIG_PATH})",
    )
    runtime = argparse.ArgumentParser(add_help=False)
    runtime.add_argument(
        "--state-dir",
        metavar="DIR",
        help=f"state directory on a local filesystem (default: ${STATE_DIR_ENV}, "
        f"else {DEFAULT_STATE_DIR})",
    )
    runtime.add_argument(
        "--log-level",
        type=str.upper,
        choices=LOG_LEVELS,
        help=f"log level (default: ${LOG_LEVEL_ENV}, else INFO)",
    )

    commands = parser.add_subparsers(dest="command", metavar="COMMAND")
    run = commands.add_parser(
        "run", parents=[config, runtime], help="run the relay (dry-run unless sending is enabled)"
    )
    run.add_argument("--once", action="store_true", help="run one poll cycle, then exit")
    check = commands.add_parser(
        "check-config", parents=[config], help="validate the configuration without sending"
    )
    check.add_argument(
        "--structure-only",
        action="store_true",
        help="do not read secret files (the result is never 'ready')",
    )
    test = commands.add_parser(
        "test-notification",
        parents=[config, runtime],
        help="send one test message to one configured recipient",
    )
    test.add_argument("--recipient", required=True, metavar="NAME", help="recipient name")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_usage(sys.stderr)
        sys.stderr.write(f"{PROG}: error: a command is required (run, check-config, ...)\n")
        return int(ExitCode.USAGE)
    if args.command == "check-config":
        return int(_check_config(args))
    level = args.log_level or os.environ.get(LOG_LEVEL_ENV, "INFO").upper()
    if level not in LOG_LEVELS:
        parser.error(f"${LOG_LEVEL_ENV} must be one of {', '.join(LOG_LEVELS)}")
    if args.command == "run":
        configure_logging(level)
        return int(_run(args))
    # test-notification keeps stdout for its result line.
    configure_logging(level, stream=sys.stderr)
    return int(_test_notification(args))


def _startup_failed(error: StartupError) -> ExitCode:
    logger.error(
        "the relay cannot start",
        extra={"event": "service.startup_failed", "problems": list(error.problems)},
    )
    lines = "".join(f"  - {problem}\n" for problem in error.problems)
    sys.stderr.write(f"{PROG}: cannot start:\n{lines}")
    return error.code


@contextmanager
def _stop_on_signals(stop: threading.Event) -> Iterator[list[int]]:
    """Set ``stop`` on SIGTERM or SIGINT; yields the signals received."""
    received: list[int] = []

    def handle(signum: int, _frame: FrameType | None) -> None:
        received.append(signum)
        stop.set()

    previous = {sig: signal.signal(sig, handle) for sig in STOP_SIGNALS}
    try:
        yield received
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def _run(args: argparse.Namespace) -> ExitCode:
    try:
        runtime = open_runtime(resolve_config_path(args.config), resolve_state_dir(args.state_dir))
    except StartupError as exc:
        return _startup_failed(exc)
    service = Service(runtime)
    stop = threading.Event()
    with _stop_on_signals(stop) as received:
        try:
            service.start_health()
            service.run(stop, max_cycles=1 if args.once else None)
        finally:
            service.close()
    if received:
        logger.info(
            "stopped by signal",
            extra={"event": "service.signal", "signal": signal.Signals(received[0]).name},
        )
    return ExitCode.OK


def _test_notification(args: argparse.Namespace) -> ExitCode:
    try:
        runtime = open_runtime(resolve_config_path(args.config), resolve_state_dir(args.state_dir))
    except StartupError as exc:
        return _startup_failed(exc)
    try:
        outcome = send_test_notification(runtime, args.recipient)
    except StartupError as exc:
        return _startup_failed(exc)
    finally:
        runtime.close()
    sys.stdout.write(f"test notification: {outcome.describe()}\n")
    return ExitCode.OK if outcome.delivered else ExitCode.NOT_DELIVERED


def _check_config(args: argparse.Namespace) -> ExitCode:
    report = check_config(resolve_config_path(args.config), structure_only=args.structure_only)
    sys.stdout.write(format_report(report))
    return ExitCode.OK if report.ok else ExitCode.CONFIG


def _names(values: Sequence[str]) -> str:
    return ", ".join(values) if values else "none"


def format_report(report: CheckReport) -> str:
    """The ``check-config`` output. Recipient names are already display-masked."""
    if report.ready:
        result = "ready: the configuration and its secret files are valid"
    elif report.ok:
        result = "valid structure: secret files were not read"
    else:
        result = "problems found"
    lines = [f"result: {result}"]
    for heading, items in (
        ("problems", report.problems),
        ("warnings", report.warnings),
        ("notes", report.notes),
    ):
        if items:
            lines.append(f"{heading}:")
            lines.extend(f"  - {item}" for item in items)
    if report.installations:
        system = _names(report.system_recipients)
        if report.system_recipients_defaulted:
            system += " (default: every recipient used by a rule)"
        elif not report.system_recipients:
            system += " (system notifications are only logged)"
        lines.extend(
            [
                f"installations: {report.installations}",
                f"rules: {report.rules}",
                f"recipients: {report.recipients}",
                f"live providers: {_names(report.live_providers)}",
                f"dry-run providers: {_names(report.dry_run_providers)}",
                f"live recipients: {_names(report.live_recipients)}",
                f"dry-run recipients: {_names(report.dry_run_recipients)}",
                f"system recipients: {system}",
            ]
        )
    return "\n".join(lines) + "\n"

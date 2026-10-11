"""Command-line entry point for VRM Alert Relay."""

import argparse
import json
import sys
from collections.abc import Sequence

from vrm_alert_relay import __version__

PROG = "vrm-alert-relay"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Unofficial alert relay for Victron VRM measurements (placeholder build).",
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    build_parser().parse_args(argv)
    record = {
        "level": "info",
        "event": "placeholder",
        "dry_run": True,
        "version": __version__,
        "message": "Placeholder build: monitoring and notifications are not implemented. "
        "Running in dry-run mode; nothing will be sent.",
    }
    sys.stderr.write(json.dumps(record) + "\n")
    return 0

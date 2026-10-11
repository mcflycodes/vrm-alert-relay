"""The ``check-config`` report."""

from __future__ import annotations

import os
from dataclasses import dataclass

from .errors import ConfigError
from .loader import _collect_secrets, config_warnings, load_config
from .models import DeliveryMode, ProviderName

__all__ = ["CheckReport", "check_config"]


@dataclass(frozen=True, slots=True)
class CheckReport:
    """Outcome of validating a configuration file and its secret files."""

    ok: bool
    problems: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    installations: int = 0
    rules: int = 0
    recipients: int = 0
    live_providers: tuple[ProviderName, ...] = ()
    dry_run_providers: tuple[ProviderName, ...] = ()
    live_recipients: tuple[str, ...] = ()
    dry_run_recipients: tuple[str, ...] = ()


def check_config(path: str | os.PathLike[str]) -> CheckReport:
    """Validate the configuration at ``path`` without contacting any service.

    Reads only the configuration file and the secret files it references. A
    configuration in dry-run mode passes even when provider secret files are
    absent; a live provider's secret files must exist and be usable.
    """
    try:
        config = load_config(path)
    except ConfigError as exc:
        return CheckReport(ok=False, problems=exc.problems)

    _, problems, secret_warnings = _collect_secrets(config, preflight=True)
    modes = config.delivery_modes()
    return CheckReport(
        ok=not problems,
        problems=tuple(problems),
        warnings=(*config_warnings(config), *secret_warnings),
        installations=len(config.vrm.installations),
        rules=len(config.rules),
        recipients=len(config.recipients),
        live_providers=config.live_providers(),
        dry_run_providers=config.dry_run_providers(),
        live_recipients=tuple(n for n, m in modes.items() if m is DeliveryMode.LIVE),
        dry_run_recipients=tuple(
            n for n, m in modes.items() if m is DeliveryMode.DRY_RUN
        ),
    )

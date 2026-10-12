"""The ``check-config`` report."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from vrm_alert_relay.net import InvalidCaFileError, load_ca_file

from ._paths import display_name
from .errors import ConfigError
from .loader import _collect_secrets, config_warnings, load_config
from .models import DeliveryMode, ProviderName

if TYPE_CHECKING:
    import os

    from .models import RelayConfig

__all__ = [
    "STRUCTURE_ONLY_NOTE",
    "SYSTEM_RECIPIENTS_DEFAULT_NOTE",
    "CheckReport",
    "check_config",
]

SYSTEM_RECIPIENTS_DEFAULT_NOTE = (
    "system_recipients: not set; system notifications go to every recipient used by a rule"
)
STRUCTURE_ONLY_NOTE = (
    "structure-only check: secret files were not read, so this configuration "
    "has not been verified as ready to deploy"
)


@dataclass(frozen=True, slots=True)
class CheckReport:
    """Outcome of validating a configuration file and, unless skipped, its secrets.

    ``ok`` means no problems were found by the checks that ran. ``ready`` means
    the configuration and every required secret file were verified; it is always
    false for a structure-only check. Recipient names that may not be displayed
    (see ``is_displayable_key``) are listed as ``[#<position>]``.
    """

    ok: bool
    ready: bool = False
    secrets_checked: bool = False
    problems: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    installations: int = 0
    rules: int = 0
    recipients: int = 0
    live_providers: tuple[ProviderName, ...] = ()
    dry_run_providers: tuple[ProviderName, ...] = ()
    live_recipients: tuple[str, ...] = ()
    dry_run_recipients: tuple[str, ...] = ()
    system_recipients: tuple[str, ...] = ()
    system_recipients_defaulted: bool = False


def check_config(path: str | os.PathLike[str], *, structure_only: bool = False) -> CheckReport:
    """Validate the configuration at ``path`` without contacting any service.

    Reads only the configuration file and the secret files it references. The
    VRM token file must exist and be usable, as must the secret files of every
    live provider; problems with the secrets of providers that are enabled but
    not live (``sending.enabled`` is false) are warnings.

    With ``structure_only`` no secret file is read, and the report is never
    ``ready``.
    """
    notes = (STRUCTURE_ONLY_NOTE,) if structure_only else ()
    try:
        config = load_config(path)
    except ConfigError as exc:
        return CheckReport(ok=False, problems=exc.problems, notes=notes)

    problems: list[str] = []
    secret_warnings: list[str] = []
    if not structure_only:
        _, problems, secret_warnings = _collect_secrets(config, preflight=True)
        _check_ca_files(config, problems, secret_warnings)
    shown = {name: display_name(name, position) for position, name in enumerate(config.recipients)}
    modes = config.delivery_modes()
    defaulted = config.system_recipients is None
    if defaulted:
        notes = (*notes, SYSTEM_RECIPIENTS_DEFAULT_NOTE)
    ok = not problems
    return CheckReport(
        ok=ok,
        ready=ok and not structure_only,
        secrets_checked=not structure_only,
        problems=tuple(problems),
        warnings=(*config_warnings(config), *secret_warnings),
        notes=notes,
        installations=len(config.vrm.installations),
        rules=len(config.rules),
        recipients=len(config.recipients),
        live_providers=config.live_providers(),
        dry_run_providers=config.dry_run_providers(),
        live_recipients=tuple(shown[n] for n, m in modes.items() if m is DeliveryMode.LIVE),
        dry_run_recipients=tuple(shown[n] for n, m in modes.items() if m is DeliveryMode.DRY_RUN),
        system_recipients=tuple(shown[n] for n in config.system_recipient_names()),
        system_recipients_defaulted=defaulted,
    )


def _check_ca_files(config: RelayConfig, problems: list[str], warnings: list[str]) -> None:
    """Load each enabled provider's ``ca_file`` the way the provider will."""
    sections: tuple[tuple[ProviderName, str | None], ...] = (
        ("homeassistant", config.providers.homeassistant.ca_file),
        ("webhook", config.providers.webhook.ca_file),
    )
    for provider, ca_file in sections:
        if ca_file is None or not config.providers.is_enabled(provider):
            continue
        try:
            load_ca_file(ca_file)
        except InvalidCaFileError as exc:
            message = f"providers.{provider}.ca_file: {exc}"
            if config.provider_is_live(provider):
                problems.append(message)
            else:
                warnings.append(f"{message} (required before sending is enabled)")

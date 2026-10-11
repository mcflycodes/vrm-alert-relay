"""Loading the configuration file and resolving its secret files."""

from __future__ import annotations

import errno
import ipaddress
import os
import re
import stat

from pydantic import BaseModel, ConfigDict, ValidationError

from .errors import ConfigError, format_path
from .models import PROVIDER_NAMES, ProviderName, RelayConfig
from .secret import Secret, SecretFileError, read_secret_file
from .yaml_loader import MAX_CONFIG_BYTES, parse_yaml

__all__ = [
    "RelaySecrets",
    "config_warnings",
    "load_config",
    "load_secrets",
    "parse_config",
]

_INLINE_SECRET_KEY = re.compile(
    r"(?:.*_)?(?:password|passwd|token|secret|apikey|api_key|credentials?)"
    r"|username|auth_header_value"
)
_INLINE_VALUE_MESSAGE = (
    "inline secret values are not allowed; put the value in a file "
    "and reference it with the matching '*_file' setting"
)
_VALUE_ERROR_PREFIX = "Value error, "


class RelaySecrets(BaseModel):
    """Secret values resolved from the files the configuration references.

    A field is ``None`` when its provider is not live (or, for ``vrm_token``, when
    it was not required). Serialization always masks the values.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    vrm_token: Secret | None = None
    voipms_username: Secret | None = None
    voipms_password: Secret | None = None
    homeassistant_token: Secret | None = None
    webhook_auth_header_value: Secret | None = None


def _strip_union_tag(loc: tuple[str | int, ...]) -> tuple[str | int, ...]:
    # Pydantic inserts the discriminator value into recipient error locations.
    if len(loc) >= 3 and loc[0] == "recipients" and loc[2] in PROVIDER_NAMES:
        return (*loc[:2], *loc[3:])
    return loc


def _validation_problems(exc: ValidationError) -> list[str]:
    problems: list[str] = []
    for error in exc.errors(
        include_url=False, include_input=False, include_context=False
    ):
        loc = _strip_union_tag(tuple(error["loc"]))
        key = loc[-1] if loc else None
        if (
            error["type"] == "extra_forbidden"
            and isinstance(key, str)
            and _INLINE_SECRET_KEY.fullmatch(key)
        ):
            message = _INLINE_VALUE_MESSAGE
        else:
            message = str(error["msg"]).removeprefix(_VALUE_ERROR_PREFIX)
        problems.append(f"{format_path(loc)}: {message}")
    return problems


def parse_config(data: bytes | str) -> RelayConfig:
    """Parse and validate configuration text. Raises :class:`ConfigError`."""
    raw = parse_yaml(data)
    if not isinstance(raw, dict):
        raise ConfigError(["configuration must be a YAML mapping at the top level"])
    try:
        return RelayConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(_validation_problems(exc)) from None


def _read_config_bytes(path: str | os.PathLike[str]) -> bytes:
    shown = os.fspath(path)
    try:
        with open(path, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ConfigError(
                    [f"{shown}: configuration path is not a regular file"]
                )
            data = handle.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            reason = "configuration file does not exist"
        else:
            reason = (
                f"configuration file cannot be read: {exc.strerror or 'unknown error'}"
            )
        raise ConfigError([f"{shown}: {reason}"]) from None
    if len(data) > MAX_CONFIG_BYTES:
        raise ConfigError(
            [f"{shown}: configuration is larger than {MAX_CONFIG_BYTES} bytes"]
        )
    return data


def load_config(path: str | os.PathLike[str]) -> RelayConfig:
    """Read and validate the configuration file. Does not read secret files.

    Raises :class:`ConfigError` listing every problem found.
    """
    return parse_config(_read_config_bytes(path))


def config_warnings(config: RelayConfig) -> list[str]:
    """Non-fatal findings an operator should see, such as unused recipients."""
    warnings: list[str] = []
    if config.sending.enabled and not config.live_providers():
        warnings.append(
            "sending.enabled: sending is enabled but no provider is enabled; "
            "all messages will be logged only"
        )
    used = {name for rule in config.rules for name in rule.recipients}
    for name, recipient in config.recipients.items():
        path = format_path(("recipients", name))
        if recipient.provider != "log" and not config.providers.is_enabled(
            recipient.provider
        ):
            warnings.append(
                f"{path}: provider '{recipient.provider}' is not enabled; "
                "messages to this recipient will be logged only"
            )
        if name not in used:
            warnings.append(f"{path}: not used by any rule")
    if not config.rules:
        warnings.append("rules: no rules are configured; nothing will be monitored")
    if (
        config.health.enabled
        and not ipaddress.ip_address(config.health.bind).is_loopback
    ):
        warnings.append(
            "health.bind: the health endpoint listens on a non-loopback address"
        )
    return warnings


_SecretSpec = tuple[str, tuple[str, ...], str | None]


def _provider_secret_specs(
    config: RelayConfig,
) -> list[tuple[ProviderName, _SecretSpec]]:
    voipms = config.providers.voipms
    ha = config.providers.homeassistant
    webhook = config.providers.webhook
    return [
        (
            "voipms",
            (
                "voipms_username",
                ("providers", "voipms", "username_file"),
                voipms.username_file,
            ),
        ),
        (
            "voipms",
            (
                "voipms_password",
                ("providers", "voipms", "password_file"),
                voipms.password_file,
            ),
        ),
        (
            "homeassistant",
            (
                "homeassistant_token",
                ("providers", "homeassistant", "token_file"),
                ha.token_file,
            ),
        ),
        (
            "webhook",
            (
                "webhook_auth_header_value",
                ("providers", "webhook", "auth_header_value_file"),
                webhook.auth_header_value_file,
            ),
        ),
    ]


def _read_into(
    values: dict[str, Secret],
    warnings: list[str],
    spec: _SecretSpec,
) -> SecretFileError | None:
    field, loc, path = spec
    if path is None:
        return None
    try:
        result = read_secret_file(path)
    except SecretFileError as exc:
        return exc
    values[field] = result.secret
    if result.group_or_world_readable:
        warnings.append(
            f"{format_path(loc)}: secret file is readable by group or others; "
            "restrict it to mode 0600 or 0400"
        )
    return None


def _collect_secrets(
    config: RelayConfig, *, preflight: bool
) -> tuple[RelaySecrets, list[str], list[str]]:
    """Read secret files.

    At runtime (``preflight=False``) the VRM token and every live provider's
    secrets are required, and providers that are not live are skipped. In a
    preflight check a missing VRM token and problems with the secrets of enabled
    but not yet live providers are warnings, so a dry-run configuration passes.
    """
    values: dict[str, Secret] = {}
    problems: list[str] = []
    warnings: list[str] = []

    vrm_spec: _SecretSpec = ("vrm_token", ("vrm", "token_file"), config.vrm.token_file)
    error = _read_into(values, warnings, vrm_spec)
    if error is not None:
        message = f"vrm.token_file: {error.reason}"
        if error.missing and preflight:
            warnings.append(f"{message}; the relay cannot poll VRM until it exists")
        else:
            problems.append(message)

    for provider, spec in _provider_secret_specs(config):
        live = config.provider_is_live(provider)
        if not config.providers.is_enabled(provider) or not (live or preflight):
            continue
        error = _read_into(values, warnings, spec)
        if error is None:
            continue
        message = f"{format_path(spec[1])}: {error.reason}"
        if live:
            problems.append(message)
        else:
            warnings.append(f"{message} (required before sending is enabled)")
    return RelaySecrets(**values), problems, warnings


def load_secrets(config: RelayConfig) -> tuple[RelaySecrets, list[str]]:
    """Read the secrets the relay needs to run: the VRM token and live providers'.

    Secret files of providers that are not live are not read. Returns the secrets
    and any warnings (such as permissive file modes). Raises :class:`ConfigError`
    if a required secret is missing or unusable.
    """
    secrets, problems, warnings = _collect_secrets(config, preflight=False)
    if problems:
        raise ConfigError(problems)
    return secrets, warnings

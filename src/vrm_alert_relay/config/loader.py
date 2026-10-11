"""Loading the configuration file and resolving its secret files."""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError, model_validator
from pydantic_core import ErrorDetails

from ._files import FileProblem, FileReadError, read_regular_file
from .errors import ConfigError, format_path
from .fields import FieldProblem
from .models import (
    PROVIDER_NAMES,
    SUPPORTED_VERSIONS,
    SUPPORTED_VERSIONS_TEXT,
    UNSUPPORTED_VERSION_MESSAGE,
    ProviderName,
    RelayConfig,
)
from .secret import Secret, SecretFileError, SecretTypeError, read_secret_file
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
_PROVIDER_CHOICES = ", ".join(f"'{name}'" for name in PROVIDER_NAMES)

# Fixed operator-facing text per pydantic error type. Upstream message text and
# input values are never shown, because they can contain secrets or phone numbers.
_FIXED_MESSAGES = {
    "missing": "is required",
    "extra_forbidden": "is not a recognized setting",
    "string_type": "must be a string",
    "bool_type": "must be true or false",
    "int_type": "must be a whole number",
    "float_type": "must be a number",
    "finite_number": "must be a finite number",
    "dict_type": "must be a mapping",
    "model_type": "must be a mapping",
    "model_attributes_type": "must be a mapping",
    "tuple_type": "must be a list",
    "union_tag_invalid": f"must be one of {_PROVIDER_CHOICES}",
    "union_tag_not_found": f"is required (one of {_PROVIDER_CHOICES})",
}
_BOUND_MESSAGES = {
    "greater_than_equal": ("ge", "must be at least {}"),
    "less_than_equal": ("le", "must be at most {}"),
    "greater_than": ("gt", "must be greater than {}"),
    "less_than": ("lt", "must be less than {}"),
    "too_short": ("min_length", "must contain at least {} item(s)"),
    "too_long": ("max_length", "must contain at most {} item(s)"),
}
_GENERIC_MESSAGE = "is invalid"


class RelaySecrets(BaseModel):
    """Secret values resolved from the files the configuration references.

    A field is ``None`` when its provider is not live (or, for ``vrm_token``, when
    it was not required). Serialization always masks the values. Constructing it
    with anything other than :class:`Secret` values raises
    :class:`SecretTypeError` before pydantic validation, so no plaintext can be
    captured in a ``ValidationError``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    vrm_token: Secret | None = None
    voipms_username: Secret | None = None
    voipms_password: Secret | None = None
    homeassistant_token: Secret | None = None
    webhook_auth_header_value: Secret | None = None

    @model_validator(mode="before")
    @classmethod
    def _only_secrets(cls, data: Any) -> Any:
        if not isinstance(data, dict) or not all(
            value is None or isinstance(value, Secret) for value in data.values()
        ):
            raise SecretTypeError()
        return data


def _error_location(error: ErrorDetails) -> tuple[str | int, ...]:
    loc = tuple(error["loc"])
    # Pydantic inserts the discriminator value into recipient error locations.
    if len(loc) >= 3 and loc[0] == "recipients" and loc[2] in PROVIDER_NAMES:
        loc = (*loc[:2], *loc[3:])
    if error["type"] in ("union_tag_invalid", "union_tag_not_found"):
        loc = (*loc, "provider")
    return loc


def _error_message(error: ErrorDetails, loc: tuple[str | int, ...]) -> str:
    kind = error["type"]
    ctx = error.get("ctx") or {}
    if kind == "value_error":
        cause = ctx.get("error")
        return str(cause) if isinstance(cause, FieldProblem) else _GENERIC_MESSAGE
    if kind == "extra_forbidden":
        key = loc[-1] if loc else None
        if isinstance(key, str) and _INLINE_SECRET_KEY.fullmatch(key):
            return _INLINE_VALUE_MESSAGE
    if kind == "missing" and loc == ("version",):
        return f"is required; {SUPPORTED_VERSIONS_TEXT}"
    if kind == "literal_error":
        expected = ctx.get("expected")
        return (
            f"must be one of {expected}"
            if isinstance(expected, str)
            else _GENERIC_MESSAGE
        )
    if kind in _BOUND_MESSAGES:
        name, template = _BOUND_MESSAGES[kind]
        bound = ctx.get(name)
        if isinstance(bound, int | float) and not isinstance(bound, bool):
            return template.format(bound)
        return _GENERIC_MESSAGE
    return _FIXED_MESSAGES.get(kind, _GENERIC_MESSAGE)


def _validation_problems(exc: ValidationError) -> list[str]:
    problems: list[str] = []
    for error in exc.errors(
        include_url=False, include_input=False, include_context=True
    ):
        loc = _error_location(error)
        problems.append(f"{format_path(loc)}: {_error_message(error, loc)}")
    return problems


def parse_config(data: bytes | str) -> RelayConfig:
    """Parse and validate configuration text. Raises :class:`ConfigError`."""
    raw = parse_yaml(data)
    if not isinstance(raw, dict):
        raise ConfigError(["configuration must be a YAML mapping at the top level"])
    version = raw.get("version")
    if (
        isinstance(version, int)
        and not isinstance(version, bool)
        and version not in SUPPORTED_VERSIONS
    ):
        # Other problems are likely noise when the file targets another version.
        raise ConfigError([f"version: {UNSUPPORTED_VERSION_MESSAGE}"])
    problems: list[str] = []
    try:
        return RelayConfig.model_validate(raw)
    except ValidationError as exc:
        problems = _validation_problems(exc)
    # Raised outside the except block so the ValidationError, which holds raw
    # input values, is not chained as __context__.
    raise ConfigError(problems)


_CONFIG_FILE_PROBLEMS = {
    FileProblem.MISSING: "configuration file does not exist",
    FileProblem.PERMISSION_DENIED: "configuration file is not readable (permission denied)",
    FileProblem.NOT_REGULAR: "configuration path is not a regular file",
    FileProblem.TOO_LARGE: f"configuration is larger than {MAX_CONFIG_BYTES} bytes",
}


def _read_config_bytes(path: str | os.PathLike[str]) -> bytes:
    failure: FileReadError | None = None
    try:
        return read_regular_file(path, MAX_CONFIG_BYTES).data
    except FileReadError as exc:
        failure = exc
    reason = _CONFIG_FILE_PROBLEMS.get(
        failure.problem, f"configuration file cannot be read ({failure.code})"
    )
    raise ConfigError([f"{os.fspath(path)}: {reason}"])


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

    The VRM token is always required, and so are the secrets of every live
    provider. At runtime (``preflight=False``) providers that are not live are
    skipped. In a preflight check, enabled but not yet live providers' secrets
    are read too and their problems reported as warnings, so a dry-run
    configuration passes.
    """
    values: dict[str, Secret] = {}
    problems: list[str] = []
    warnings: list[str] = []

    vrm_spec: _SecretSpec = ("vrm_token", ("vrm", "token_file"), config.vrm.token_file)
    error = _read_into(values, warnings, vrm_spec)
    if error is not None:
        problems.append(f"vrm.token_file: {error.reason}")

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

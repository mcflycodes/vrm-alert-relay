"""Typed, immutable configuration models."""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    SerializerFunctionWrapHandler,
    ValidationInfo,
    field_serializer,
    field_validator,
    model_validator,
)

from .errors import ConfigError, format_path
from .fields import (
    BindAddress,
    CaFilePath,
    FieldValueError,
    HaServiceName,
    HeaderName,
    HttpsUrl,
    HttpUrl,
    MeasurementCode,
    MessageTemplate,
    Name,
    PhoneNumber,
    SecretPath,
    ServiceType,
)

__all__ = [
    "DEFAULT_VOIPMS_BASE_URL",
    "DEFAULT_VRM_BASE_URL",
    "PROVIDER_NAMES",
    "SUPPORTED_VERSIONS",
    "SUPPORTED_VERSIONS_TEXT",
    "UNSUPPORTED_VERSION_MESSAGE",
    "DeliveryMode",
    "HealthConfig",
    "HomeAssistantProvider",
    "HomeAssistantRecipient",
    "Installation",
    "Level",
    "LogProvider",
    "LogRecipient",
    "Measurement",
    "ProviderName",
    "ProvidersConfig",
    "RateLimitsConfig",
    "Recipient",
    "RelayConfig",
    "Rule",
    "SendingConfig",
    "VoipmsProvider",
    "VoipmsRecipient",
    "VrmConfig",
    "WebhookProvider",
    "WebhookRecipient",
]

DEFAULT_VRM_BASE_URL = "https://vrmapi.victronenergy.com/v2"
DEFAULT_VOIPMS_BASE_URL = "https://voip.ms/api/v1/rest.php"

MAX_INSTALLATIONS = 50
MAX_RULES = 200
MAX_LEVELS = 20
MAX_RECIPIENTS = 50

SUPPORTED_VERSIONS: tuple[int, ...] = (1,)
SUPPORTED_VERSIONS_TEXT = "this release supports configuration version " + ", ".join(
    str(v) for v in SUPPORTED_VERSIONS
)
UNSUPPORTED_VERSION_MESSAGE = f"unsupported configuration version; {SUPPORTED_VERSIONS_TEXT}"

type ProviderName = Literal["voipms", "homeassistant", "webhook", "log"]
PROVIDER_NAMES: tuple[ProviderName, ...] = ("voipms", "homeassistant", "webhook", "log")


def _check_version(value: int) -> int:
    if value not in SUPPORTED_VERSIONS:
        raise FieldValueError(UNSUPPORTED_VERSION_MESSAGE)
    return value


class DeliveryMode(StrEnum):
    """Whether messages to a recipient are really sent or only logged."""

    LIVE = "live"
    DRY_RUN = "dry_run"


def _as_tuple(value: object) -> object:
    return tuple(value) if isinstance(value, list) else value


def _freeze_mapping(value: Mapping[str, Recipient]) -> Mapping[str, Recipient]:
    return MappingProxyType(dict(value))


def _empty_recipients() -> Mapping[str, Recipient]:
    return MappingProxyType({})


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, hide_input_in_errors=True)


class SendingConfig(_Model):
    enabled: bool = False


class Installation(_Model):
    id: Name
    site_id: int = Field(ge=1, le=999_999_999)


class VrmConfig(_Model):
    base_url: HttpsUrl = DEFAULT_VRM_BASE_URL
    token_file: SecretPath
    poll_interval: int = Field(default=60, ge=30, le=3600)
    installations: Annotated[
        tuple[Installation, ...],
        BeforeValidator(_as_tuple),
        Field(min_length=1, max_length=MAX_INSTALLATIONS),
    ]


class RateLimitsConfig(_Model):
    global_per_hour: int = Field(default=20, ge=1, le=1000)
    global_per_day: int = Field(default=60, ge=1, le=10_000)
    retries: int = Field(default=3, ge=0, le=10)


class VoipmsRecipient(_Model):
    provider: Literal["voipms"]
    phone: PhoneNumber


class HomeAssistantRecipient(_Model):
    provider: Literal["homeassistant"]
    service: HaServiceName


class WebhookRecipient(_Model):
    provider: Literal["webhook"]


class LogRecipient(_Model):
    provider: Literal["log"]


type Recipient = Annotated[
    VoipmsRecipient | HomeAssistantRecipient | WebhookRecipient | LogRecipient,
    Field(discriminator="provider"),
]


class VoipmsProvider(_Model):
    enabled: bool = False
    base_url: HttpsUrl = DEFAULT_VOIPMS_BASE_URL
    username_file: SecretPath | None = None
    password_file: SecretPath | None = None
    did: PhoneNumber | None = None


_PLAIN_HTTP_MESSAGE = (
    "must be an https:// URL (set allow_insecure_http: true for this provider to permit http://)"
)


def _https_unless_allowed(value: str | None, info: ValidationInfo) -> str | None:
    # allow_insecure_http is declared before the URL, so it is validated first;
    # when it is missing or invalid, plain http stays refused.
    if (
        value is not None
        and value.startswith("http:")
        and info.data.get("allow_insecure_http") is not True
    ):
        raise FieldValueError(_PLAIN_HTTP_MESSAGE)
    return value


class HomeAssistantProvider(_Model):
    enabled: bool = False
    allow_insecure_http: bool = False
    """Permit a plain http:// ``base_url`` for this provider only."""
    base_url: HttpUrl | None = None
    """https:// unless ``allow_insecure_http`` is true."""
    token_file: SecretPath | None = None
    ca_file: CaFilePath | None = None
    """PEM certificates to verify this provider's TLS certificate against,
    instead of the bundled trust store. Verification is never disabled."""

    _check_base_url = field_validator("base_url")(_https_unless_allowed)


class WebhookProvider(_Model):
    enabled: bool = False
    allow_insecure_http: bool = False
    """Permit a plain http:// ``url`` for this provider only."""
    url: HttpUrl | None = None
    """https:// unless ``allow_insecure_http`` is true."""
    auth_header_name: HeaderName | None = None
    auth_header_value_file: SecretPath | None = None
    ca_file: CaFilePath | None = None
    """PEM certificates to verify this provider's TLS certificate against,
    instead of the bundled trust store. Verification is never disabled."""

    _check_url = field_validator("url")(_https_unless_allowed)


class LogProvider(_Model):
    pass


class ProvidersConfig(_Model):
    voipms: VoipmsProvider = Field(default_factory=VoipmsProvider)
    homeassistant: HomeAssistantProvider = Field(default_factory=HomeAssistantProvider)
    webhook: WebhookProvider = Field(default_factory=WebhookProvider)
    log: LogProvider = Field(default_factory=LogProvider)

    def is_enabled(self, provider: ProviderName) -> bool:
        """Whether the provider section enables it. ``log`` is always available."""
        if provider == "log":
            return True
        section: VoipmsProvider | HomeAssistantProvider | WebhookProvider = getattr(self, provider)
        return section.enabled


class Measurement(_Model):
    code: MeasurementCode
    instance: int = Field(ge=0, le=1_000_000)
    service_type: ServiceType | None = None


class Level(_Model):
    name: Name
    threshold: float = Field(allow_inf_nan=False)
    message: MessageTemplate | None = None


class Rule(_Model):
    id: Name
    installation: Name
    measurement: Measurement
    direction: Literal["rising", "falling"]
    levels: Annotated[
        tuple[Level, ...],
        BeforeValidator(_as_tuple),
        Field(min_length=1, max_length=MAX_LEVELS),
    ]
    hysteresis: float = Field(default=0.0, ge=0, allow_inf_nan=False)
    clear_after_samples: int = Field(default=1, ge=1, le=100)
    recovery_notify: bool = True
    cooldown_minutes: int = Field(default=15, ge=1, le=1440)
    reminder_interval_minutes: int = Field(default=60, ge=1, le=10_080)
    reminder_max: int = Field(default=3, ge=0, le=20)
    stale_after_minutes: int = Field(default=35, ge=1, le=10_080)
    recipients: Annotated[
        tuple[Name, ...],
        BeforeValidator(_as_tuple),
        Field(min_length=1, max_length=MAX_RECIPIENTS),
    ]


class HealthConfig(_Model):
    enabled: bool = False
    bind: BindAddress = "127.0.0.1"
    port: int = Field(default=8080, ge=1, le=65535)


class RelayConfig(_Model):
    """The complete, validated operator configuration."""

    version: Annotated[int, AfterValidator(_check_version)]
    sending: SendingConfig = Field(default_factory=SendingConfig)
    vrm: VrmConfig
    rate_limits: RateLimitsConfig = Field(default_factory=RateLimitsConfig)
    recipients: Annotated[
        Mapping[Name, Recipient],
        Field(max_length=MAX_RECIPIENTS),
        AfterValidator(_freeze_mapping),
    ] = Field(default_factory=_empty_recipients)
    providers: ProvidersConfig = Field(default_factory=ProvidersConfig)
    rules: Annotated[
        tuple[Rule, ...],
        BeforeValidator(_as_tuple),
        Field(max_length=MAX_RULES),
    ] = ()
    system_recipients: (
        Annotated[
            tuple[Name, ...],
            BeforeValidator(_as_tuple),
            Field(min_length=1, max_length=MAX_RECIPIENTS),
        ]
        | None
    ) = None
    health: HealthConfig = Field(default_factory=HealthConfig)

    @field_serializer("recipients", mode="wrap")
    def _serialize_recipients(
        self, value: Mapping[str, Recipient], handler: SerializerFunctionWrapHandler
    ) -> object:
        return handler(dict(value))

    @model_validator(mode="after")
    def _check_semantics(self) -> Self:
        problems = _semantic_problems(self)
        if problems:
            # ConfigError is not a ValueError, so pydantic lets it propagate.
            raise ConfigError(problems)
        return self

    def provider_is_live(self, provider: ProviderName) -> bool:
        """A provider sends for real only when sending and the provider are enabled."""
        if provider == "log":
            return False
        return self.sending.enabled and self.providers.is_enabled(provider)

    def delivery_mode(self, recipient: str) -> DeliveryMode:
        """Return whether messages to ``recipient`` are sent or only logged.

        Raises ``KeyError`` for a recipient that is not configured.
        """
        provider = self.recipients[recipient].provider
        return DeliveryMode.LIVE if self.provider_is_live(provider) else DeliveryMode.DRY_RUN

    def delivery_modes(self) -> Mapping[str, DeliveryMode]:
        """Delivery mode for every configured recipient."""
        return MappingProxyType({name: self.delivery_mode(name) for name in self.recipients})

    def system_recipient_names(self) -> tuple[str, ...]:
        """Recipients of system notifications such as rate-limit summaries.

        ``system_recipients`` when set; otherwise every recipient that any rule
        names, in order of first appearance.
        """
        if self.system_recipients is not None:
            return self.system_recipients
        return tuple(dict.fromkeys(name for rule in self.rules for name in rule.recipients))

    def live_providers(self) -> tuple[ProviderName, ...]:
        return tuple(p for p in PROVIDER_NAMES if self.provider_is_live(p))

    def dry_run_providers(self) -> tuple[ProviderName, ...]:
        return tuple(p for p in PROVIDER_NAMES if not self.provider_is_live(p))


def _required(problems: list[str], loc: tuple[str, ...], value: object, why: str) -> None:
    if value is None:
        problems.append(f"{format_path(loc)}: is required {why}")


def _provider_problems(providers: ProvidersConfig) -> list[str]:
    problems: list[str] = []
    when = "when the provider is enabled"
    voipms = providers.voipms
    if voipms.enabled:
        base = ("providers", "voipms")
        _required(problems, (*base, "username_file"), voipms.username_file, when)
        _required(problems, (*base, "password_file"), voipms.password_file, when)
        _required(problems, (*base, "did"), voipms.did, when)
    ha = providers.homeassistant
    if ha.enabled:
        base = ("providers", "homeassistant")
        _required(problems, (*base, "base_url"), ha.base_url, when)
        _required(problems, (*base, "token_file"), ha.token_file, when)
    webhook = providers.webhook
    if webhook.enabled:
        _required(problems, ("providers", "webhook", "url"), webhook.url, when)
    if (webhook.auth_header_name is None) != (webhook.auth_header_value_file is None):
        problems.append(
            "providers.webhook: auth_header_name and auth_header_value_file must be set together"
        )
    return problems


def _rule_problems(index: int, rule: Rule, config: RelayConfig) -> list[str]:
    problems: list[str] = []
    base: tuple[str | int, ...] = ("rules", index)
    installations = {inst.id for inst in config.vrm.installations}
    if rule.installation not in installations:
        problems.append(
            f"{format_path((*base, 'installation'))}: unknown installation "
            "(not listed in vrm.installations)"
        )
    problems.extend(_level_problems(base, rule))
    problems.extend(_rule_recipient_problems(base, rule, config))
    if rule.stale_after_minutes * 60 <= config.vrm.poll_interval:
        problems.append(
            f"{format_path((*base, 'stale_after_minutes'))}: must be longer than vrm.poll_interval"
        )
    return problems


def _level_problems(base: tuple[str | int, ...], rule: Rule) -> list[str]:
    problems: list[str] = []
    level_names: dict[str, int] = {}
    for level_index, level in enumerate(rule.levels):
        level_loc = (*base, "levels", level_index)
        if level.name in level_names:
            first = format_path((*base, "levels", level_names[level.name], "name"))
            problems.append(
                f"{format_path((*level_loc, 'name'))}: duplicate level name (same as {first})"
            )
        level_names.setdefault(level.name, level_index)
        if level_index == 0:
            continue
        previous = rule.levels[level_index - 1].threshold
        if rule.direction == "rising" and level.threshold <= previous:
            problems.append(
                f"{format_path((*level_loc, 'threshold'))}: must be greater than the "
                "previous level's threshold for a rising rule"
            )
        elif rule.direction == "falling" and level.threshold >= previous:
            problems.append(
                f"{format_path((*level_loc, 'threshold'))}: must be less than the "
                "previous level's threshold for a falling rule"
            )
    return problems


def _rule_recipient_problems(
    base: tuple[str | int, ...], rule: Rule, config: RelayConfig
) -> list[str]:
    return _recipient_list_problems((*base, "recipients"), rule.recipients, config)


def _recipient_list_problems(
    base: tuple[str | int, ...], names: tuple[str, ...], config: RelayConfig
) -> list[str]:
    problems: list[str] = []
    seen_recipients: dict[str, int] = {}
    for recipient_index, name in enumerate(names):
        loc = format_path((*base, recipient_index))
        if name in seen_recipients:
            first = format_path((*base, seen_recipients[name]))
            problems.append(f"{loc}: duplicate recipient (same as {first})")
        elif name not in config.recipients:
            problems.append(f"{loc}: unknown recipient (not defined under recipients)")
        seen_recipients.setdefault(name, recipient_index)
    return problems


def _semantic_problems(config: RelayConfig) -> list[str]:
    problems: list[str] = []
    seen_ids: dict[str, int] = {}
    seen_sites: dict[int, int] = {}
    for index, inst in enumerate(config.vrm.installations):
        loc = ("vrm", "installations", index)
        if inst.id in seen_ids:
            first = format_path(("vrm", "installations", seen_ids[inst.id], "id"))
            problems.append(
                f"{format_path((*loc, 'id'))}: duplicate installation id (same as {first})"
            )
        if inst.site_id in seen_sites:
            first = format_path(("vrm", "installations", seen_sites[inst.site_id], "site_id"))
            problems.append(
                f"{format_path((*loc, 'site_id'))}: duplicate site_id (same as {first})"
            )
        seen_ids.setdefault(inst.id, index)
        seen_sites.setdefault(inst.site_id, index)

    limits = config.rate_limits
    if limits.global_per_hour > limits.global_per_day:
        problems.append("rate_limits.global_per_hour: must not exceed rate_limits.global_per_day")

    problems.extend(_provider_problems(config.providers))

    rule_ids: dict[str, int] = {}
    for index, rule in enumerate(config.rules):
        if rule.id in rule_ids:
            first = format_path(("rules", rule_ids[rule.id], "id"))
            problems.append(
                f"{format_path(('rules', index, 'id'))}: duplicate rule id (same as {first})"
            )
        rule_ids.setdefault(rule.id, index)
        problems.extend(_rule_problems(index, rule, config))
    if config.system_recipients is not None:
        problems.extend(
            _recipient_list_problems(("system_recipients",), config.system_recipients, config)
        )
    return problems

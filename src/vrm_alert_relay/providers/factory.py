"""Building the configured providers from configuration and secrets (R24).

Only live providers are built: a provider is live when ``sending.enabled``
and the provider's own ``enabled`` are both true. Every other recipient,
including all of them while sending is disabled, is delivered to the dry-run
:class:`DryRunLogProvider`, which the delivery engine uses for every route
whose :class:`~vrm_alert_relay.config.DeliveryMode` is ``DRY_RUN``.

Each live HTTP provider gets its own :class:`SafeHttpClient`. VoIP.ms always
uses strict HTTPS with the bundled trust store. Home Assistant and the webhook
use the provider's ``ca_file`` and ``allow_insecure_http`` settings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Self

from vrm_alert_relay.net import SafeHttpClient
from vrm_alert_relay.providers.homeassistant import HomeAssistantNotifyProvider
from vrm_alert_relay.providers.log import DryRunLogProvider
from vrm_alert_relay.providers.voipms import VoipmsSmsProvider
from vrm_alert_relay.providers.webhook import WebhookPostProvider

if TYPE_CHECKING:
    from collections.abc import Mapping
    from types import TracebackType

    from vrm_alert_relay.config import ProviderName, RelayConfig, RelaySecrets, Secret
    from vrm_alert_relay.delivery.protocol import Provider
    from vrm_alert_relay.logs.redaction import SecretRegistry
    from vrm_alert_relay.net import Timeouts

__all__ = ["ProviderSet", "ProviderSetupError", "build_providers"]


class ProviderSetupError(ValueError):
    """A live provider could not be built. The message never holds a secret."""


@dataclass(frozen=True, slots=True, eq=False)
class ProviderSet:
    """The live providers by name, the dry-run sink, and the clients to close."""

    providers: Mapping[ProviderName, Provider]
    dry_run: DryRunLogProvider
    clients: tuple[SafeHttpClient, ...] = field(default=(), repr=False)

    def close(self) -> None:
        for client in self.clients:
            client.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def _require(secret: Secret | None, setting: str) -> Secret:
    if secret is None:
        raise ProviderSetupError(f"{setting}: the secret was not loaded for a live provider")  # noqa: TRY003  # fixed operator-facing text
    return secret


def _build(  # noqa: PLR0913, PLR0917  # internal helper of build_providers
    name: ProviderName,
    config: RelayConfig,
    secrets: RelaySecrets,
    clients: list[SafeHttpClient],
    registry: SecretRegistry | None,
    timeouts: Timeouts | None,
) -> Provider:
    providers = config.providers
    if name == "voipms":
        voipms = providers.voipms
        if voipms.did is None:
            raise ProviderSetupError("providers.voipms.did: is required for a live provider")  # noqa: TRY003  # fixed operator-facing text
        username = _require(secrets.voipms_username, "providers.voipms.username_file")
        password = _require(secrets.voipms_password, "providers.voipms.password_file")
        client = SafeHttpClient(timeouts=timeouts)
        clients.append(client)
        return VoipmsSmsProvider(
            client,
            username=username,
            password=password,
            did=voipms.did,
            base_url=voipms.base_url,
            registry=registry,
        )
    if name == "homeassistant":
        ha = providers.homeassistant
        if ha.base_url is None:
            raise ProviderSetupError(  # noqa: TRY003  # fixed operator-facing text
                "providers.homeassistant.base_url: is required for a live provider"
            )
        token = _require(secrets.homeassistant_token, "providers.homeassistant.token_file")
        client = SafeHttpClient(
            timeouts=timeouts, ca_file=ha.ca_file, allow_insecure_http=ha.allow_insecure_http
        )
        clients.append(client)
        return HomeAssistantNotifyProvider(
            client, base_url=ha.base_url, token=token, registry=registry
        )
    webhook = providers.webhook
    if webhook.url is None:
        raise ProviderSetupError("providers.webhook.url: is required for a live provider")  # noqa: TRY003  # fixed operator-facing text
    auth: tuple[str, Secret] | None = None
    if webhook.auth_header_name is not None:
        value = _require(
            secrets.webhook_auth_header_value, "providers.webhook.auth_header_value_file"
        )
        auth = (webhook.auth_header_name, value)
    client = SafeHttpClient(
        timeouts=timeouts, ca_file=webhook.ca_file, allow_insecure_http=webhook.allow_insecure_http
    )
    clients.append(client)
    return WebhookPostProvider(client, url=webhook.url, auth_header=auth, registry=registry)


def build_providers(
    config: RelayConfig,
    secrets: RelaySecrets,
    *,
    registry: SecretRegistry | None = None,
    timeouts: Timeouts | None = None,
) -> ProviderSet:
    """Build every live provider, plus the dry-run sink.

    ``secrets`` comes from :func:`~vrm_alert_relay.config.load_secrets`, which
    already requires every live provider's secrets. Raises
    :class:`ProviderSetupError` when one is missing anyway, and
    :class:`~vrm_alert_relay.net.InvalidCaFileError` when a ``ca_file``
    cannot be loaded; clients built before the failure are closed.
    """
    clients: list[SafeHttpClient] = []
    built: dict[ProviderName, Provider] = {}
    try:
        for name in config.live_providers():
            built[name] = _build(name, config, secrets, clients, registry, timeouts)
    except BaseException:
        for client in clients:
            client.close()
        raise
    return ProviderSet(
        providers=MappingProxyType(built),
        dry_run=DryRunLogProvider(),
        clients=tuple(clients),
    )

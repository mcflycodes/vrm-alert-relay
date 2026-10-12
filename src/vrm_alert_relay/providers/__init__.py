"""Notification providers (R19-R21) and the factory that builds them.

Every provider implements :class:`~vrm_alert_relay.delivery.Provider`, and
VoIP.ms also :class:`~vrm_alert_relay.delivery.ReconcilingProvider`. A
provider delivers only to the configured recipient object it is handed, and
nothing it receives in a response can change a destination.
"""

from vrm_alert_relay.providers.factory import ProviderSet, ProviderSetupError, build_providers
from vrm_alert_relay.providers.homeassistant import HomeAssistantNotifyProvider
from vrm_alert_relay.providers.log import DryRunLogProvider, describe_recipient
from vrm_alert_relay.providers.messages import DetailedMessage
from vrm_alert_relay.providers.voipms import MAX_SMS_CHARS, VoipmsSmsProvider, sms_text
from vrm_alert_relay.providers.webhook import PAYLOAD_VERSION, WebhookPostProvider, webhook_payload

__all__ = [
    "MAX_SMS_CHARS",
    "PAYLOAD_VERSION",
    "DetailedMessage",
    "DryRunLogProvider",
    "HomeAssistantNotifyProvider",
    "ProviderSet",
    "ProviderSetupError",
    "VoipmsSmsProvider",
    "WebhookPostProvider",
    "build_providers",
    "describe_recipient",
    "sms_text",
    "webhook_payload",
]

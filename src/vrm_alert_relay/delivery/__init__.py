"""Delivery of notifications to configured recipients through providers.

Providers (one per transport) implement :class:`Provider`, and
:class:`ReconcilingProvider` when they can look up an earlier attempt. The
service loop builds a :class:`DeliveryEngine` from configuration, hands it
each poll cycle's rule states and notifications with
:meth:`DeliveryEngine.accept_cycle`, and calls :meth:`DeliveryEngine.run_due`.
"""

from .engine import DeliveryEngine, DeliveryHealth, DeliveryLimits, RunReport
from .limits import RateLimiter, RetryPolicy
from .protocol import (
    MAX_MESSAGE_LENGTH,
    Message,
    Provider,
    ReconcileQuery,
    ReconcileStatus,
    ReconcilingProvider,
    SendResult,
    SendStatus,
    delivery_id,
    sanitize_text,
)
from .routing import (
    Notification,
    RecipientTarget,
    Route,
    Routing,
    RuleTarget,
    Target,
    UnknownTargetError,
)

__all__ = [
    "MAX_MESSAGE_LENGTH",
    "DeliveryEngine",
    "DeliveryHealth",
    "DeliveryLimits",
    "Message",
    "Notification",
    "Provider",
    "RateLimiter",
    "RecipientTarget",
    "ReconcileQuery",
    "ReconcileStatus",
    "ReconcilingProvider",
    "RetryPolicy",
    "Route",
    "Routing",
    "RuleTarget",
    "RunReport",
    "SendResult",
    "SendStatus",
    "Target",
    "UnknownTargetError",
    "delivery_id",
    "sanitize_text",
]

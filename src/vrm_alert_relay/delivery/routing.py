"""Recipient resolution from operator configuration only.

:class:`Routing` is built once from a validated
:class:`~vrm_alert_relay.config.RelayConfig` and never changes. A
:class:`Notification` can only *name* a configured rule, a configured
recipient, or the configured system recipients; the destination a provider
receives is always the configured :class:`~vrm_alert_relay.config.Recipient`
object, looked up by name. Nothing in an event, label, template, delivery
record, or provider response can add a recipient or change where one points.

:meth:`Routing.opted_out` applies the configuration's opt-outs
(``stale_notify: false``, ``system_recipients: []``) to a delivery by its
stored origin, so they hold for deliveries queued before a restart too.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from vrm_alert_relay.config import display_name
from vrm_alert_relay.engine import EventKind
from vrm_alert_relay.state import DeliveryOrigin

if TYPE_CHECKING:
    from collections.abc import Mapping

    from vrm_alert_relay.config import DeliveryMode, Recipient, RelayConfig
    from vrm_alert_relay.engine import Event

__all__ = [
    "Notification",
    "RecipientTarget",
    "Route",
    "Routing",
    "RuleTarget",
    "SystemTarget",
    "Target",
    "UnknownTargetError",
]


class UnknownTargetError(LookupError):
    """A notification named a rule or recipient that is not configured."""


@dataclass(frozen=True, slots=True)
class RuleTarget:
    """Deliver to the recipients configured on a rule."""

    rule_id: str


@dataclass(frozen=True, slots=True)
class RecipientTarget:
    """Deliver to one configured recipient, e.g. a test notification."""

    name: str


@dataclass(frozen=True, slots=True)
class SystemTarget:
    """Deliver to the configured system recipients, e.g. monitoring degraded."""


type Target = RuleTarget | RecipientTarget | SystemTarget


@dataclass(frozen=True, slots=True)
class Notification:
    """A rendered message and where, by configured name, it should go."""

    event_id: str
    text: str
    target: Target
    origin: DeliveryOrigin | None = None
    """What it reports. A system target always counts as ``SYSTEM``."""

    @classmethod
    def for_event(cls, event: Event, text: str) -> Notification:
        """Route an engine event to the recipients of the rule that produced it."""
        return cls(
            event_id=event.event_id,
            text=text,
            target=RuleTarget(event.rule_id),
            origin=_EVENT_ORIGINS[event.kind],
        )


_EVENT_ORIGINS = MappingProxyType(
    {
        EventKind.ESCALATED: DeliveryOrigin.ALARM,
        EventKind.REMINDER: DeliveryOrigin.REMINDER,
        EventKind.RECOVERED: DeliveryOrigin.RECOVERY,
        EventKind.STALE: DeliveryOrigin.STALE,
        EventKind.RESTORED: DeliveryOrigin.RESTORED,
    }
)
_STALE_ORIGINS = frozenset({DeliveryOrigin.STALE, DeliveryOrigin.RESTORED})


@dataclass(frozen=True, slots=True)
class Route:
    """A configured recipient and whether it is live or dry-run."""

    name: str
    recipient: Recipient
    mode: DeliveryMode


class Routing:
    """An immutable name-to-recipient mapping built from operator configuration."""

    __slots__ = ("_display", "_quiet_stale", "_routes", "_rules", "_system", "_system_log_only")

    _routes: Mapping[str, Route]
    _rules: Mapping[str, tuple[str, ...]]
    _system: tuple[str, ...]
    _display: Mapping[str, str]
    _quiet_stale: frozenset[str]
    _system_log_only: bool

    def __init__(
        self,
        routes: Mapping[str, Route],
        rules: Mapping[str, tuple[str, ...]],
        system: tuple[str, ...] = (),
        *,
        quiet_stale: frozenset[str] = frozenset(),
        system_log_only: bool = False,
    ) -> None:
        frozen_routes = dict(routes)
        for name, route in frozen_routes.items():
            if route.name != name:
                raise ValueError("route names must match their keys")  # noqa: TRY003  # per-check validation message
        frozen_rules = {rule_id: tuple(names) for rule_id, names in rules.items()}
        for names in (*frozen_rules.values(), tuple(system)):
            if any(name not in frozen_routes for name in names):
                raise UnknownTargetError("a route list names an unconfigured recipient")  # noqa: TRY003  # per-check validation message
        object.__setattr__(self, "_routes", MappingProxyType(frozen_routes))
        object.__setattr__(self, "_rules", MappingProxyType(frozen_rules))
        object.__setattr__(self, "_system", tuple(system))
        object.__setattr__(self, "_quiet_stale", frozenset(quiet_stale))
        object.__setattr__(self, "_system_log_only", system_log_only)
        object.__setattr__(
            self,
            "_display",
            MappingProxyType(
                {name: display_name(name, index) for index, name in enumerate(frozen_routes)}
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Routing is immutable")  # noqa: TRY003  # per-check validation message

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Routing is immutable")  # noqa: TRY003  # per-check validation message

    @classmethod
    def from_config(cls, config: RelayConfig) -> Routing:
        routes = {
            name: Route(name=name, recipient=recipient, mode=config.delivery_mode(name))
            for name, recipient in config.recipients.items()
        }
        rules = {rule.id: tuple(rule.recipients) for rule in config.rules}
        return cls(
            routes,
            rules,
            config.system_recipient_names(),
            quiet_stale=frozenset(rule.id for rule in config.rules if not rule.stale_notify),
            system_log_only=config.system_recipients == (),
        )

    @property
    def routes(self) -> Mapping[str, Route]:
        return self._routes

    @property
    def system_routes(self) -> tuple[Route, ...]:
        return tuple(self._routes[name] for name in self._system)

    def opted_out(self, origin: DeliveryOrigin | None, rule_id: str | None) -> bool:
        """Whether the configuration says a delivery of this origin is only logged.

        Stale data and its restoration are opted out for a rule with
        ``stale_notify: false`` or one no longer configured; system
        notifications when ``system_recipients`` is empty. Alarms, reminders,
        recoveries and deliveries of unknown origin never are.
        """
        if origin in _STALE_ORIGINS:
            return rule_id not in self._rules or rule_id in self._quiet_stale
        return origin is DeliveryOrigin.SYSTEM and self._system_log_only

    def route(self, name: str) -> Route | None:
        return self._routes.get(name)

    def display(self, name: str) -> str:
        """The recipient name as logs may show it: phone-shaped names are withheld."""
        return self._display.get(name) or display_name(name, "?")

    def resolve(self, target: Target) -> tuple[Route, ...]:
        """Return the configured routes for ``target``, or raise :class:`UnknownTargetError`."""
        if isinstance(target, RuleTarget):
            names = self._rules.get(target.rule_id)
            if names is None:
                raise UnknownTargetError("unknown rule")  # noqa: TRY003  # per-check validation message
            return tuple(self._routes[name] for name in names)
        if isinstance(target, RecipientTarget):
            route = self._routes.get(target.name)
            if route is None:
                raise UnknownTargetError("unknown recipient")  # noqa: TRY003  # per-check validation message
            return (route,)
        if isinstance(target, SystemTarget):
            return self.system_routes
        raise UnknownTargetError("unsupported target")  # noqa: TRY003  # per-check validation message

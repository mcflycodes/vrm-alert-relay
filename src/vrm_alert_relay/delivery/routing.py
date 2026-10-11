"""Recipient resolution from operator configuration only.

:class:`Routing` is built once from a validated
:class:`~vrm_alert_relay.config.RelayConfig` and never changes. A
:class:`Notification` can only *name* a configured rule or recipient; the
destination a provider receives is always the configured
:class:`~vrm_alert_relay.config.Recipient` object, looked up by name.
Nothing in an event, label, template, or provider response can add a
recipient or change where one points.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

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
    """Deliver to one configured recipient, e.g. a test or system notification."""

    name: str


type Target = RuleTarget | RecipientTarget


@dataclass(frozen=True, slots=True)
class Notification:
    """A rendered message and where, by configured name, it should go."""

    event_id: str
    text: str
    target: Target

    @classmethod
    def for_event(cls, event: Event, text: str) -> Notification:
        """Route an engine event to the recipients of the rule that produced it."""
        return cls(event_id=event.event_id, text=text, target=RuleTarget(event.rule_id))


@dataclass(frozen=True, slots=True)
class Route:
    """A configured recipient and whether it is live or dry-run."""

    name: str
    recipient: Recipient
    mode: DeliveryMode


class Routing:
    """An immutable name-to-recipient mapping built from operator configuration."""

    __slots__ = ("_routes", "_rules")

    def __init__(
        self,
        routes: Mapping[str, Route],
        rules: Mapping[str, tuple[str, ...]],
    ) -> None:
        frozen_routes = dict(routes)
        for name, route in frozen_routes.items():
            if route.name != name:
                raise ValueError("route names must match their keys")  # noqa: TRY003  # per-check validation message
        frozen_rules = {rule_id: tuple(names) for rule_id, names in rules.items()}
        for names in frozen_rules.values():
            unknown = [name for name in names if name not in frozen_routes]
            if unknown:
                raise UnknownTargetError("a rule names an unconfigured recipient")  # noqa: TRY003  # per-check validation message
        object.__setattr__(self, "_routes", MappingProxyType(frozen_routes))
        object.__setattr__(self, "_rules", MappingProxyType(frozen_rules))

    _routes: Mapping[str, Route]
    _rules: Mapping[str, tuple[str, ...]]

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
        return cls(routes, rules)

    @property
    def routes(self) -> Mapping[str, Route]:
        return self._routes

    def route(self, name: str) -> Route | None:
        return self._routes.get(name)

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
        raise UnknownTargetError("unsupported target")  # noqa: TRY003  # per-check validation message

"""Binding configured rules to the rules engine, the VRM poll and the templates.

Everything here is derived from the validated configuration once at startup.
A rule names its installation, measurement, levels and recipients; VRM data
only ever supplies a sample, an untrusted display label and an untrusted unit.
The unit and a rule's ``display_unit`` affect only rendered text, never the
engine's view of the rule.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, replace
from datetime import timedelta
from types import MappingProxyType
from typing import TYPE_CHECKING

from vrm_alert_relay.config import PROVIDER_NAMES, display_name
from vrm_alert_relay.engine import Direction, LevelSpec, RuleSpec
from vrm_alert_relay.templates import (
    DisplayUnit,
    fields_for_event,
    for_display,
    render_notification,
)

from ._quiet import log_info

if TYPE_CHECKING:
    from collections.abc import Mapping

    from vrm_alert_relay.config import Installation, Measurement, RelayConfig, Rule
    from vrm_alert_relay.engine import Event
    from vrm_alert_relay.templates import TemplateFields

__all__ = [
    "FINGERPRINT_LENGTH",
    "FINGERPRINT_UNAVAILABLE",
    "PollTarget",
    "RuleBinding",
    "bind_rules",
    "config_fingerprint",
    "log_loaded_rules",
    "poll_targets",
    "rule_spec",
]

type PollTarget = tuple[Installation, tuple[Measurement, ...]]

logger = logging.getLogger(__name__)

FINGERPRINT_LENGTH = 16
"""Hex characters of the configuration fingerprint that are shown."""
FINGERPRINT_UNAVAILABLE = "unavailable"
"""Shown instead of the fingerprint if it cannot be computed."""


def rule_spec(rule: Rule) -> RuleSpec:
    """The engine's view of a configured rule."""
    return RuleSpec(
        rule_id=rule.id,
        direction=Direction(rule.direction),
        levels=tuple(LevelSpec(level.name, level.threshold) for level in rule.levels),
        hysteresis=rule.hysteresis,
        clear_after_samples=rule.clear_after_samples,
        recovery_notify=rule.recovery_notify,
        cooldown=timedelta(minutes=rule.cooldown_minutes),
        reminder_interval=timedelta(minutes=rule.reminder_interval_minutes),
        reminder_max=rule.reminder_max,
        stale_after=timedelta(minutes=rule.stale_after_minutes),
    )


@dataclass(frozen=True, slots=True)
class RuleBinding:
    """A configured rule, its engine spec, and its level message templates."""

    rule: Rule
    spec: RuleSpec
    messages: Mapping[str, str]

    @classmethod
    def from_rule(cls, rule: Rule) -> RuleBinding:
        messages = {level.name: level.message for level in rule.levels if level.message}
        return cls(rule=rule, spec=rule_spec(rule), messages=MappingProxyType(messages))

    def render(self, event: Event, label: str | None, unit: str | None = None) -> str:
        """The notification text for one of this rule's events.

        The operator's level message applies to escalations and reminders; every
        other kind uses its default template (see docs/notifications.md).
        ``unit`` is the unit VRM reports; it is used only with the rule's
        ``display_unit``.
        """
        fields = fields_for_event(
            event,
            installation=self.rule.installation,
            measurement=self.rule.measurement.code,
            label=label,
        )
        if self.rule.display_unit is not None:
            fields = self._for_display(fields, DisplayUnit(self.rule.display_unit), unit)
        message = self.messages.get(event.level) if event.level is not None else None
        return render_notification(fields, level_message=message)

    def _for_display(
        self, fields: TemplateFields, display_unit: DisplayUnit, unit: str | None
    ) -> TemplateFields:
        """``fields`` in ``display_unit``, else the value and unit as VRM reports them."""
        shown = for_display(fields, display_unit, reported_unit=unit)
        if shown is not None:
            return shown
        logger.warning(
            "the measurement is not reported in degrees Celsius; "
            "showing its value without display_unit conversion",
            extra={"event": "relay.display_unit_fallback", "rule_id": self.rule.id},
        )
        return replace(fields, unit=unit)


def bind_rules(config: RelayConfig) -> tuple[RuleBinding, ...]:
    return tuple(RuleBinding.from_rule(rule) for rule in config.rules)


def poll_targets(config: RelayConfig) -> tuple[PollTarget, ...]:
    """Every configured installation with the measurements its rules watch.

    Each installation is polled once per cycle (R1), even one that no rule
    uses, so that a failure to reach it is still reported.
    """
    targets: list[PollTarget] = []
    for installation in config.vrm.installations:
        measurements: dict[Measurement, None] = {}
        for rule in config.rules:
            if rule.installation == installation.id:
                measurements.setdefault(rule.measurement, None)
        targets.append((installation, tuple(measurements)))
    return tuple(targets)


def _rule_settings(rule: Rule, positions: Mapping[str, int]) -> dict[str, object]:
    """The settings of ``rule`` that decide when and to whom it alerts.

    Recipients appear by name only, and a name that looks like a phone
    number only by its placeholder (``[#<position>]``, as ``check-config``
    shows it); their phone numbers, services and addresses are not part of it.
    """
    measurement = rule.measurement
    return {
        "id": rule.id,
        "installation": rule.installation,
        "measurement": [measurement.code, measurement.instance, measurement.service_type],
        "direction": rule.direction,
        "levels": [[level.name, float(level.threshold)] for level in rule.levels],
        "hysteresis": float(rule.hysteresis),
        "clear_after_samples": rule.clear_after_samples,
        "recovery_notify": rule.recovery_notify,
        "cooldown_minutes": rule.cooldown_minutes,
        "reminder_interval_minutes": rule.reminder_interval_minutes,
        "reminder_max": rule.reminder_max,
        "stale_after_minutes": rule.stale_after_minutes,
        "stale_notify": rule.stale_notify,
        "display_unit": rule.display_unit,
        "recipients": [display_name(name, positions[name]) for name in rule.recipients],
    }


def config_fingerprint(config: RelayConfig) -> str:
    """A short SHA-256 fingerprint of the settings that decide alerting.

    It covers every rule's settings (see :func:`_rule_settings`) and which
    providers are enabled, and changes when any of them does, so an operator
    can tell from the logs or health which configuration a relay has loaded.
    It never covers phone numbers, DIDs, URLs, secrets or file contents.
    Being informative only, it never raises: if it cannot be computed it is
    :data:`FINGERPRINT_UNAVAILABLE`.
    """
    try:
        return _fingerprint(config)
    except Exception:  # noqa: BLE001  # visibility must never stop startup
        return FINGERPRINT_UNAVAILABLE


def _fingerprint(config: RelayConfig) -> str:
    positions = {name: position for position, name in enumerate(config.recipients)}
    canonical = {
        "rules": [_rule_settings(rule, positions) for rule in config.rules],
        "sending": config.sending.enabled,
        "providers": {name: config.providers.is_enabled(name) for name in PROVIDER_NAMES},
    }
    text = json.dumps(canonical, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(text.encode()).hexdigest()[:FINGERPRINT_LENGTH]


def log_loaded_rules(config: RelayConfig) -> None:
    """Log one ``relay.rule_loaded`` record per rule, without recipients.

    A record that cannot be logged is dropped; startup goes on.
    """
    for rule in config.rules:
        log_info(
            logger,
            "rule loaded",
            {
                "event": "relay.rule_loaded",
                "rule_id": rule.id,
                "direction": rule.direction,
                "levels": [
                    {"name": level.name, "threshold": level.threshold} for level in rule.levels
                ],
                "hysteresis": rule.hysteresis,
                "display_unit": rule.display_unit,
            },
        )

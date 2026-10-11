"""Restricted message templates and notification text rendering (R23).

Importing this package must not import :mod:`vrm_alert_relay.config`, which
uses :mod:`vrm_alert_relay.templates.syntax` to validate templates.
"""

from vrm_alert_relay.templates.render import (
    DEFAULT_TEMPLATES,
    FIELD_LIMITS,
    MAX_RENDERED_LENGTH,
    MISSING,
    NotificationKind,
    Template,
    TemplateFields,
    fields_for_event,
    render_notification,
    sanitize_field,
)
from vrm_alert_relay.templates.syntax import (
    FIELD_NAMES,
    MAX_TEMPLATE_CHARS,
    TemplateSyntaxError,
    parse_template,
)

__all__ = [
    "DEFAULT_TEMPLATES",
    "FIELD_LIMITS",
    "FIELD_NAMES",
    "MAX_RENDERED_LENGTH",
    "MAX_TEMPLATE_CHARS",
    "MISSING",
    "NotificationKind",
    "Template",
    "TemplateFields",
    "TemplateSyntaxError",
    "fields_for_event",
    "parse_template",
    "render_notification",
    "sanitize_field",
]

"""Restricted templates: syntax, sanitizing, bounding and single-pass rendering."""

from __future__ import annotations

import re
import unicodedata
from datetime import UTC, datetime, timedelta, timezone

import pytest
from hypothesis import given
from hypothesis import strategies as st

from vrm_alert_relay.engine import Event, EventKind
from vrm_alert_relay.templates import (
    DEFAULT_TEMPLATES,
    DISPLAY_DECIMALS,
    FIELD_LIMITS,
    FIELD_NAMES,
    MAX_RENDERED_LENGTH,
    MAX_TEMPLATE_CHARS,
    MISSING,
    DisplayUnit,
    NotificationKind,
    Template,
    TemplateFields,
    TemplateSyntaxError,
    fields_for_event,
    for_display,
    is_celsius,
    neutralize_links,
    parse_template,
    render_notification,
    sanitize_field,
    sanitize_untrusted,
)
from vrm_alert_relay.templates.syntax import Literal, Placeholder

WHEN = datetime(2026, 1, 15, 12, 30, 45, tzinfo=UTC)
FIELDS = TemplateFields(
    kind=NotificationKind.ESCALATED,
    rule="cabin-freezer-warm",
    level="critical",
    value=-3.5,
    unit="°C",
    installation="cabin",
    measurement="tsT",
    label="Freezer temperature",
    time=WHEN,
)


def test_parse_splits_literals_and_placeholders() -> None:
    assert parse_template("{level}: {{literal}} {rule}!") == (
        Placeholder("level"),
        Literal(": {literal} "),
        Placeholder("rule"),
        Literal("!"),
    )
    assert parse_template("no placeholders") == (Literal("no placeholders"),)
    assert parse_template("{rule}{level}") == (Placeholder("rule"), Placeholder("level"))


def test_every_field_name_is_accepted() -> None:
    text = " ".join(f"{{{name}}}" for name in FIELD_NAMES)
    assert Template(text).placeholders == frozenset(FIELD_NAMES)


@pytest.mark.parametrize(
    ("template", "problem"),
    [
        ("{nope}", "unknown placeholder"),
        ("{Rule}", "bare field name"),
        ("{}", "bare field name"),
        ("{ rule }", "bare field name"),
        ("{rule.__class__}", "bare field name"),
        ("{rule[0]}", "bare field name"),
        ("{rule!r}", "bare field name"),
        ("{value:>99999}", "bare field name"),
        ("{value:,.2f}", "bare field name"),
        ("{rule", "unmatched"),
        ("rule}", "unmatched"),
        ("{{rule}", "unmatched"),
        ("{a{rule}}", "unmatched"),
        ("line\nbreak", "control or format"),
        ("tab\there", "control or format"),
        ("bidi \u202e override", "control or format"),
        ("zero\u200bwidth", "control or format"),
        ("para\u2029sep", "control or format"),
    ],
)
def test_unsupported_syntax_is_rejected(template: str, problem: str) -> None:
    with pytest.raises(TemplateSyntaxError) as caught:
        parse_template(template)
    assert problem in caught.value.reason
    assert "allowed placeholders are {rule}, {level}" in caught.value.reason
    assert "__class__" not in str(caught.value)
    with pytest.raises(TemplateSyntaxError):
        Template(template)


@pytest.mark.parametrize("source", ["", "x" * (MAX_TEMPLATE_CHARS + 1), None])
def test_template_size_and_type(source: object) -> None:
    with pytest.raises(TemplateSyntaxError):
        Template(source)  # type: ignore[arg-type]


def test_template_value_semantics() -> None:
    a, b = Template("{rule}"), Template("{rule}")
    assert a == b
    assert hash(a) == hash(b)
    assert a != Template("{level}")
    assert a != "{rule}"
    assert repr(a) == "Template('{rule}')"
    assert a.source == "{rule}"


def test_default_escalation_text() -> None:
    assert render_notification(FIELDS) == (
        "critical: cabin-freezer-warm at cabin: Freezer temperature is -3.5°C "
        "(2026-01-15 12:30 UTC)"
    )


@pytest.mark.parametrize("kind", list(NotificationKind))
def test_every_kind_has_a_bounded_default(kind: NotificationKind) -> None:
    fields = TemplateFields(
        kind=kind,
        rule="r" * 300,
        level="l" * 300,
        value=1.0,
        installation="i" * 300,
        measurement="m",
        label="x" * 300,
        time=WHEN,
        count=7,
    )
    text = render_notification(fields)
    assert kind in DEFAULT_TEMPLATES
    assert 0 < len(text) <= MAX_RENDERED_LENGTH
    assert "{" not in text


def test_system_kinds_render_their_fields() -> None:
    summary = TemplateFields(kind=NotificationKind.SUPPRESSION_SUMMARY, count=3, time=WHEN)
    assert render_notification(summary) == (
        "VRM Alert Relay: 3 alert(s) held back by the global rate limit since 2026-01-15 12:30 UTC"
    )
    degraded = TemplateFields(
        kind=NotificationKind.MONITORING_DEGRADED, installation="cabin", time=WHEN
    )
    assert "monitoring of cabin is degraded since 2026-01-15 12:30 UTC" in render_notification(
        degraded
    )


@pytest.mark.parametrize(
    ("value", "text"),
    [
        (12.0, "12"),
        (-0.0, "0"),
        (0.0001, "0"),
        (-7.25, "-7.25"),
        (1 / 3, "0.333"),
        (999999.4, "999999.4"),
        (12345678.9, "1.23457e+07"),
        (float("nan"), MISSING),
        (float("inf"), MISSING),
        (True, MISSING),
        (None, MISSING),
    ],
)
def test_value_formatting(value: float | None, text: str) -> None:
    fields = TemplateFields(kind=NotificationKind.ESCALATED, value=value)
    assert Template("{value}").render(fields) == text


def test_missing_fields_and_fallbacks() -> None:
    bare = TemplateFields(kind=NotificationKind.STALE)
    assert Template("[{unit}]").render(bare) == "[]"
    assert Template("{rule} {level} {time} {count} {label}").render(bare) == " ".join([MISSING] * 5)
    assert Template("{kind}").render(bare) == "stale"
    with_measurement = TemplateFields(kind=NotificationKind.STALE, measurement="tsT")
    assert Template("{label}").render(with_measurement) == "tsT"


def test_time_is_shown_in_utc_and_naive_time_is_missing() -> None:
    mountain = timezone(timedelta(hours=-7))
    local = TemplateFields(
        kind=NotificationKind.ESCALATED, time=datetime(2026, 1, 15, 5, 30, tzinfo=mountain)
    )
    assert Template("{time}").render(local) == "2026-01-15 12:30 UTC"
    naive = TemplateFields(kind=NotificationKind.ESCALATED, time=datetime(2026, 1, 15, 5, 30))
    assert Template("{time}").render(naive) == MISSING


def test_substitution_is_single_pass() -> None:
    fields = TemplateFields(
        kind=NotificationKind.ESCALATED, rule="real-rule", label="{rule} {{level}} {time"
    )
    assert Template("{label}/{rule}").render(fields) == "{rule} {{level}} {time/real-rule"


def test_untrusted_label_is_sanitized_and_truncated() -> None:
    label = "Freezer\r\n+1 202 555 0199\x1b[31m\u202eSTOP\u2028\tend\x00" + "z" * 500
    fields = TemplateFields(kind=NotificationKind.ESCALATED, label=label)
    text = Template("<{label}>").render(fields)
    inner = text[1:-1]
    assert len(inner) == FIELD_LIMITS["label"]
    assert inner.endswith("…")
    assert inner.startswith("Freezer +1 202 555 0199 [31m STOP end z")
    assert all(unicodedata.category(c)[0] not in "CZ" or c == " " for c in text)


def test_huge_untrusted_input_is_cut_before_it_is_examined() -> None:
    assert sanitize_field("a" * 10_000_000, 10) == "aaaaaaaaa…"
    assert sanitize_field("  a \n\n b  ", 10) == "a b"


def test_rendered_text_is_bounded() -> None:
    fields = TemplateFields(kind=NotificationKind.ESCALATED, label="y" * 64)
    template = Template("{label}" * 40)
    assert len(template.render(fields)) == MAX_RENDERED_LENGTH
    assert len(template.render(fields, max_length=160)) == 160


def test_level_message_replaces_the_escalation_default() -> None:
    assert render_notification(FIELDS, level_message="Freezer {level} at {value}{unit}") == (
        "Freezer critical at -3.5°C"
    )
    reminder = TemplateFields(kind=NotificationKind.REMINDER, level="critical")
    assert render_notification(reminder, level_message="Freezer {level}") == (
        "Reminder: Freezer critical"
    )
    recovered = TemplateFields(kind=NotificationKind.RECOVERED, rule="r", installation="i")
    assert render_notification(recovered, level_message="ignored").startswith("Recovered: r at i")


def test_level_message_is_validated_at_render_time_too() -> None:
    with pytest.raises(TemplateSyntaxError):
        render_notification(FIELDS, level_message="{rule.__init__}")


@pytest.mark.parametrize("kind", list(EventKind))
def test_fields_for_event(kind: EventKind) -> None:
    event = Event(
        rule_id="freezer",
        episode=1,
        kind=kind,
        level="warning",
        value=-10.0,
        sample_time=WHEN,
        event_id="evt_fake_0001",
    )
    fields = fields_for_event(
        event, installation="cabin", measurement="tsT", label="Freezer", unit="°C"
    )
    assert fields.kind.value == kind.value
    assert (fields.rule, fields.level, fields.value, fields.time) == (
        "freezer",
        "warning",
        -10.0,
        WHEN,
    )
    assert (fields.installation, fields.measurement, fields.label, fields.unit) == (
        "cabin",
        "tsT",
        "Freezer",
        "°C",
    )
    assert render_notification(fields)


@given(st.text(max_size=400))
def test_any_label_renders_one_bounded_line(label: str) -> None:
    fields = TemplateFields(kind=NotificationKind.ESCALATED, rule="freezer", label=label)
    text = render_notification(fields)
    assert len(text) <= MAX_RENDERED_LENGTH
    assert all(unicodedata.category(c)[0] not in "CZ" or c == " " for c in text)
    assert " at n/a: " in text
    assert text.startswith("n/a: freezer at ")


@given(st.text(max_size=80))
def test_any_template_parses_or_raises_syntax_error(source: str) -> None:
    try:
        template = Template(source)
    except TemplateSyntaxError:
        return
    assert template.placeholders <= frozenset(FIELD_NAMES)
    assert len(template.render(FIELDS)) <= MAX_RENDERED_LENGTH


# Links in untrusted fields -----------------------------------------------------

LINKY = re.compile(r"[\w-]+(?:\.[\w-]+)*\.[^\W\d_]{2,}|\d{1,3}(?:\.\d{1,3}){3}")
BARE_SCHEME = re.compile(
    r"(?i)\b(?:mailto|tel|sms|smsto|callto|facetime|javascript|vbscript|data|file|geo|intent|market):"
)


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        ("https://evil.example.test/x", "hxxps[:]//evil[.]example[.]test/x"),
        ("HTTP://Evil.Example.Test", "HxxP[:]//Evil[.]Example[.]Test"),
        ("ftp://files.example.test", "ftp[:]//files[.]example[.]test"),
        ("visit www.evil.example now", "visit www[.]evil[.]example now"),
        ("call tel:+12025550199", "call tel[:]+12025550199"),
        ("mailto:someone@evil.example", "mailto[:]someone@evil[.]example"),
        ("javascript:alert(1)", "javascript[:]alert(1)"),
        ("gateway 192.0.2.10 down", "gateway 192[.]0[.]2[.]10 down"),
        ("evil.", "evil[.]"),
        (".com", "[.]com"),
        ("bücher.example", "bücher[.]example"),
        ("Freezer temperature", "Freezer temperature"),
        ("Battery 12.5 V, SoC 80%", "Battery 12.5 V, SoC 80%"),
        ("e.g. v1.2", "e.g. v1.2"),
        ("Time: 12:30", "Time: 12:30"),
    ],
)
def test_neutralize_links(text: str, shown: str) -> None:
    assert neutralize_links(text) == shown


def test_untrusted_label_and_unit_lose_their_links() -> None:
    fields = TemplateFields(
        kind=NotificationKind.ESCALATED,
        label="Pay at https://evil.example.test/x",
        unit=".com",
        value=1.0,
    )
    text = Template("{label} {value}{unit}").render(fields)
    assert text == "Pay at hxxps[:]//evil[.]example[.]test/x 1[.]com"
    adjacent = TemplateFields(kind=NotificationKind.ESCALATED, label="evil.", unit="com")
    assert Template("{label}{unit}").render(adjacent) == "evil[.]com"


def test_operator_template_text_is_unchanged() -> None:
    fields = TemplateFields(kind=NotificationKind.ESCALATED, label="Freezer", rule="freezer")
    template = Template("See https://status.example.test for {rule}: {label}")
    assert template.render(fields) == "See https://status.example.test for freezer: Freezer"


def test_trusted_fields_are_not_rewritten() -> None:
    fields = TemplateFields(kind=NotificationKind.ESCALATED, measurement="tsT", rule="a.bc")
    assert Template("{rule} {label}").render(fields) == "a.bc tsT"


def test_untrusted_sanitizing_is_bounded() -> None:
    shown = sanitize_untrusted("a.bc " * 1_000_000, 64)
    assert len(shown) <= 64
    assert shown.endswith("…")


@given(st.text(max_size=300))
def test_untrusted_text_never_keeps_a_link(text: str) -> None:
    shown = sanitize_untrusted(text, FIELD_LIMITS["label"])
    folded = _folded(shown)
    assert "://" not in folded
    assert LINKY.search(folded) is None
    assert BARE_SCHEME.search(folded) is None
    assert len(shown) <= FIELD_LIMITS["label"]


@given(
    st.lists(
        st.sampled_from(["http", "s", "://", ".", "www", "evil", "com", "tel", ":", "1", " ", "é"]),
        max_size=40,
    )
)
def test_link_shaped_labels_never_keep_a_link(parts: list[str]) -> None:
    fields = TemplateFields(kind=NotificationKind.ESCALATED, label="".join(parts))
    shown = Template("{label}").render(fields)
    assert "://" not in shown
    assert LINKY.search(shown) is None
    assert BARE_SCHEME.search(shown) is None


# Lookalike punctuation in untrusted fields -------------------------------------

FULLWIDTH_COLON, FULLWIDTH_SOLIDUS, FULLWIDTH_STOP = "\uff1a", "\uff0f", "\uff0e"
IDEOGRAPHIC_STOP, HALFWIDTH_IDEOGRAPHIC_STOP, SMALL_STOP = "\u3002", "\uff61", "\ufe52"


@pytest.mark.parametrize(
    ("text", "shown"),
    [
        (
            f"https{FULLWIDTH_COLON}{FULLWIDTH_SOLIDUS}{FULLWIDTH_SOLIDUS}evil{FULLWIDTH_STOP}com",
            "hxxps[:]//evil[.]com",
        ),
        (f"evil{IDEOGRAPHIC_STOP}example{IDEOGRAPHIC_STOP}test", "evil[.]example[.]test"),
        (f"evil{HALFWIDTH_IDEOGRAPHIC_STOP}com", "evil[.]com"),
        (f"evil{FULLWIDTH_STOP}com", "evil[.]com"),
        (f"www{SMALL_STOP}evil{SMALL_STOP}com", "www[.]evil[.]com"),
        ("\uff11\uff19\uff12\uff0e\uff10\uff0e\uff12\uff0e\uff11", "192[.]0[.]2[.]1"),
        (f"tel{FULLWIDTH_COLON}+12025550199", "tel[:]+12025550199"),
        ("Freezer \u2103", "Freezer \u00b0C"),
    ],
)
def test_lookalike_punctuation_is_folded_before_neutralizing(text: str, shown: str) -> None:
    assert sanitize_untrusted(text, 64) == shown
    fields = TemplateFields(kind=NotificationKind.ESCALATED, label=text)
    assert Template("{label}").render(fields) == shown


LOOKALIKE_PARTS = [
    "http",
    "s",
    "evil",
    "com",
    "www",
    "tel",
    "1",
    ".",
    ":",
    "/",
    FULLWIDTH_COLON,
    FULLWIDTH_SOLIDUS,
    FULLWIDTH_STOP,
    IDEOGRAPHIC_STOP,
    HALFWIDTH_IDEOGRAPHIC_STOP,
    SMALL_STOP,
    "\uff45",
    " ",
]


def _folded(text: str) -> str:
    return unicodedata.normalize("NFKC", text).replace(IDEOGRAPHIC_STOP, ".")


@given(st.lists(st.sampled_from(LOOKALIKE_PARTS), max_size=40))
def test_lookalike_links_never_survive(parts: list[str]) -> None:
    shown = sanitize_untrusted("".join(parts), FIELD_LIMITS["label"])
    folded = _folded(shown)
    assert "://" not in folded
    assert LINKY.search(folded) is None
    assert BARE_SCHEME.search(folded) is None


@pytest.mark.parametrize("unit", ["°C", " °C ", "° C", "℃"])
def test_celsius_spellings_are_recognized(unit: str) -> None:
    assert is_celsius(unit)


@pytest.mark.parametrize("unit", [None, "", "C", "°F", "°c", "ºC", "V", "%", "K"])
def test_other_units_are_not_celsius(unit: str | None) -> None:
    assert not is_celsius(unit)


@pytest.mark.parametrize(
    ("celsius", "display_unit", "value", "symbol"),
    [
        (-3.5, DisplayUnit.DEG_F, 25.7, "°F"),
        (-40.0, DisplayUnit.DEG_F, -40.0, "°F"),
        (-18.0, DisplayUnit.DEG_F, -0.4, "°F"),
        (0.0, DisplayUnit.DEG_F, 32.0, "°F"),
        (4.44, DisplayUnit.DEG_F, 40.0, "°F"),
        (37.0, DisplayUnit.DEG_F, 98.6, "°F"),
        (-3.5, DisplayUnit.DEG_C, -3.5, "°C"),
        (-3.46, DisplayUnit.DEG_C, -3.5, "°C"),
        (21.04, DisplayUnit.DEG_C, 21.0, "°C"),
    ],
)
def test_for_display_converts_and_rounds(
    celsius: float, display_unit: DisplayUnit, value: float, symbol: str
) -> None:
    fields = TemplateFields(kind=NotificationKind.ESCALATED, value=celsius, unit=None)
    shown = for_display(fields, display_unit, reported_unit="°C")
    assert shown is not None
    assert shown.value == pytest.approx(value)
    assert shown.unit == symbol
    assert shown.kind is fields.kind


@pytest.mark.parametrize(
    ("celsius", "text"),
    [
        (-3.5, "25.7°F"),
        (-17.8, "0°F"),
        (-17.79, "0°F"),
        (-18.0, "-0.4°F"),
        (-23.3, "-9.9°F"),
        (4.44, "40°F"),
        (4.5, "40.1°F"),
    ],
)
def test_display_value_renders_with_one_decimal_at_most(celsius: float, text: str) -> None:
    fields = TemplateFields(kind=NotificationKind.ESCALATED, value=celsius)
    shown = for_display(fields, DisplayUnit.DEG_F, reported_unit="℃")
    assert shown is not None
    assert Template("{value}{unit}").render(shown) == text


def test_for_display_rounds_to_the_documented_decimals() -> None:
    assert DISPLAY_DECIMALS == 1
    fields = TemplateFields(kind=NotificationKind.ESCALATED, value=1.23456)
    shown = for_display(fields, DisplayUnit.DEG_C, reported_unit="°C")
    assert shown is not None
    assert Template("{value}").render(shown) == "1.2"


def test_for_display_keeps_a_missing_value_missing() -> None:
    fields = TemplateFields(kind=NotificationKind.STALE, rule="freezer", time=WHEN)
    shown = for_display(fields, DisplayUnit.DEG_F, reported_unit="°C")
    assert shown == TemplateFields(
        kind=NotificationKind.STALE, rule="freezer", time=WHEN, unit="°F"
    )


@pytest.mark.parametrize("reported", [None, "", "V", "°F", "%", "°C/h"])
@pytest.mark.parametrize("display_unit", list(DisplayUnit))
def test_for_display_refuses_a_unit_that_is_not_celsius(
    reported: str | None, display_unit: DisplayUnit
) -> None:
    assert for_display(FIELDS, display_unit, reported_unit=reported) is None


def test_display_fields_are_still_sanitized_and_bounded() -> None:
    shown = for_display(FIELDS, DisplayUnit.DEG_F, reported_unit="°C")
    assert shown is not None
    assert render_notification(shown, level_message="{label} {value}{unit}") == (
        "Freezer temperature 25.7°F"
    )
    assert len(render_notification(shown, max_length=40)) <= 40
    hostile = for_display(
        TemplateFields(kind=NotificationKind.ESCALATED, value=1.0, label="see evil.example.test"),
        DisplayUnit.DEG_F,
        reported_unit="°C",
    )
    assert hostile is not None
    assert Template("{label} {value}{unit}").render(hostile) == "see evil[.]example[.]test 33.8°F"

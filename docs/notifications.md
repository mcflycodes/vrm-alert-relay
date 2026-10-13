# Notifications: message templates and providers

**Updated:** 2026-10-12

VRM Alert Relay is an unofficial, independent project. It is not affiliated with, sponsored by, or endorsed by Victron Energy.

This page describes how notification text is produced and what each provider sends. Requirements R19–R24 and R27 in [requirements.md](requirements.md) set the rules; ADR 0002 covers delivery, retries and reconciliation.

## Message templates

A level's optional `message` is a single-line template of at most 320 characters. Templates use a restricted placeholder syntax:

- `{name}` inserts a field. Only the names in the table below are accepted.
- `{{` and `}}` insert a literal `{` or `}`.
- Nothing else is allowed: no expressions, no attribute or index access (`{rule.x}`, `{rule[0]}`), no conversions (`{rule!r}`), no format specifications (`{value:>10}`), and no control or format characters (line breaks, tabs, bidirectional overrides, zero-width characters).

The configuration is rejected at load time, and by `check-config`, if a template breaks these rules.

| Placeholder | Value |
|---|---|
| `{rule}` | The rule id. |
| `{level}` | The level name. |
| `{value}` | The measured value, up to three decimals (`-3.5`, `12`). With the rule's `display_unit`, the value in that unit, always with one decimal (`25.7`, `32.0`). |
| `{unit}` | Empty, unless the rule sets `display_unit`: then the display unit (`°C` or `°F`), or the unit VRM reports when the value cannot be converted. |
| `{installation}` | The installation id from `vrm.installations`. |
| `{measurement}` | The measurement code, such as `tsT`. |
| `{label}` | The display label VRM reports for the measurement, or the measurement code when there is none. |
| `{time}` | The sample time, in UTC, as `2026-01-15 12:30 UTC`. |
| `{kind}` | The notification kind, such as `escalated`. |
| `{count}` | For a rate-limit summary, how many alerts were held back. |

A field the notification does not carry is shown as `n/a` (`{unit}` is left empty).

### Display unit

A rule's optional `display_unit` (`degC` or `degF`, see [configuration.md](configuration.md#display-unit)) converts `{value}` and sets `{unit}` when the text is rendered, for escalations, reminders, recoveries and "data restored" messages, including a level's own `message`. Nothing else changes: thresholds, hysteresis, evaluation, event ids and delivery use the measurement's own units.

With `display_unit: degF`, a freezer at -3.5 °C produces:

```text
critical: cabin-freezer-warm at cabin: Freezer temperature is 25.7°F (2026-01-15 12:30 UTC)
```

A display unit never stops a message. When VRM does not report the measurement in °C, the message shows the value and unit as reported (for example `12.6V`); if rendering fails for any other reason, the default text is sent with the value as reported. The unit VRM reports is untrusted, so it is sanitized and its links neutralized like `{label}`.

### Safety of rendered text

- Substitution is a single pass: a value that contains `{rule}` is inserted as the literal text `{rule}`.
- Every value is stripped of control, format and line-separator characters, has its whitespace collapsed, and is cut to a per-field limit (64 characters for labels and names) before it is inserted.
- `{label}` and `{unit}` can come from VRM data and are treated as untrusted: links in them are made visibly non-clickable. `https://evil.example.test/x` is shown as `hxxps[:]//evil[.]example[.]test/x`, `tel:` and similar schemes as `tel[:]`, and the dots of domain names and IP addresses as `[.]`. Fullwidth and other lookalike forms of these characters (for example the ideographic full stop) are first folded to their plain forms, so they are caught too. Text you write in a template is left as it is.
- The rendered text is at most 480 characters. Providers may shorten it further; SMS is limited to 160.
- A template produces only text. Recipients and destinations come only from the configuration; nothing in a template, a label or a provider response can add or change one.

### Defaults

Without a `message`, each kind uses a default:

| Kind | Default template |
|---|---|
| escalated | `{level}: {rule} at {installation}: {label} is {value}{unit} ({time})` |
| reminder | `Reminder, still {level}: {rule} at {installation}: {label} is {value}{unit} ({time})` |
| recovered | `Recovered: {rule} at {installation} is back to normal: {label} is {value}{unit} ({time})` |
| stale | `Stale data: {rule} at {installation} has had no new {label} reading since {time}` |
| restored | `Data restored: {rule} at {installation} is reporting again: {label} is {value}{unit} ({time})` |
| rate-limit summary | `VRM Alert Relay: {count} alert(s) held back by the global rate limit since {time}` |
| storage notice | `VRM Alert Relay: state storage is failing, so alerts continue under limits kept in memory only. Check the relay.` |
| monitoring degraded | `VRM Alert Relay: monitoring of {installation} is degraded since {time}; alerts may be delayed or missed` |
| monitoring restored | `VRM Alert Relay: monitoring of {installation} is restored ({time})` |

A level's `message` replaces the default for escalations into that level. Reminders for the level send `Reminder: ` followed by the level's message.

System notifications (the rate-limit summary, the storage notice and the monitoring notices) go to `system_recipients`. [operations.md](operations.md) explains when monitoring is reported as degraded and restored. The `test-notification` command sends the fixed text `VRM Alert Relay: test notification. If you can read this, delivery to this recipient works.`

## Providers

Real sending needs both `sending.enabled: true` and the provider's own `enabled: true`. Until then every message goes to the `log` provider.

### `log`

Writes one structured log record per message (`"event": "provider.dry_run"`) with the provider, a log-safe description of the recipient (phone numbers show only the last four digits, and a Home Assistant service name with five or more digits is shown as a placeholder such as `notify.[#***0199]`), the delivery id and the text as the provider would send it. It never contacts any service.

### `voipms`

Sends SMS through the VoIP.ms REST API (`https://voip.ms/api/v1/rest.php` by default).

- Each call is an HTTPS `POST` with a `multipart/form-data` body carrying the API username, API password, method and arguments. Credentials never appear in a URL.
- A message counts as sent only when the JSON `status` is exactly `success`. VoIP.ms reports errors as HTTP 200 with another status: refusals such as `invalid_credentials`, `invalid_dst` or `sms_toolong` fail without retry; `limit_reached`, `api_limit_exceeded`, `method_maintenance` and `sms_failed` are retried. An unrecognized status, an unreadable response, or a failure after the request was sent is treated as ambiguous.
- Messages are trimmed to 160 characters, ending in `...`.
- An ambiguous attempt is looked up with `getSMS` before any retry. It counts as sent only when VoIP.ms returns a sent message from the DID to the recipient with exactly the attempt's message id. Without an id, an empty result for the days around the attempt counts as not sent; a message with the same text is not proof, because it may be an earlier one, so the attempt is retried within the retry limit.
- VoIP.ms sends SMS only to US and Canadian numbers; the configuration accepts only those.
- VoIP.ms is always reached over HTTPS with the bundled trust store. It has no `ca_file` or `allow_insecure_http` setting.

### `homeassistant`

Calls a Home Assistant `notify` service: `POST {base_url}/api/services/notify/<service>` with `Authorization: Bearer <token>` and the JSON body `{"message": "...", "title": "VRM Alert Relay"}`. Use a long-lived access token of a dedicated, non-admin Home Assistant user.

A 2xx answer is success. 401 and 403 mean the token is wrong or lacks permission and are not retried; neither are other 4xx answers except 408, 425 and 429. A 5xx answer, a redirect (which is never followed) or a timeout after the request was sent is ambiguous and retried.

### `webhook`

POSTs this JSON document (payload version 1) to the configured URL:

```json
{
  "version": 1,
  "source": "vrm-alert-relay",
  "delivery_id": "dlv_0123456789abcdef0123456789abcdef",
  "kind": "escalated",
  "rule": "cabin-freezer-warm",
  "level": "critical",
  "value": -3.5,
  "unit": null,
  "installation": "cabin",
  "measurement": "tsT",
  "time": "2026-01-15T12:30:00Z",
  "text": "critical: cabin-freezer-warm at cabin: tsT is -3.5 (2026-01-15 12:30 UTC)"
}
```

- Every key is always present. Structured fields are `null` when the message does not carry them; `text` is always the rendered message.
- **Known v1 limitation:** the delivery engine stores only each message's rendered text, not its structured fields, so in v1 every structured field (`kind`, `rule`, `level`, `value`, `unit`, `installation`, `measurement`, `time`) is `null` and receivers should read `text`. The payload shape stays the same when the fields are filled in a later release.
- `delivery_id` is the same for every retry of one message to one recipient, so a receiver can drop duplicates.
- With `auth_header_name` and `auth_header_value_file`, the header is sent with every request.
- The URL path is shown as `/[REDACTED]` in logs, since webhook URLs often embed a token.
- Status handling matches the Home Assistant provider.

## Private certificates and plain HTTP (Home Assistant and webhook only)

Home Assistant and webhook receivers often run on a private network. Two per-provider settings cover that:

- `ca_file`: an absolute path to a PEM file with the CA certificate (or the self-signed certificate) that signs the receiver's certificate. The provider then trusts only the certificates in that file. Certificate and hostname verification stay on; there is no way to turn verification off.
- `allow_insecure_http: true`: permits a plain `http://` URL for that one provider. Its token, header value and messages then cross the network unencrypted. `check-config` prints an `INSECURE` warning whenever this is on.

```yaml
providers:
  homeassistant:
    enabled: true
    base_url: https://homeassistant.example.invalid:8123
    token_file: /run/secrets/homeassistant_token
    ca_file: /etc/vrm-alert-relay/homeassistant-ca.pem
  webhook:
    enabled: true
    url: http://192.0.2.10:8080/relay
    allow_insecure_http: true
```

Redirects are never followed, and timeouts and response-size limits apply, with either setting. VRM and VoIP.ms do not accept either setting.

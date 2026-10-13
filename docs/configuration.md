# Configuration reference

**Updated:** 2026-10-12

VRM Alert Relay is an unofficial, independent project. It is not affiliated with, sponsored by, or endorsed by Victron Energy.

This page lists every setting in the configuration file, with its type, default, bounds and validation rules. [examples/config.example.yaml](../examples/config.example.yaml) is a complete, commented example that uses every section. Other pages own the behaviour behind the settings:

- [notifications.md](notifications.md): message templates, and what each provider sends.
- [operations.md](operations.md): the command line, where the relay finds this file, the poll loop, monitoring notices and the health endpoint.
- [deploy-docker.md](deploy-docker.md): putting the file and its secret files in place.

## The file

The configuration is one YAML file. The relay reads it from `--config`, else `$VRM_ALERT_RELAY_CONFIG`, else `/etc/vrm-alert-relay/config.yaml`. It is validated in full at startup and by `vrm-alert-relay check-config`; the relay does not start with an invalid file.

- At most 256 KiB, UTF-8 (a byte-order mark is accepted), exactly one YAML document, with a mapping at the top level.
- Unknown keys are rejected, so a typo is an error rather than an ignored setting.
- YAML anchors, aliases and merge keys (`&`, `*`, `<<`) are not allowed. Mapping keys must be plain strings and may not repeat. Nesting is limited to 16 levels and each list or mapping to 1000 entries.
- Types are strict: a whole number must be written as one (`60`, not `"60"` or `60.0`), and a string where text is expected. A number setting (`threshold`, `hysteresis`) also accepts a whole number. Infinity and NaN are rejected.
- The parser follows YAML 1.1, so unquoted `yes`, `no`, `on` and `off` are booleans. Quote such text where a string is expected.
- Secrets are never written in this file. Each one lives in its own file, named by a `*_file` setting (see [Secret files](#secret-files)). A key such as `password:`, `token:` or `api_key:` is rejected with a message saying so.
- Error messages show the location and the rule broken, never the rejected value, because it may be a secret or a phone number. Where a location cannot be shown safely, the line number is given instead.

### Names

Installation ids, rule ids, level names and recipient names are 1 to 63 characters: lowercase letters, digits, `_` and `-`, starting with a letter or digit. A recipient name with five or more digits, which could be a phone number, is shown by its position, such as `[#3]`, in everything the relay prints or logs.

### URLs

Every URL setting must:

- use `https://` (Home Assistant and the webhook can opt in to `http://`, see [`allow_insecure_http`](#private-certificates-and-plain-http));
- be at most 2048 characters, with no whitespace, control characters or `\`;
- include a host: an IPv4 address, an IPv6 address in brackets, or an ASCII (or punycode) host name of at most 253 characters, made of dot-separated labels of 1 to 63 letters, digits and `-` that neither start nor end with `-` (a trailing dot is allowed). Private network addresses are allowed;
- have no credentials before the host (`user:pass@`) and no `#fragment`;
- use a port from 1 to 65535, if it gives one.

## Top-level settings

| Key | Type | Default | Notes |
|---|---|---|---|
| `version` | integer | required | Configuration format version. This release supports `1` only. |
| `sending` | mapping | see below | The master switch for real sending. |
| `vrm` | mapping | required | VRM API access and the installations to poll. |
| `rate_limits` | mapping | see below | The global cap and retries. |
| `recipients` | mapping | empty | The recipient allowlist. |
| `providers` | mapping | external providers disabled | Notification provider settings. The `log` provider is always available. |
| `rules` | list | empty | Alert rules. With none, `check-config` warns that nothing is monitored. |
| `system_recipients` | list | not set | Who receives system notifications. `[]` logs them only. |
| `health` | mapping | disabled | The optional health endpoint. |

## `sending` and dry-run mode

| Key | Type | Default |
|---|---|---|
| `sending.enabled` | boolean | `false` |

A provider sends for real ("is live") only when **both** `sending.enabled` and that provider's own `providers.<name>.enabled` are `true`. Otherwise every message for it goes to the `log` provider, which writes it to the log and contacts nothing. The `log` provider is never live. A fresh configuration therefore runs in dry-run mode, and so does one with a provider enabled but `sending.enabled: false`.

Each recipient's mode follows its provider. `check-config` lists the live and dry-run providers and recipients, and warns when:

- `sending.enabled` is true but no provider is enabled;
- a recipient's provider is not enabled, so messages to it are only logged.

The relay logs `"dry_run": true` in its `service.started` record, and the health document reports `dry_run`, while no provider is live.

## `vrm`

| Key | Type | Default | Bounds and rules |
|---|---|---|---|
| `base_url` | URL | `https://vrmapi.victronenergy.com/v2` | HTTPS only. |
| `token_file` | secret file path | required | A VRM access token. Always read, even in dry-run mode. See [vrm-credentials.md](vrm-credentials.md). |
| `poll_interval` | integer (seconds) | `60` | 30 to 3600. Each cycle adds up to 10% random jitter. |
| `installations` | list | required | 1 to 50 entries. |

Each installation:

| Key | Type | Rules |
|---|---|---|
| `id` | name | Your own short name, used by rules and in messages (`{installation}`). Unique. |
| `site_id` | integer | The numeric VRM installation id (`idSite`), 1 to 999,999,999. Unique. |

## `rate_limits`

| Key | Type | Default | Bounds |
|---|---|---|---|
| `global_per_hour` | integer | `20` | 1 to 200, and not more than `global_per_day`. |
| `global_per_day` | integer | `60` | 1 to 1000. |
| `retries` | integer | `3` | 0 to 10. Retries after the first attempt of one message to one recipient. |

The global cap counts real provider calls only, over sliding one-hour and one-day windows, across every rule, recipient and provider. Retries, the rate-limit summary and storage notices count against it. Dry-run messages never use it. When it is full, messages are held back and counted, and one summary goes to the system recipients later. ADR 0002, decisions 7 and 13, gives the exact rules; per-rule cooldowns and reminder limits are rule settings below.

The maximums (200 per hour, 1000 per day) are ceilings for an alerting relay, not targets. Also keep a limit at the provider (see [voipms.md](voipms.md)): it is the final backstop if the relay's own accounting fails.

## `recipients`

A mapping of up to 50 recipient names to recipients. Rules and `system_recipients` refer to these names. Nothing in VRM data, a template or a provider response can add a recipient or change where one points.

Every recipient has a `provider`: one of `voipms`, `homeassistant`, `webhook` or `log`.

| Provider | Other keys | Rules |
|---|---|---|
| `voipms` | `phone` (string, required) | A US or Canadian number: 10 digits, 11 digits starting with `1`, or `+1` and 10 digits. Spaces, `-`, `.`, `(` and `)` are ignored; the value may be at most 32 characters including them. The area code and exchange must not start with 0 or 1. Quote it, or YAML reads it as a number. Logs show only the last four digits. |
| `homeassistant` | `service` (string, required) | The Home Assistant notify service, without the `notify.` prefix: 1 to 255 lowercase letters, digits and `_`, for example `mobile_app_example_phone`. |
| `webhook` | none | Messages go to `providers.webhook.url`. |
| `log` | none | Messages are only logged. |

`check-config` warns about a recipient that no rule or `system_recipients` uses.

## `providers`

Every provider section is optional. The external providers (`voipms`, `homeassistant`, `webhook`) are disabled by default; the `log` provider has no switch and is always available. A provider's required settings must be present as soon as it is `enabled`. Its secret files are read only once it is live; `check-config` reads them for every enabled provider and reports a problem with a provider that is not yet live as a warning ("required before sending is enabled").

### `providers.voipms`

| Key | Type | Default | Rules |
|---|---|---|---|
| `enabled` | boolean | `false` | |
| `base_url` | URL | `https://voip.ms/api/v1/rest.php` | HTTPS only. |
| `username_file` | secret file path | none | Required when enabled. The VoIP.ms account login (email address). |
| `password_file` | secret file path | none | Required when enabled. The VoIP.ms **API** password, not the account password. |
| `did` | phone number (string) | none | Required when enabled. The SMS-enabled DID messages are sent from; same format as a recipient's `phone`. |

VoIP.ms has no `ca_file` or `allow_insecure_http`. Setup: [voipms.md](voipms.md).

### `providers.homeassistant`

| Key | Type | Default | Rules |
|---|---|---|---|
| `enabled` | boolean | `false` | |
| `base_url` | URL | none | Required when enabled. The Home Assistant URL, such as `https://homeassistant.example.test:8123`. `https://` unless `allow_insecure_http` is true. |
| `token_file` | secret file path | none | Required when enabled. A long-lived access token. |
| `ca_file` | file path | none | Optional. See below. |
| `allow_insecure_http` | boolean | `false` | Optional. See below. |

Setup: [home-assistant.md](home-assistant.md).

### `providers.webhook`

| Key | Type | Default | Rules |
|---|---|---|---|
| `enabled` | boolean | `false` | |
| `url` | URL | none | Required when enabled. `https://` unless `allow_insecure_http` is true. Its path is shown as `/[REDACTED]` in logs. |
| `auth_header_name` | string | none | Optional HTTP header sent with every request. A valid header name of at most 64 characters, other than `Connection`, `Content-Length`, `Content-Type`, `Host`, `Keep-Alive`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade` and `Proxy-*`. |
| `auth_header_value_file` | secret file path | none | The header's value. Set both header settings or neither, even while the provider is disabled. |
| `ca_file` | file path | none | Optional. See below. |
| `allow_insecure_http` | boolean | `false` | Optional. See below. |

The payload is described in [notifications.md](notifications.md#webhook).

### Private certificates and plain HTTP

For `homeassistant` and `webhook` only:

- **`ca_file`**: an absolute path (at most 4096 characters, with no control or line-separator characters) to a PEM file holding the CA certificate, or the self-signed certificate, of the receiver. The provider then trusts only the certificates in that file, instead of the bundled trust store. Certificate and hostname verification always stay on; nothing turns them off. `check-config` loads the file for an enabled provider and reports a file that holds no usable certificate. It is not a secret, so its file mode is not checked. With a plain `http://` URL it has no effect, and `check-config` says so.
- **`allow_insecure_http: true`**: permits a plain `http://` URL for that one provider. **The provider's token or header value, and every message, then cross the network unencrypted**, readable and alterable by anything on the path. `check-config` prints an `INSECURE` warning whenever it is on. Use it only on a network segment you control, and prefer `ca_file`. [home-assistant.md](home-assistant.md#http-https-or-a-private-ca) compares the options.

Neither setting affects redirects (never followed), timeouts or response-size limits.

### `providers.log`

`log: {}`. It has no settings and is always available.

## `rules`

A list of up to 200 rules. Each rule watches one measurement of one installation and escalates through ordered levels. The rules engine semantics are requirements R5–R11 in [requirements.md](requirements.md).

| Key | Type | Default | Bounds and rules |
|---|---|---|---|
| `id` | name | required | Unique among rules. Shown as `{rule}`. |
| `installation` | name | required | One of the `vrm.installations` ids. |
| `measurement` | mapping | required | See below. |
| `direction` | `rising` or `falling` | required | `rising` alerts as the value climbs past each threshold; `falling` as it drops. |
| `levels` | list | required | 1 to 20 levels, in escalation order. |
| `hysteresis` | number | `0` | 0 or more, in the measurement's units. |
| `clear_after_samples` | integer | `1` | 1 to 100. |
| `recovery_notify` | boolean | `true` | Send "recovered" when the rule returns fully to normal. |
| `cooldown_minutes` | integer | `15` | 1 to 1440. The same level is not sent twice within this time. |
| `reminder_interval_minutes` | integer | `60` | 1 to 10,080 (7 days). |
| `reminder_max` | integer | `3` | 0 to 20. `0` disables reminders. |
| `stale_after_minutes` | integer | `35` | 1 to 10,080, and longer than `vrm.poll_interval`. |
| `stale_notify` | boolean | `true` | Send "stale data" and "data restored". With `false` they are only logged. See [Alarms only](#alarms-only). |
| `display_unit` | `degC` or `degF` | not set | Shows a temperature measured in °C in this unit in messages. See [Display unit](#display-unit). |
| `recipients` | list of names | required | 1 to 50 configured recipient names, without duplicates. |

**`measurement`** identifies the value in the installation's VRM Diagnostics data ([vrm-credentials.md](vrm-credentials.md#find-measurement-codes) shows how to list the records):

| Key | Type | Rules |
|---|---|---|
| `code` | string | Required. The VRM attribute code, such as `tsT`: 1 to 32 letters, digits or `_`. |
| `instance` | integer | Required. The device instance, 0 to 1,000,000. |
| `service_type` | string | Optional. Matched against the record's `dbusServiceType`; needed only when code and instance match more than one record. 1 to 64 letters, digits, `_`, `.` or `-`. |

A measurement that matches no record, or more than one, produces no sample and makes the installation's poll count as failed (see [operations.md](operations.md#monitoring-degraded-and-restored)).

**`levels`**: each level has:

| Key | Type | Rules |
|---|---|---|
| `name` | name | Required. Unique within the rule. Shown as `{level}`. |
| `threshold` | number | Required, finite. For a `rising` rule each level's threshold must be greater than the previous one; for `falling`, less. |
| `message` | template | Optional. Replaces the default text for escalations into this level. |

How the timing settings work:

- **Escalation:** one notification per escalation into a level. Jumping several levels in one poll sends one notification, for the highest level reached.
- **Hysteresis and clearing:** a level clears only after the value has gone back past `threshold - hysteresis` (rising) or `threshold + hysteresis` (falling) for `clear_after_samples` consecutive samples. With `hysteresis: 0`, a value hovering at a threshold clears and re-triggers repeatedly, held back only by the cooldown, so set a non-zero hysteresis.
- **Reminders:** while the rule stays at its **highest** level, a reminder goes out every `reminder_interval_minutes`, at most `reminder_max` times per episode.
- **Stale data:** once a rule has had a sample, it reports stale data when its newest sample is older than `stale_after_minutes`, and "data restored" when samples return. The default of 35 minutes is two default GX log intervals plus margin; [vrm-credentials.md](vrm-credentials.md#how-fresh-is-the-data) explains how to tune it. With `stale_notify: false` both are still detected and logged, but not sent.

### Display unit

`display_unit` changes only how a rule's messages show its value. VRM reports temperatures in degrees Celsius, so `threshold` and `hysteresis` are always written in °C, and the rule is evaluated, cleared and deduplicated exactly as it would be without the setting.

| Value | `{value}` | `{unit}` |
|---|---|---|
| `degC` | The value in °C, rounded to and always shown with one decimal (`21.0`). | `°C` |
| `degF` | The value converted to °F, rounded to and always shown with one decimal (`36.0`). | `°F` |

Any other value is rejected when the file is loaded. The relay converts a value only when VRM reported °C (in the record's `formatWithUnit`) with that same reading. A unit from an earlier or later poll is never applied to it, so a reminder or recovery for a value whose unit is not known, such as one restored from saved state after a restart, shows the value as reported. If it reports another unit, or none, the message is still sent, with the value and unit as VRM reports them, and the relay logs a `relay.display_unit_fallback` warning. Without `display_unit`, `{unit}` stays empty and `{value}` shows up to three decimals, as before.

```yaml
rules:
  - id: cabin-freezer-warm
    installation: cabin
    measurement: {code: tsT, instance: 20}
    direction: rising
    display_unit: degF # messages say "25.7°F"; thresholds stay in °C
    levels:
      - name: critical
        threshold: -4.0 # °C
    hysteresis: 1.0 # °C
    recipients: [owner_sms]
```

### Message templates

A level's `message` is a non-empty, single-line template of at most 320 characters. It must not contain control characters (including line breaks and tabs), Unicode format characters (such as bidirectional overrides and zero-width characters), the line and paragraph separators, or private-use and unassigned code points. Braces must match. Its only placeholders are `{rule}`, `{level}`, `{value}`, `{unit}`, `{installation}`, `{measurement}`, `{label}`, `{time}`, `{kind}` and `{count}`; `{{` and `}}` are literal braces. Anything else, such as `{rule.x}`, `{value:>10}` or an unknown name, is rejected when the file is loaded. [notifications.md](notifications.md#message-templates) defines each placeholder, the default texts and how rendered text is sanitized and shortened.

## `system_recipients`

| Key | Type | Default |
|---|---|---|
| `system_recipients` | list of names | not set |

Who receives system notifications: the rate-limit summary, the storage notice, and the "monitoring degraded" and "monitoring restored" notices. If set, it holds up to 50 configured recipient names without duplicates.

When it is not set, system notifications go to every recipient used by any rule, in order of first appearance, and `check-config` adds a note saying so. With no rules and no `system_recipients`, `check-config` warns that system notifications have nowhere to go.

An empty list (`system_recipients: []`) sends system notifications to nobody: they are only logged (`monitoring.degraded`, `monitoring.restored`, `delivery.suppressed`, `delivery.storage_degraded`) and shown in [health](operations.md#health-endpoint). `check-config` warns that system problems will only be logged. Held-back alerts are still counted, but no summary is sent.

Storage notices try the system recipients in order, live ones first, and stop at the first that may have received it (ADR 0002, decision 11), so put your most reliable channel first.

### Alarms only

To be messaged only for real alarms (escalations, reminders and recoveries), set `stale_notify: false` on every rule and `system_recipients: []`:

```yaml
rules:
  - id: cabin-freezer-warm
    installation: cabin
    measurement: {code: tsT, instance: 20}
    direction: rising
    levels:
      - name: critical
        threshold: -4.0
    stale_notify: false # stale data and data restored go to the log only
    recipients: [owner_sms]

system_recipients: [] # monitoring, rate-limit and storage notices go to the log only
```

The trade-off: with both off, a GX device that stops uploading, or a VRM outage, sends **no message at all**. It shows only in the logs and in the health endpoint, and during it the relay cannot see the values it is meant to alarm on. Use this only if something else watches the logs or health, or if missing an outage is acceptable. A middle ground is to keep `system_recipients` (one "monitoring degraded" per installation per outage) and turn off only `stale_notify` (one "stale data" per rule).

## `health`

| Key | Type | Default | Rules |
|---|---|---|---|
| `enabled` | boolean | `false` | |
| `bind` | IP address | `127.0.0.1` | An IPv4 or IPv6 address (not a host name). `check-config` warns when it is not loopback. |
| `port` | integer | `8080` | 1 to 65535. |

The endpoint and its document are described in [operations.md](operations.md#health-endpoint). In a container, loopback is the container's own; [deploy-docker.md](deploy-docker.md#optional-health-endpoint) explains how to reach it.

## Secret files

Every `*_file` setting other than `ca_file` names a secret file:

| Setting | Holds | Read |
|---|---|---|
| `vrm.token_file` | VRM access token | Always. |
| `providers.voipms.username_file` | VoIP.ms account login | When VoIP.ms is live. |
| `providers.voipms.password_file` | VoIP.ms API password | When VoIP.ms is live. |
| `providers.homeassistant.token_file` | Home Assistant long-lived access token | When Home Assistant is live. |
| `providers.webhook.auth_header_value_file` | Webhook header value | When the webhook is live. |

Each path must be absolute and at most 4096 characters, with no control or line-separator characters. Each file must:

- be a regular file (not a directory, device or FIFO) of at most 4096 bytes;
- hold UTF-8 text: the secret on one line. One trailing newline (`\n` or `\r\n`) is removed; the rest must be non-empty, with no other line breaks or control characters.

A file that group or others can read draws a warning: restrict it to mode `0600` or `0400`, owned by the user the relay runs as (UID 65532 in the container image). A missing or unusable required secret stops the relay with exit code 3; problems are reported without the file's content or path. [deploy-docker.md](deploy-docker.md#4-create-the-secret-files) shows how to create these files without the secret reaching your shell history.

## Checking a configuration

```sh
vrm-alert-relay check-config --config /etc/vrm-alert-relay/config.yaml
```

It contacts no service. It prints `result: ready` when the file and every required secret file are valid, `result: valid structure` with `--structure-only` (secret and CA files are not read, so it is never "ready"), or `result: problems found` with each problem, then any warnings and notes, and a summary of installations, rules, recipients, live and dry-run providers and recipients, and system recipients. Exit codes are listed in [operations.md](operations.md#exit-codes).

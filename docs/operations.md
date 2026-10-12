# Running VRM Alert Relay

**Updated:** 2026-10-11

VRM Alert Relay is an unofficial, independent project. It is not affiliated with, sponsored by, or endorsed by Victron Energy.

This page covers the command line, the poll loop, monitoring notifications and the health endpoint. Requirements R1, R10, R18 and R24–R28 in [requirements.md](requirements.md) set the rules; ADR 0002 covers delivery and state storage.

## Command line

```text
vrm-alert-relay run [--config PATH] [--state-dir DIR] [--log-level LEVEL] [--once]
vrm-alert-relay check-config [--config PATH] [--structure-only]
vrm-alert-relay test-notification --recipient NAME [--config PATH] [--state-dir DIR] [--log-level LEVEL]
vrm-alert-relay --version
```

| Setting | Flag | Environment variable | Default |
|---|---|---|---|
| Configuration file | `--config` | `VRM_ALERT_RELAY_CONFIG` | `/etc/vrm-alert-relay/config.yaml` |
| State directory | `--state-dir` | `VRM_ALERT_RELAY_STATE_DIR` | `/var/lib/vrm-alert-relay` |
| Log level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) | `--log-level` | `VRM_ALERT_RELAY_LOG_LEVEL` | `INFO` |

A flag wins over its environment variable. The container image runs `run` by default.

- **`run`** starts the relay. It logs one JSON object per line to standard output, starting with a `service.started` record whose `dry_run` field is `true` unless some provider is live. `--once` runs a single poll cycle and exits, which is useful for a first test of a new configuration.
- **`check-config`** validates the configuration and the secret files it references, without contacting any service, and prints a report. Recipient names that look like phone numbers (five or more digits) are shown by position, such as `[#3]`, everywhere the relay prints or logs a recipient name. `--structure-only` skips the secret files; its result is never "ready".
- **`test-notification --recipient NAME`** sends one test message to one configured recipient and prints the outcome. It sends only when you run it, goes through the delivery engine like any alert (so the global cap, dry-run routing, attempt records and reconciliation all apply), and sends nothing else that is waiting. While sending is disabled for the recipient's provider, the message is only written to the log. It needs the state directory, so stop the relay first: a running relay holds the directory's lock.

### The state directory

The state directory must be on a local filesystem, owned by the relay user and writable by nobody else (ADR 0002). The image runs as UID and GID 65532 and ships `/var/lib/vrm-alert-relay` owned by `65532:65532` with mode `0700`.

- **Named volume (recommended):** mount it at `/var/lib/vrm-alert-relay`. Docker initialises a new named volume from the image, so it starts with the right owner and mode.
- **Bind mount:** Docker does not change a host directory's ownership. Create it first and give it to UID 65532, for example `install -d -o 65532 -g 65532 -m 0700 /srv/vrm-alert-relay/state`. If you run the container with another `--user`, the directory must belong to that UID instead.
- A directory the relay cannot write leaves it running and alerting from memory, with `state_persistence.healthy` false and a storage notice to the system recipients. A directory that group or others can write draws a warning in the log.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. `run` stopped normally (also after SIGTERM or SIGINT); `check-config` found no problems; `test-notification` delivered the message (or logged it in dry run). |
| 1 | `test-notification`: the message was not delivered, or its outcome is unknown. The output says which: held back by the global cap, refused by the provider, or awaiting reconciliation or retry. |
| 2 | Invalid command line, including an invalid `VRM_ALERT_RELAY_LOG_LEVEL`. |
| 3 | The configuration, a required secret file or a provider setting is unusable, or `--recipient` names no configured recipient. |
| 4 | Another relay process holds the state directory. |

Every other storage problem (an unreadable, corrupt or unwritable database, an unsafe state path) leaves the relay running and alerting under limits kept in memory, as ADR 0002 requires; health and the logs report it.

## The poll loop

Each cycle:

1. polls every configured installation once (one Diagnostics request each, R1);
2. evaluates every rule with its measurement's sample, or with no sample when there is none, so stale data is still detected;
3. evaluates each installation's monitor (below);
4. renders each event's text from its template and hands the cycle's rule states and notifications to the delivery engine in one transaction;
5. delivers whatever is due.

Cycles start the configured `vrm.poll_interval` apart, plus up to 10% random jitter, so never more often than the interval. A long cycle is followed by the next one at once. VRM backoff (on errors, 429 `Retry-After`, and the hourly retry after a 401 or 403) is per site and enforced by the VRM adapter: while a site backs off, cycles skip its request but still check staleness, monitoring and pending deliveries.

A failure inside a cycle never stops the relay. An unexpected error from the poll counts as a failed poll of every installation; an error evaluating one rule is retried from fresh rule state (which may repeat an active alert, never lose one); an error rendering a level message falls back to the default text.

A rule that has never had a usable sample reports neither stale data nor its restoration: until its first sample it is not evaluated without one, and acquisition problems are reported by the installation's monitor instead. A fresh installation with VRM unreachable therefore sends only "monitoring degraded". From its first sample on (remembered in the rule's stored state, so across restarts too), a rule reports stale data when its newest sample is older than `stale_after_minutes`, and "data restored" when samples return.

**Shutdown:** SIGTERM or SIGINT lets the cycle in progress finish (its HTTP calls are bounded by timeouts), then the relay stops the health endpoint, writes pending state and closes the state store.

## Monitoring degraded and restored

Each installation has a monitor. Its notifications go to `system_recipients` (or, when that is not set, to every recipient used by a rule):

- `VRM Alert Relay: monitoring of <installation> is degraded since <time>; alerts may be delayed or missed`
- `VRM Alert Relay: monitoring of <installation> is restored (<time>)`

A poll of an installation **fails** when its Diagnostics could not be fetched (authentication, rate limiting, unavailability, a bad or rejected response), including cycles in which the request is skipped because the installation is still backing off, or when any configured measurement of it produced no usable sample (missing, ambiguous, non-numeric, or with an unusable timestamp). Measurement problems count because a measurement that silently stops reporting is exactly what monitoring must surface.

One bound decides whether a sample is usable: a reading stamped more than 60 seconds after the relay's clock is reported as a future timestamp by the VRM parser, the same limit the rules engine applies, so a skewed GX or host clock shows up as "monitoring degraded" instead of silently suppressing alerts. As a second line of defence, any sample the rules engine still cannot use, a reading older than the rule's newest one (a device clock that jumped back), and a rule that cannot be evaluated at all also count as a failed poll of its installation. Seeing the same reading again, because the device has not logged a new value yet, is normal and does not count.

An installation becomes **degraded**:

- after **2 consecutive failed polls**, so a single failed request does not page anyone;
- at once on an **authentication failure (401, 403) or a rejected request (other 4xx)**, which do not heal by themselves; the adapter retries those hourly.

It is **restored** by the first poll that fetches it with every measurement usable.

One "degraded" goes out per outage and one "restored" when it ends. Both the outage (key `monitoring:<installation>`) and the failure streak behind it (key `monitoring-streak:<installation>`: the count of consecutive failed polls, at most 1,000,000, and the time of the first) are stored, so a restart neither sends "degraded" again, nor forgets to send "restored", nor restarts the count: a restart between the first and second failed poll still reports the outage on the second, with the first failure's time. If the stored streak cannot be read, it counts as one failure already seen, so the next failed poll reports the outage. A new outage that starts within 15 minutes of the last "degraded" is announced only if it is still open when those 15 minutes are up, which bounds a flapping connection. Both notifications count against the global cap like any message.

## Health endpoint

Enable it with `health.enabled: true`. It listens on `health.bind` (default `127.0.0.1`, loopback) and `health.port` (default 8080). `check-config` warns when the address is not loopback. If the port cannot be bound, the relay logs an error and keeps running without it.

`GET /health` (or `/`) returns a small JSON document, always with status 200: the endpoint is informational, not a gate. `HEAD` returns the headers only, other paths 404, other methods 501. No CORS headers are sent and requests are not logged. The document holds no secrets, recipient names or addresses, installation or site ids, or message text. It is refreshed after every cycle. Its `status` is `starting` until the first cycle completes, and never `ok` before then.

```json
{
  "schema": 1,
  "status": "ok",
  "version": "0.1.0",
  "dry_run": true,
  "started_at": "2026-01-15T12:00:00+00:00",
  "monitoring": {
    "status": "ok",
    "cycles": 42,
    "last_cycle_failed": false,
    "last_cycle_at": "2026-01-15T12:41:03+00:00",
    "last_successful_poll_at": "2026-01-15T12:41:03+00:00",
    "installations": 1,
    "failing_installations": 0,
    "degraded_installations": 0
  },
  "state_persistence": {
    "healthy": true,
    "durable_accounting": true,
    "error": null
  },
  "delivery": {
    "queued": 0,
    "suppressed_pending": 0,
    "suppressed_total": 0,
    "sent_last_hour": 0,
    "sent_last_day": 0,
    "would_send_last_hour": 2,
    "would_send_last_day": 5,
    "would_send_over_cap_total": 0
  }
}
```

| Field | Meaning |
|---|---|
| `status` | `degraded` when the latest cycle failed, any installation is degraded, or state persistence is not healthy and durable; otherwise `starting` until the first cycle completes, then `ok`. |
| `monitoring.cycles` | Cycles completed since the relay started. |
| `monitoring.last_cycle_failed` | Whether the latest cycle stopped with an unexpected error. |
| `dry_run` | `true` when no provider is live. |
| `monitoring.last_successful_poll_at` | The last cycle in which every installation was fetched (measurement problems aside). |
| `monitoring.failing_installations` | Installations whose last poll failed. |
| `monitoring.degraded_installations` | Installations with an open outage. |
| `state_persistence.healthy` | False while storage fails, and for the rest of the run after corrupt state was found. |
| `state_persistence.durable_accounting` | False in every ADR 0002 failure mode, when the cap is enforced in memory only. |
| `state_persistence.error` | A short description of the latest storage problem, without file paths. |
| `delivery.suppressed_pending` | Held-back deliveries not yet reported in a summary. |
| `delivery.sent_last_hour`, `sent_last_day` | Real provider calls in the sliding cap windows. |
| `delivery.would_send_*` | Dry-run sends, counted against the cap but never enforced. |

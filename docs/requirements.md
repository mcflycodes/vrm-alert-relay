# VRM Alert Relay requirements

**Updated:** 2026-10-11
**Status:** Accepted

Product requirements for the first release (v1).

## Problem and users

VRM's native alarms notify once per condition through Victron's own channels. Operators monitoring conditions that worsen gradually (a tank approaching freezing, a refrigerator warming, a battery drifting) need staged escalation, reminders while a condition stays critical, stale-data warnings, and delivery over channels VRM does not offer: SMS through an operator-owned provider account, Home Assistant, or any HTTP endpoint.

Users are technically capable people who self-host one instance for their own installations. Multi-tenant hosting is not planned.

## Design principles

- **Fail toward alerting.** When something breaks, the relay keeps trying to tell the operator, rather than going silent. Duplicates are tolerated in rare failure cases but are always hard-capped.
- **The operator is trusted; data is not.** Everything that selects a destination (recipient, provider, URL) comes only from the operator's configuration. VRM data, labels, templates, and provider responses can never change where a message goes.
- **Safe by default.** Fresh installs run in dry-run mode.

## Must-haves (v1)

### Acquisition
- R1. Poll configured numeric measurements from the VRM API v2 at a configurable interval (default 60 s, minimum 30 s, jittered), one Diagnostics request per installation per cycle.
- R2. Support multiple installations, devices, and measurements; identify a measurement by attribute code + device instance (+ service type when needed), never by position or numeric attribute ID alone.
- R3. Authenticate with a VRM personal access token read from a secret file. Docs recommend a dedicated VRM user invited only to the monitored installations with the lowest role that works.
- R4. Honour HTTP 429 / `Retry-After`; back off on errors with bounded, jittered exponential delay; do not retry 401/403 as transient.

### Rules engine (independent of VRM and providers)
- R5. Rising and falling threshold ladders: each rule has ordered levels (e.g. `warning`, `alert`, `critical`), each with a threshold and message.
- R6. Exactly one notification per escalation into a level; jumping several levels in one poll sends one notification for the highest level reached.
- R7. Hysteresis per rule: a level clears only after the value retreats past threshold ± hysteresis, optionally for N consecutive samples.
- R8. Recovery notification when the rule returns fully to normal (per rule, default on).
- R9. Bounded critical reminders: configurable interval and maximum count per episode (defaults 60 min, 3).
- R10. Stale-data event when a measurement's timestamp is older than a configurable age (default 35 min, i.e. two default GX log periods plus margin; docs explain tuning to the GX log interval), and one "data restored" event. A polling-failure streak sends one "monitoring degraded" notification per outage and one "restored" notification.
- R11. Per-rule cooldown (default 15 min) so oscillation around a threshold cannot send the same level twice within the cooldown.
- R12. Evaluation is pure and deterministic: (previous state, sample, clock) → (new state, events), unit-testable without I/O.

### State and delivery
- R13. Persistent state (rule levels, episodes, reminder counts, last-sent times, rate-limit counters, pending deliveries) in a local SQLite file survives restart. Re-evaluating an unchanged condition after a restart sends nothing.
- R14. Each event has a stable identity (rule, episode, level, kind); delivery is tracked per (event, recipient).
- R15. Delivery fails toward alerting: the relay records a delivery as in-flight before sending; after an ambiguous outcome (timeout, crash), it reconciles with the provider when the provider supports a lookup (VoIP.ms `getSMS`) and otherwise retries. A rare duplicate after a crash is accepted.
- R16. Rate limits: one global cap (defaults 20/hour, 60/day), per-rule cooldowns (R11), and the critical-reminder cap (R9). Retries count against the global cap. When the cap is hit, held-back events are counted and logged, and one "N alerts suppressed" summary is sent when the window reopens.
- R17. Bounded retries (default 3) with exponential backoff and jitter.
- R18. Failures never go silent: VRM fetch/parse failures and stale data produce the degraded notification (R10); a failure to persist state is logged loudly, surfaced in health, and delivery continues with in-memory duplicate suppression, still bounded by the global cap.

### Providers
- R19. A provider interface; no provider-specific logic in the core. Each provider is an in-tree adapter with its documented default endpoint, which the operator may override in configuration (HTTPS only).
- R20. v1 providers:
  - `log`: dry-run; records what would be sent.
  - `voipms`: VoIP.ms SMS. Credentials from secret files; credentials sent in a multipart POST body if verified, otherwise GET with the URL never logged; success only when the JSON `status` is `success`; messages trimmed to 160 characters.
  - `homeassistant`: calls a configured Home Assistant `notify` service with a long-lived token from a secret file. Docs recommend a dedicated non-admin HA user and include example setups.
  - `webhook`: POSTs a fixed, documented JSON payload to an operator-configured HTTPS URL with optional header-based auth from a secret file.
- R21. Outbound HTTP for every provider and VRM: HTTPS only, certificate verification on, no redirects followed, connect/read timeouts, response-size cap. URLs come only from operator configuration or adapter defaults. Private network destinations are allowed (local Home Assistant, ntfy).

### Recipients and messages
- R22. Recipients are defined only in operator configuration and referenced by name from rules; nothing from VRM data, labels, templates, or events can add or change a recipient or destination.
- R23. Message templates use a restricted placeholder syntax (no expressions or attribute access) over a fixed set of fields; output is length-bounded and stripped of control characters; untrusted strings (VRM labels) are sanitized and truncated.

### Safety defaults and configuration
- R24. Dry-run by default: real sending requires both a global `sending.enabled: true` and a per-provider enable; otherwise everything routes to `log`.
- R25. One YAML configuration file (safe loader, strict schema, unknown keys rejected, sizes bounded), validated at startup and by a `check-config` command. Secrets are referenced as file paths, never inline.
- R26. A `test-notification` command sends one message to one named recipient only when explicitly invoked, subject to the global cap.

### Operations
- R27. Structured JSON logs. Never log secrets, authorization headers, or full request URLs; phone numbers show only the last four digits.
- R28. Optional health endpoint: informational only, loopback-bound by default, no secrets or recipient data; reports last successful poll, state-persistence health, and suppression counts.
- R29. Container: distroless base, non-root UID, read-only root filesystem, single writable state volume, all capabilities dropped, `no-new-privileges`, secrets as mounted files, no Docker socket. A documented Compose file applies all of these.
- R30. Supply chain: every PR builds the image, scans it, and produces an SBOM. HIGH/CRITICAL findings with an available fix block; unfixed findings are reported without blocking. `main` is re-scanned weekly, base-image updates arrive as automated pull requests, and published images are signed.
- R31. No telemetry; no outbound requests other than VRM and configured providers.

### Quality
- R32. Tests:
  - rules engine: unit tests plus property-based tests that search for double or missed alerts; near-100% coverage;
  - integration tests against mocked VRM, VoIP.ms, Home Assistant, and webhook servers;
  - named scenarios: restart sends no duplicates, ambiguous send is reconciled before retry, global cap holds under a flood, malicious labels/responses/templates cannot alter recipients or inject content, state-persistence failure keeps alerting;
  - overall coverage ≥ 85%;
  - all fixtures fictitious.

## Non-goals (v1)

- Inbound commands, SMS replies, or acknowledgements.
- A web UI, multi-tenant hosting, or user accounts.
- Writing anything to VRM or controlling devices.
- Replacing VRM native alarms or any safety device.
- Third-party plugin packages (the provider interface leaves room for them later).
- Google Voice (no official API).
- Quiet hours and on-call schedules.

## After v1 (roadmap candidates)

- Publish relay state to Home Assistant as sensors (MQTT discovery): rule levels, stale status, relay health. First post-v1 item.
- Additional providers: Twilio, RingCentral, ntfy, others via contribution.

## Success criteria

- All gates green in CI; every code PR independently cross-reviewed; no unresolved security findings.
- A documented Compose deployment that starts in dry-run with zero code changes.
- A dry-run soak of at least 7 days against real VRM data on a real installation with no spurious or duplicate events, then one maintainer-approved live message per provider used.

## Assumptions and open items

- The lowest VRM role that can read Diagnostics through the API is unverified (the read-only `User` role may be refused). Operators should test with a dedicated user; the code works with any role that can read Diagnostics.
- VoIP.ms multipart POST support is community-reported, not documented; covered by mocked tests and confirmed in live testing before release.
- VoIP.ms treats automated alerts as A2P traffic; the operator completes VoIP.ms messaging verification before live use.

# 0004 Notification opt-outs

**Updated:** 2026-10-12
**Status:** Accepted
**Date:** 2026-10-12

## Context

Some operators want messages only for real alarms. In 0.1.0, a GX device that stops uploading sends one "stale data" message per rule and later one "data restored" per rule, and system notifications always go to a recipient. ADR 0002 says failures favour alerting, so any way to send less must be explicit, visible, and unable to silence an alarm.

## Decision

- A rule's `stale_notify: false` stops its stale-data and data-restored messages, and `system_recipients: []` stops system messages (monitoring degraded and restored, the rate-limit summary, the storage notice). Both are opt-in; the defaults are unchanged. Stale data and monitoring are still evaluated exactly as before, and what is not sent is logged and shown in health. `check-config` warns about an empty `system_recipients`.
- The opt-outs apply when a message is due, not only when it is queued, so a message queued before a restart under a configuration that sent it is not sent afterwards. Each delivery record stores its origin (alarm, reminder, recovery, stale, restored or system) in a new nullable column (schema version 2) and in the journal. A due stale or restored record whose rule now opts out, or no longer exists, and a due system record while `system_recipients` is empty, are finished without a send and logged as `delivery.suppressed_by_config`.
- Alarms, reminders and recoveries are never dropped by configuration. A record with no stored origin (written by 0.1.0, or unreadable) is always sent.
- A failure while evaluating the monitors, or while logging a monitoring notice, must not stop the rules' alarms from the same cycle: monitoring is evaluated in isolation, its failure is logged and shown in health, and its log records are dropped if they cannot be written.

## Consequences

- With both opt-outs on, a GX or VRM outage sends no message at all; the operator relies on logs and health. The documentation says so where the settings are described.
- 0.1.0 cannot read a state database upgraded by 0.1.1; a rollback restores the backup taken before the upgrade, as for any schema change.

# 0002 Delivery semantics

**Updated:** 2026-10-11
**Status:** Accepted
**Date:** 2026-10-11

## Context

ADR 0001 sets the failure policy: fail toward alerting, and tolerate rare duplicates as long as they are always hard-capped. The delivery engine and state store have to turn that policy into exact rules. A review of the first implementation showed the rules must also hold when SQLite cannot be written or read, when the process restarts during an outage, when stored rows are corrupt, when the wall clock jumps, and when two processes share a state directory.

## Decisions

1. **One delivery per (event, recipient).** Each delivery is a record with one of these statuses: `PENDING`, `IN_FLIGHT`, `AMBIGUOUS`, `DELIVERED`, `FAILED` or `SUPPRESSED`. The last three are terminal. A delivery that already exists is never queued again.

   Before every provider call the record moves to `IN_FLIGHT` with an incremented attempt count. The provider's result then moves it to:
   - `DELIVERED`;
   - `FAILED`, when the provider rejected the message;
   - `PENDING` with a backoff, when the failure is retryable and attempts remain;
   - `AMBIGUOUS`, when the outcome is unknown. An exception from the provider, or a malformed result, also counts as unknown.

   Retries are bounded: one attempt plus `rate_limits.retries` (3 by default). Backoff is exponential from 30 seconds up to 15 minutes, with half of each delay random.

2. **Reconcile before retry.** An `AMBIGUOUS` record is checked with the provider before any retry, if the provider supports a lookup. So is an `IN_FLIGHT` record found at startup, which means the process stopped mid-send.
   - If the lookup reports the message as delivered, the record becomes `DELIVERED` without a send.
   - If the lookup reports it as not delivered, or cannot tell, the message is retried.
   - Providers without a lookup always retry.

3. **No provider call without a durable attempt.** The `IN_FLIGHT` record and its attempt mark must reach durable storage before the provider is called. SQLite is tried first. If that fails, the attempt goes to an append-only journal next to the database.
   - **Writing:** the journal is opened with `O_APPEND` and `O_NOFOLLOW` and kept at mode 0600. Each line is written with `fsync` before the call it records.
   - **Format and size:** each line is one JSON object, validated when read. The file rotates to one previous generation at 4 MiB.
   - **Startup:** the journal is replayed into rate limiting and duplicate suppression before anything is sent.
   - **Recovery:** the next successful SQLite transaction merges the journal into the database, and the journal is then deleted.
   - **Outcomes:** they are written the same way, best effort.

4. **No durable accounting.** If neither SQLite nor the journal can record an attempt, the relay makes no real provider call except one "state storage unavailable" notice per process. The notice goes to one system recipient, a live one when there is one. Until storage works again, the relay logs an error on every run and reports itself unhealthy. The same holds while the stored send history cannot be read, because the cap cannot be enforced without it. The relay tries to read the history again on every run.

5. **A failed load is not an empty database.** If the database cannot be read at startup, the store is marked unhealthy, the file is left untouched, and whatever can be read is used. That includes each readable table and the journal.

6. **Corruption fails closed for sending and open for alerting.**
   - An unreadable send-attempt row, or an unreadable journal line, occupies one slot for a full 24-hour window from load time. The row is rewritten in a readable form so that it ages out normally.
   - An unreadable unfinished delivery is never dropped:
     - If its event and recipient can be read, it is recovered as `AMBIGUOUS` and goes through reconcile-then-retry.
     - Otherwise, if its rule can be read, that rule's stored state is reset so its next evaluation raises the alert again.
     - Otherwise, it is counted as held back and reported in the next summary.
   - Any corruption marks persistence unhealthy for the rest of the run and is logged as a count, not as content.

7. **The cap counts real provider calls only, over sliding windows.** The global cap is 20 per hour and 60 per day by default. It counts every real provider call: first attempts, retries, summaries and the storage notice. Each call occupies a slot from its time until one hour (or one day) later, so no 60-minute or 24-hour interval holds more than the cap. Slots are persisted and reloaded at startup.

   Dry-run and `log` sends never use the cap. They are counted against a separate "would send" cap that is reported in health and never enforced, so a dry-run soak still shows what the cap would have done.

8. **Clock discontinuities.**
   - **While running:** windows, backoff and the summary interval use monotonic time, so changing the wall clock frees no capacity.
   - **What is stored:** wall-clock times, plus the latest wall time seen.
   - **At startup**, stored times are interpreted conservatively:
     - An attempt stamped later than now counts as happening now.
     - If the clock moved backwards since the latest time seen, no attempt is pruned by age.
     - A stored retry time further ahead than the maximum backoff is due immediately.
     - Age-based pruning of finished deliveries uses the later of now and the latest time seen.

9. **One process per state directory.** At startup the relay takes an exclusive, non-blocking `flock` on a lock file in the state directory. It does so before migrating or loading. A second process fails at startup with a clear error. Migrations re-read the schema version after taking the database write lock.

10. **State paths are checked.**
    - The state directory must be a real directory, not a symlink. A directory that group or others can write draws a warning.
    - Every state file is opened without following symlinks, must be a regular file, and is set to mode 0600. That covers the database, its WAL and SHM files, the journal and the lock file.
    - A symlinked or irregular state path stops the relay at startup. Later in the run, the same problem is treated as a storage failure.

11. **System recipients.** System notifications go only to `system_recipients`. These include the rate-limit summary, the storage notice and future monitoring notices. The field is optional; its names must be configured recipients. When it is omitted, the default is every recipient used by any rule, in order of first appearance, and `check-config` says that the default applies. No recipient is ever derived from an event, a delivery record or a provider response.

12. **Summaries never compete with real alerts.** A delivery that finds the cap full becomes `SUPPRESSED` and is counted. Overflow of the delivery queue is counted the same way.
    - **One summary:** it is a single aggregate event, "N alerts held back by the global rate limit since …", sent to the system recipients.
    - **When it is sent:** only when no real alert is due and the cap has room, and at most once per hour.
    - **When the count clears:** once a summary is delivered, the count it reported is subtracted. If the summary is itself held back or fails, the count keeps growing for the next one.

13. **Logging.** Logs name recipients only as `check-config` displays them. A name with five or more digits appears as its position, such as `[#3]`.

## Alternatives considered

- **Send anyway when no attempt can be recorded** (rejected). This is what the first implementation did. Every restart during an outage could then send again, which defeats both duplicate suppression and the cap.
- **Hold real alerts without any notice while storage is unavailable** (rejected). The relay would go silent. One unaccounted notice per process tells the operator, while staying bounded.
- **Fixed windows for the cap** (rejected). They allow up to twice the cap across a window boundary.
- **One summary per recipient** (rejected). The number of summaries then grew with the number of recipients, and summaries could take capacity away from real alerts.
- **Counting dry-run sends against the cap** (rejected). A dry-run or log recipient would then take capacity from live ones.

## Accepted risks

- **Duplicates after a crash.** A message can be sent twice when the process stops between a send and its recorded outcome and the provider has no lookup. It is capped like any other send.
- **One notice per restart.** Each process may send one storage notice while nothing can be recorded. A restart loop during an outage can therefore send one notice per restart. Provider-side limits, such as an SMS provider's daily cap, are the final backstop.
- **Rule state is not journaled.** If SQLite cannot be written and the process restarts, rule state starts fresh. An active condition may then be reported again under a new event identity, within the cap.
- **A forward clock jump across a restart.** If the wall clock jumps forward and the process restarts before the jump is corrected, stored attempts look older than they are and may free slots early. Without a trusted clock this cannot be detected.
- **Journal rotation drops the oldest generation.** At very high volume during a long outage this loses evidence, which is bounded by the size limit.
- **A permanently unreadable database holds real alerts.** They stay held, after one notice, until the operator repairs or moves the file. Not knowing the send history is treated like having no durable accounting.

## Consequences

- C6 providers implement `Provider.send`, and `ReconcilingProvider.reconcile` when the service offers a lookup. Neither can name a destination.
- C7 builds the engine from configuration with a real clock, and reports the engine's health fields. It sends monitoring notices to the system recipients through the same pipeline, so they are capped and deduplicated like everything else.

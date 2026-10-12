# 0002 Delivery semantics

**Updated:** 2026-10-11
**Status:** Accepted
**Date:** 2026-10-11

## Context

ADR 0001 sets the failure policy: fail toward alerting, and tolerate rare duplicates. The delivery engine and state store have to turn that policy into exact rules. Two reviews of the first implementations showed that the rules must also cover these cases:

- SQLite cannot be written or read.
- The process restarts during an outage.
- Stored data is corrupt or oversized.
- The wall clock jumps.
- State paths are tampered with.
- Two processes share a state directory.

The first review led to a design that held real alerts whenever the send history was uncertain. The maintainer rejected that trade-off, and the rule below replaces it.

## The rule: every failure favours alerting

Wherever a choice trades alerting against strictness, the relay favours alerting.

- **In normal operation**, including ordinary crashes and restarts, the global cap is hard.
- **In rare failure modes**, the relay keeps alerting under limits it enforces in memory. It reports itself unhealthy, logs an error on every run, and relies on provider-side limits as the final backstop. These failure modes are:
  - unreadable, corrupt or unwritable storage;
  - unsafe state paths;
  - clock jumps.
- **Nothing may hold a real alert** because the send history is uncertain.

The only startup failure that stops the relay is a second process on the same state directory, because the first process is already alerting.

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

3. **Record before sending, best effort.** Before the provider is called, the relay tries to make the `IN_FLIGHT` record and its attempt mark durable. SQLite is tried first, then an append-only journal next to the database.
   - **If neither can record it, the message is sent anyway.** The attempt still counts against the in-memory cap. The relay marks itself unhealthy, logs an error on every run, and sends a storage notice (decision 11). A run report counts every real provider call as sent, and those that could not be recorded again as a subset.
   - **Journal writes:** the journal is opened with `O_APPEND` and `O_NOFOLLOW` and kept at mode 0600. Each line is written with `fsync` before the call it records. Each line is one JSON object, validated when read.
   - **Other changes:** every other change to a delivery reaches the journal too when SQLite fails, keyed by delivery identity. That includes outcomes, deliveries held back by the cap or by queue overflow, and summary acknowledgements.
   - **Startup:** the journal is replayed into rate limiting, duplicate suppression and the held-back count.
   - **Replay applies each change once.** A delivery counts as held back once, unless the database already shows it held back. A delivered summary subtracts what it reported only when that is provably not yet done: the database does not show it delivered, and it is the database's open summary or was delivered after the database was last written. Otherwise nothing is subtracted, and the count errs high.
   - **Recovery:** the next successful SQLite transaction merges the journal, and then the journal is deleted.

4. **The journal never discards recent evidence.** When the journal reaches its size bound (4 MiB), it is compacted rather than rotated. Compaction atomically rewrites it to:
   - the latest line for each delivery;
   - every attempt line younger than 24 hours.

   An unreadable line becomes a dated placeholder that keeps its slot for 24 hours. The compacted size is bounded at about 62.5 MiB, which holds four days of attempt lines at the largest valid daily cap and the longest possible line. If a failure mode ever produces more, the newest evidence is kept, and the loss is logged.

5. **An unreadable database never holds alerts.**
   - **Corrupt:** SQLite reports a malformed file or one that is not a database.
     - Every table that can still be read is salvaged.
     - The file and its sidecars are renamed to `relay-state.sqlite3.corrupt-<UTC time>`, kept at mode 0600, and never overwritten. Every source is checked first, and the name is chosen clear for the database and every sidecar. Each move refuses to replace a file: a hard link and then an unlink, or, where the filesystem has no hard links, a rename after checking the name. If the unlink fails, the new link is removed again.
     - If a move fails part way, the failure is logged with the files already moved, the relay stays unhealthy and keeps alerting, and the database is read again on the next cycle.
     - A fresh database is created. The relay rewrites everything it holds into it: salvaged rows, the journal, and its own state.
     - The missing history does not fill the cap. Only the attempts that were actually salvaged hold slots.
     - The relay is unhealthy for the rest of the run, and a storage notice goes out.
     - A summary in progress whose deliveries were lost is forgotten. Its count stands and is summarised again, after the usual wait.
   - **Otherwise unreadable:** permission or I/O errors, a lock, an unsafe path, or a schema from a newer release.
     - The file is left untouched, and nothing is written to it.
     - The relay runs on the journal and in-memory state, and keeps alerting.
     - While the database or the journal cannot be read, every cycle reads both again as one snapshot. Once both can be read, the stored state is merged in; anything read before then is merged too, and the reads continue. Slots this process already holds keep their monotonic time.
     - Held-back counts are merged by delivery identity, not by adding counters. They count as unread while either the database or the journal is unreadable, and the relay keeps its record of identities for that whole time. The stored count already covers the deliveries the database shows held back, and already excludes what the summaries it shows delivered reported. Only what this process counted beyond those is added or subtracted, so a delivery that both the database and the journal recorded is counted once.
     - A newer schema is never quarantined.
   - **Each table is read in its own transaction,** so one failing table hides nothing else.

6. **Corrupt rows fail toward alerting.**
   - **Unreadable send-attempt rows and journal lines:** each one occupies one slot for 24 hours from load time, because it records a send that may have happened. The row is rewritten in a readable form so it ages out normally.
   - **Unreadable unfinished deliveries** are never dropped:
     - If the event and recipient can be read, the delivery is recovered as `AMBIGUOUS` and marked recovered. It is owed one reconcile-then-retry, whatever its stored attempt count says, and the mark is stored so a restart keeps it. The retry is numbered past every stored attempt of that delivery, so its attempt record is new cap evidence, not a duplicate of an old one. After that retry the normal attempt ceiling applies.
     - Otherwise, if its rule can be read, that rule's stored state is reset so its next evaluation raises the alert again.
     - Otherwise, it is counted as held back and reported in the next summary.
   - **Oversized cells:** no stored cell is read beyond its bound. The size check reads the length from the record header, so an oversized cell is never loaded, and its row counts as corrupt. The bounds are four bytes per character of each field's limit.
   - **Reporting:** corruption marks the store unhealthy for the rest of the run, and is logged as a count, not as content.

7. **The cap counts real provider calls only, over sliding windows.**
   - **Defaults:** 20 per hour and 60 per day. Configuration allows at most 200 per hour and 1,000 per day, which are sane ceilings for an alerting relay and the size the journal is built for.
   - **What counts:** every real provider call, including first attempts, retries, summaries and storage notices.
   - **Sliding windows:** each call occupies a slot from its time until one hour (or one day) later, so no 60-minute or 24-hour interval holds more than the cap. Slots are persisted and reloaded at startup.
   - **Dry-run and `log` sends** never use the cap and are never stored, so they can never displace evidence of a real send. They are counted against a separate "would send" cap that is reported in health and never enforced.

8. **Clock discontinuities.**
   - **While running:** windows, backoff and the summary interval use monotonic time, so changing the wall clock frees no capacity. This includes merging a history that could not be read at startup, because slots already held keep their monotonic time.
   - **What is stored:** wall-clock times, plus the latest wall time seen.
   - **At startup**, stored times are interpreted conservatively:
     - An attempt stamped later than now counts as happening now.
     - If the clock moved backwards since the latest time seen, no attempt is pruned by age.
     - A stored retry time further ahead than the maximum backoff is due immediately.
     - Age-based pruning of finished deliveries uses the later of now and the latest time seen.

9. **One process per state directory.**
   - **The lock:** at startup the relay takes an exclusive, non-blocking `flock` on a lock file in the state directory, before migrating or loading.
   - **A second process** fails at startup with a clear error.
   - **Lock file identity:** the lock file is checked to still be the locked file after locking and on every new database connection. If it was replaced, storage is treated as unavailable.
   - **Migrations** re-read the schema version after taking the database write lock.
   - **The state directory must be on a local filesystem.** `flock` and SQLite's WAL mode are not reliable on NFS and other network filesystems.

10. **State paths are checked, and a bad path makes storage unavailable.**
    - **The directory:** it must be a real directory, not a symlink. A directory that group or others can write draws a warning, not a refusal.
    - **Every state file:**
      - It is opened without following symlinks and must be a regular file.
      - It must be at mode 0600. A file that cannot be restricted to 0600 is not used.
      - This covers the database, its sidecars, the journal and the lock file.
    - **The database identity:** SQLite must open the file that was validated. After connecting, the relay checks that the database path is still that file, by device and inode, and that every file SQLite opened is that file.
    - **What happens on failure:** a refused path, or a failed identity check, makes that storage unavailable. The relay keeps alerting from memory (and the journal when it is usable). It never exits for this.

11. **Storage notices.** A notice goes to the system recipients when any of these happen:
    - an attempt could not be recorded anywhere;
    - the stored state could not be read;
    - the database was replaced.

    How notices are sent:
    - **Order:** recipients are tried in configured order, live ones first.
    - **Failover:** a definite failure from the provider moves on to the next recipient. Delivery, or an unknown outcome, ends the notice, because it may have arrived.
    - **Reporting:** the real outcome is reported.
    - **Capacity:** a notice waits for a free slot in the cap.
    - **Frequency:** at most one notice per 24 hours, counted from the notice's first provider call, not from when it started waiting for a slot. Each notice is recorded like any send, so after a restart a notice is not repeated when storage could record it. When nothing can be recorded, each process start may send one.
    - **After a restart:** a notice is never resent.

12. **System recipients.** System notifications go only to `system_recipients`: the rate-limit summary, the storage notice, and future monitoring notices.
    - The field is optional, and its names must be configured recipients.
    - When it is omitted, the default is every recipient used by any rule, in order of first appearance, and `check-config` says that the default applies.
    - No recipient is ever derived from an event, a delivery record or a provider response.

13. **Summaries give way to real alerts, for at most an hour.** A delivery that finds the cap full becomes `SUPPRESSED` and is counted. Overflow of the delivery queue is counted the same way.
    - **One summary:** it is a single aggregate event, "N alerts held back by the global rate limit since …", sent to the system recipients. It records how many held-back deliveries it reports.
    - **When it is sent:** at most once per hour. Real alerts take free slots first, but once a summary has waited an hour it takes the next free slot.
    - **When the count clears:** once a summary is delivered, the count it reported is subtracted. If the summary is itself held back or fails, the count stays and the next summary reports it.

14. **Logging.** Logs name recipients only as `check-config` displays them. A name with five or more digits appears as its position, such as `[#3]`.

## Alternatives considered

- **Hold real alerts while the send history is unknown** (rejected in favour of the rule). It made the cap exact in every failure mode, at the cost of going silent. A permanently corrupt database would have held alerts until an operator stepped in.
- **Rotate the journal to one previous generation** (rejected). At valid configuration limits, a rotation could discard sends from inside the 24-hour window.
- **Store dry-run sends next to real ones** (rejected). A dry-run flood could push real sends out of a combined row limit.
- **Hold back the summary until no real alert is due** (rejected). A steady stream of real alerts could delay it indefinitely.
- **Fixed windows for the cap** (rejected). They allow up to twice the cap across a window boundary.
- **One summary per recipient** (rejected). The number of summaries grew with the number of recipients.

## Accepted risks

- **Per-process limits in failure modes.** While storage cannot record attempts, or the history cannot be read, the cap is enforced per process. A restart during such a failure starts a fresh in-memory window, so restarts can exceed the cap. Provider-side limits, such as an SMS provider's daily cap, are the final backstop.
- **One storage notice per process start.** When nothing can record the notice, a restart loop during an outage sends one notice per restart, bounded by the in-memory cap of each process and by provider-side limits.
- **Duplicates.** A message can be sent twice in these cases:
  - after a crash between a send and its recorded outcome, when the provider has no lookup;
  - after a restart while storage could not record the outcome;
  - after a corrupt database is replaced, because the delivery records it held are gone.

  Each duplicate counts against the cap of the process that sends it.
- **A forward clock jump across a restart.** If the wall clock jumps forward and the process restarts before it is corrected, stored attempts look older than they are and may free slots early. Without a trusted clock this cannot be detected.
- **Rule state is not journaled.** If SQLite cannot be written and the process restarts, rule state starts fresh. An active condition may then be reported again under a new event identity.
- **Journal evidence beyond its bound.** Only a failure mode that produces far more sends than the largest valid cap can exceed the compacted bound. The oldest evidence is then dropped and the loss logged.
- **Held-back counts can err high.** If the database pruned a held-back delivery that the journal still repeats, or more deliveries are held back while the counts are unread than the relay tracks by identity (100,000), the merged count can include some twice. A delivered summary in the journal that cannot be proven newer than the database is not subtracted. A summary then reports more than were held back, never fewer.
- **The attempt-number ceiling.** Attempt numbers stop at 100. A recovered delivery whose stored attempts already reach 100 numbers its retry 100 again, so after a restart that one retry may hold no slot. Reaching it takes about ninety recoveries of the same corrupt row.
- **A residual path race.** The identity checks narrow but cannot fully close a race against a local attacker who can write to the state directory. Keep that directory private to the relay user.
- **Schema version 1 was changed in place.** It was never released, so no database in use has the earlier layout.

## Consequences

- C6 providers implement `Provider.send`, and `ReconcilingProvider.reconcile` when the service offers a lookup. Neither can name a destination. A provider's `FAILED` result must mean the message was definitely not accepted, because the storage notice moves on to the next recipient after it.
- C7 builds the engine from configuration with a real clock, and reports the engine's health fields. These include `durable_accounting`, which is false in every failure mode above. C7 must place the state directory on a local filesystem.

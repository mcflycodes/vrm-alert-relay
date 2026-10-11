# 0001 Foundational decisions

**Updated:** 2026-10-11
**Status:** Accepted
**Date:** 2026-10-11

## Context

Before implementation, the project weighed how strict each security and reliability control should be for a self-hosted, single-operator alert relay, informed by the public documentation of the VRM API and the VoIP.ms SMS API.

## Decisions

1. **Failure behaviour:** fail toward alerting. Keep delivering, report degraded monitoring once per outage, reconcile ambiguous sends with the provider before retrying, and accept a rare, capped duplicate after a crash.
2. **Rate limiting:** one global cap (~20/hour, 60/day), per-rule cooldowns, a critical-reminder cap, and the provider's own daily cap as a backstop. Single-operator scope; no multi-tenant plans.
3. **Review:** every code PR gets one independent cross-vendor review; security-sensitive PRs get a frontier security-focused reviewer; docs-only, test-only, and small fix deltas get a coordinator check.
4. **Endpoints:** per-provider adapters with documented default endpoints, which the operator can override (HTTPS only), plus a generic webhook provider. Destinations come only from operator configuration. HTTPS, no redirects, timeouts, and response-size caps; private-network destinations allowed.
5. **Home Assistant:** a first-class HA notify provider and docs in v1; HA sensors (MQTT discovery) as the first post-v1 item.
6. **Container and supply chain:** distroless, non-root, read-only rootfs, no capabilities, file-based secrets, masked logs; every PR builds, scans (HIGH/CRITICAL block, maintainer-approved, dated exceptions only), and produces an SBOM; published images are signed.
7. **Testing:** behaviour-focused (property-tested rules engine, mocked integrations, named failure scenarios), ≥ 85% overall coverage, near-100% on the rules engine, CI secret scanning plus a local private denylist check. Revisit if defects show the bar is too low.
8. **Stack:** Python with a small dependency set (HTTP client, schema validation, YAML, stdlib SQLite); Docker/Compose packaging.

## Alternatives considered

- Fail closed (rejected: it can silently suppress the alert that matters).
- Four-layer rate limits (rejected: no added protection at single-operator scale).
- Frontier security review on every PR (rejected: cost without benefit on docs and tests).
- Fixed-only endpoints (rejected: defeats self-hosting with any provider); full SSRF machinery (rejected: blocks legitimate local targets and guards against the trusted operator).
- Go (rejected: smaller contributor pool in the HA/Victron community, despite a smaller image); TypeScript/Node (rejected: supply-chain risk and weight).

## Consequences

- `SECURITY.md` invariants on rate limits, outbound destinations, failure behaviour, and accepted risk are revised to match.
- Python's distroless base will raise more scanner findings than a Go image would; exceptions require maintainer approval with an expiry date.

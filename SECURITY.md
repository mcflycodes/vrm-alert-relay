# Security Policy

## Reporting a Vulnerability

Report suspected vulnerabilities through GitHub's private vulnerability reporting feature for this repository. Do not disclose credentials, personal data, working exploits, or other sensitive details in a public issue.

## System and Scope

VRM Alert Relay is an outbound-only monitoring service. It reads measurements from operator-configured Victron VRM installations, evaluates local alert rules, and sends messages through operator-configured notification providers.

The security boundary includes configuration loading, VRM API access, rule evaluation, persistent state, message rendering, provider integrations, health reporting, container packaging, logs, and dependency management. Deployments and provider accounts remain under the operator's control.

## Threat Model and Trust Boundaries

Protect these assets:

- VRM and notification-provider credentials
- Recipient identifiers and private deployment configuration
- Provider balances, quotas, and sending reputation
- Alert integrity, availability, state, and delivery history
- The host and network on which the service runs

Treat VRM responses, provider responses, measurement labels and values, configuration files, environment variables, persisted state, HTTP headers, and network errors as untrusted input. A deployment administrator with host and configuration access is trusted to choose installations, rules, providers, and recipients.

The service is not intended to accept public commands or arbitrary message submissions. A health endpoint, if enabled, is informational only and binds to loopback by default.

## Security Invariants

- Sending is disabled by default. A provider and at least one recipient must be explicitly enabled by operator configuration.
- Recipients come only from an explicit operator-controlled allowlist. API data, measurement labels, templates, event payloads, and request parameters cannot select or override a recipient.
- A global rate limit, per-rule cooldowns, and a cap on critical reminders bound message volume. Retries are bounded, use backoff, and count against the global limit; they cannot bypass it or duplicate-suppression state.
- Threshold crossings and delivery attempts have stable event identities. Restarts, delayed API responses, and retries must not create unbounded duplicate messages.
- No configuration value, API response, template, measurement, or message content is executed as shell code, program code, or a command.
- Outbound destinations come only from operator configuration or a provider adapter's documented default endpoint. VRM data, measurement labels, templates, event payloads, and provider responses can never supply or alter a destination. Requests use HTTPS with certificate verification and do not follow redirects.
- Message content is length-bounded and encoded for the destination transport. Untrusted content cannot add attachments, executable content, arbitrary links, headers, recipients, or provider parameters.
- Credentials never appear in source control, images, command arguments, health responses, exceptions, metrics, or logs. Sensitive query parameters and headers are always redacted.
- Public examples, fixtures, tests, documentation, and defaults contain no real installation IDs, device IDs, DIDs, phone numbers, account names, private hostnames, private addresses, or other identifying deployment data.
- The project collects no telemetry and makes no network requests beyond the operator-configured VRM and notification-provider integrations.
- The container runs as a non-root user on a read-only root filesystem with no Docker socket, host namespace, privileged mode, or Linux capabilities. Persistent and secret mounts receive only the access they require.
- Parsing, queues, history, persistent state, retries, and logs are bounded to prevent resource exhaustion.
- Failures fail toward alerting. A failure to fetch, parse, persist state, or deliver a notification must not silently suppress alerts: the service reports degraded monitoring and keeps alerting. A rare failure, such as a crash during delivery, may produce a duplicate message, but no failure can generate an arbitrary or unbounded message stream.
- Logs preserve enough information to diagnose alert behavior without exposing complete recipient identifiers or sensitive deployment details.

## Reportable Findings and Severity Context

Report vulnerabilities that can realistically cause unauthorized messaging, recipient substitution, rate-limit or duplicate-suppression bypass, credential disclosure, arbitrary outbound requests, command or template injection, unauthorized state changes, alert suppression, cross-installation data disclosure, malicious dependency execution, or host/container compromise.

Unauthorized high-volume or attacker-directed messaging, remote code execution, credential theft, and cross-installation access are high-impact findings. An issue that can silently prevent critical alerts is also security-relevant even when it does not expose data.

## Out of Scope and Accepted Risk

- Availability, accuracy, pricing, policy, or delivery behavior of VRM, telecommunications carriers, and configured notification providers
- A trusted administrator intentionally configuring an incorrect threshold, recipient, provider, or endpoint, including an endpoint on a private network
- An occasional duplicate message after a crash or ambiguous provider response, within the configured rate limits
- A provider rejecting legitimate traffic because of account registration, balance, quota, carrier filtering, or regulatory requirements
- Compromise of the deployment host or provider account that occurs independently of VRM Alert Relay
- The unavoidable disclosure of message content and recipient metadata to the notification provider selected by the operator

These exclusions do not apply when VRM Alert Relay leaks additional data, expands access, bypasses a provider control, or turns an external failure into unsafe behavior.

## Known Limitations and Compensating Controls

VRM Alert Relay cannot guarantee delivery or prevent abuse after an operator's provider credentials or host are compromised. Operators should use dedicated least-privileged credentials, provider-side spending and rate limits, narrowly scoped recipient allowlists, restrictive file permissions, and independent native VRM alarms.

The service supplements rather than replaces safety controls, local alarms, equipment protections, or human verification. It must not be the sole safeguard for conditions that could cause injury, fire, flooding, equipment damage, or other material harm.


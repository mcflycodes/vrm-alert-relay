# VRM Alert Relay

> **Unofficial project:** VRM Alert Relay is an independent open-source project. It is not affiliated with, sponsored by, approved by, or endorsed by Victron Energy B.V.

VRM Alert Relay adds stateful alert escalation and additional notification transports to measurements available through the Victron Remote Management (VRM) API.

The project is intended for use cases where a single threshold notification is not enough—for example, sending progressively more urgent alerts as a tank approaches freezing, a refrigerator warms, or a battery measurement continues moving into a dangerous range.

## Planned capabilities

- Multi-stage rising and falling threshold ladders
- One notification per threshold crossing
- Recovery hysteresis and recovery notifications
- Critical reminders with configurable cooldowns
- Stale-data and polling-failure detection
- Persistent state across restarts
- Multiple installations, devices, and measurements
- Pluggable notification providers: VoIP.ms SMS, Home Assistant, and a generic webhook to start
- Dry-run mode and container deployment

## Status

VRM Alert Relay is in initial development. It is not yet ready to monitor production systems.

## Development

The service is written in Python 3.13 and packaged as a distroless, non-root container image. With [uv](https://docs.astral.sh/uv/) installed:

```sh
uv sync
uv run vrm-alert-relay --version
uv run vrm-alert-relay check-config --config examples/config.example.yaml --structure-only
uv run pytest
```

The relay starts in dry-run mode: until sending and a provider are both enabled, every message is written to the log instead of being sent. [docs/operations.md](docs/operations.md) describes the commands, exit codes, monitoring notifications and the health endpoint. See [CONTRIBUTING.md](CONTRIBUTING.md) for all checks, [docs/requirements.md](docs/requirements.md) for the v1 requirements, and [docs/adr/](docs/adr/) for design decisions.

## Security and privacy

Abuse prevention and deployment privacy are core design requirements. Sending will be disabled by default, recipients will be explicitly allow-listed, and a global rate limit, per-rule cooldowns, and bounded critical reminders will constrain message volume. The project will not collect telemetry.

Public examples and tests use fictitious identifiers. Operators supply their own installations, devices, rules, providers, and recipients through deployment configuration; none are built into the software.

See [SECURITY.md](SECURITY.md) for the threat model, required security properties, and private vulnerability-reporting process.

## Trademark notice

Victron, Victron Energy, and VRM are trademarks or registered trademarks of Victron Energy B.V. and/or its affiliates. Their names are used solely to identify compatibility and the external service with which this software interoperates. No ownership, sponsorship, endorsement, or affiliation is claimed or implied.

See [TRADEMARKS.md](TRADEMARKS.md) for the full notice.

## License

Copyright (c) 2026 mcflycodes and contributors.

The software is licensed under the [MIT License](LICENSE). The license applies to this project's original software and documentation; it does not grant rights to Victron Energy's names, trademarks, logos, services, APIs, or other intellectual property.

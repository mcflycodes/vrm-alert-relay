# VRM Alert Relay

> **Unofficial project:** VRM Alert Relay is an independent open-source project. It is not affiliated with, sponsored by, approved by, or endorsed by Victron Energy B.V.

VRM Alert Relay adds stateful alert escalation and additional notification transports to measurements available through the Victron Remote Management (VRM) API.

The project is intended for use cases where a single threshold notification is not enough—for example, sending progressively more urgent alerts as a tank approaches freezing, a refrigerator warms, or a battery measurement continues moving into a dangerous range.

## Features (v1)

- **Escalation ladders:** rising or falling thresholds with up to 20 levels per rule, one notification per escalation into a level, and one notification for the highest level when several are crossed at once.
- **Hysteresis and recovery:** a level clears only after the value moves back past its threshold by a configurable margin, optionally for several consecutive samples, and a recovery notification follows when the rule returns to normal.
- **Several installations:** up to 50 installations and 200 rules, each measurement identified by its VRM attribute code and device instance.
- **Reminders:** bounded, configurable reminders while a rule stays at its highest level.
- **Stale data:** a notification when a measurement stops reporting, and another when it returns.
- **Monitoring degraded:** a notification when an installation cannot be polled, and another when polling recovers.
- **Rate limits:** a global cap on outgoing messages (20 per hour and 60 per day by default), per-rule cooldowns, and a summary of anything held back.
- **Persistent state:** a restart does not repeat notifications already sent. Ambiguous SMS sends are looked up with the provider before any retry.
- **Providers:** VoIP.ms SMS, Home Assistant notify actions, and a generic JSON webhook.
- **Dry-run by default:** nothing is sent until sending and a provider are both enabled; until then every message is written to the log.
- **Operations:** a `check-config` command, a `test-notification` command, structured JSON logs that never contain secrets, an optional informational health endpoint, and a hardened, non-root container image.

## Status

VRM Alert Relay is pre-release. The v1 features are implemented and tested, but there are no releases or published container images yet, and it has not yet completed a long-running trial on real installations. Run it in dry-run mode first, and keep VRM's own alarms enabled: it supplements them and is not a safety device.

## Quick start

With Docker and the Compose plugin:

```sh
git clone https://github.com/mcflycodes/vrm-alert-relay.git
cd vrm-alert-relay
docker build --tag vrm-alert-relay:local .
```

Then follow [docs/deploy-docker.md](docs/deploy-docker.md): it copies [compose.example.yaml](compose.example.yaml) and [examples/config.example.yaml](examples/config.example.yaml), creates the secret files, checks the configuration and starts the relay in dry-run mode.

## Documentation

| Page | Covers |
|---|---|
| [docs/deploy-docker.md](docs/deploy-docker.md) | Step-by-step Docker Compose deployment, upgrades, backup, rollback and removal. |
| [docs/configuration.md](docs/configuration.md) | Every configuration setting, with defaults and limits. |
| [docs/vrm-credentials.md](docs/vrm-credentials.md) | A least-privilege VRM user and token, and data freshness. |
| [docs/voipms.md](docs/voipms.md) | Setting up VoIP.ms SMS. |
| [docs/home-assistant.md](docs/home-assistant.md) | Setting up Home Assistant notifications. |
| [docs/notifications.md](docs/notifications.md) | Message templates and what each provider sends. |
| [docs/operations.md](docs/operations.md) | Commands, exit codes, the poll loop, monitoring notices and the health endpoint. |
| [docs/requirements.md](docs/requirements.md), [docs/adr/](docs/adr/) | Requirements and design decisions. |

## Development

The service is written in Python 3.13 and packaged as a minimal, non-root container image built from [Wolfi](https://github.com/wolfi-dev) packages, with no shell or package manager. With [uv](https://docs.astral.sh/uv/) installed:

```sh
uv sync
uv run vrm-alert-relay --version
uv run vrm-alert-relay check-config --config examples/config.example.yaml --structure-only
uv run pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for all checks.

## Security and privacy

Abuse prevention and deployment privacy are core design requirements. Sending is disabled by default, recipients are explicitly allow-listed, and a global rate limit, per-rule cooldowns, and bounded reminders constrain message volume. The project collects no telemetry and contacts only VRM and the providers you configure.

Public examples and tests use fictitious identifiers. Operators supply their own installations, devices, rules, providers, and recipients through deployment configuration; none are built into the software.

See [SECURITY.md](SECURITY.md) for the threat model, required security properties, and private vulnerability-reporting process.

## Trademark notice

Victron, Victron Energy, and VRM are trademarks or registered trademarks of Victron Energy B.V. and/or its affiliates. Their names are used solely to identify compatibility and the external service with which this software interoperates. No ownership, sponsorship, endorsement, or affiliation is claimed or implied.

See [TRADEMARKS.md](TRADEMARKS.md) for the full notice.

## License

Copyright (c) 2026 mcflycodes and contributors.

The software is licensed under the [MIT License](LICENSE). The license applies to this project's original software and documentation; it does not grant rights to Victron Energy's names, trademarks, logos, services, APIs, or other intellectual property.

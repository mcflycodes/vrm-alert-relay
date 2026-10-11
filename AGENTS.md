# VRM Alert Relay development guide

## Purpose

VRM Alert Relay is an unofficial open-source service that evaluates Victron VRM measurements against stateful alert rules and forwards resulting events to configurable notification providers.

## Project rules

- Keep the rules engine independent from VRM acquisition and notification transports.
- Preserve state across restarts so a restart cannot create an alert storm.
- Default to safe dry-run behavior until a notification provider is explicitly enabled.
- Never commit credentials, real installation identifiers, DIDs, phone numbers, private hostnames, or private addresses.
- Tests must use fictitious identifiers and mocked provider endpoints.
- Logs must not include authorization headers, API passwords, tokens, or complete phone numbers.
- Public documentation must describe the project as unofficial and must not imply affiliation with or endorsement by Victron Energy.

## Verification

Run formatting, linting, unit tests, and secret scanning before merging. Add integration tests with mocked HTTP services for each external provider.


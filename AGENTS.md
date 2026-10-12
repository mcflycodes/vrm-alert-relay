# VRM Alert Relay development guide

## Purpose

VRM Alert Relay is an unofficial open-source service that evaluates Victron VRM measurements against stateful alert rules and forwards resulting events to configurable notification providers.

Requirements live in [docs/requirements.md](docs/requirements.md) and decisions in [docs/adr/](docs/adr/). Read the relevant ones before changing behavior; record new decisions as a new ADR rather than editing an accepted one.

## Project rules

- Keep the rules engine independent from VRM acquisition and notification transports.
- Preserve state across restarts so a restart cannot create an alert storm.
- Default to safe dry-run behavior until a notification provider is explicitly enabled.
- Never commit credentials, real installation identifiers, DIDs, phone numbers, private hostnames, or private addresses.
- Tests must use fictitious identifiers and mocked provider endpoints.
- Logs must not include authorization headers, API passwords, tokens, or complete phone numbers.
- Public documentation must describe the project as unofficial and must not imply affiliation with or endorsement by Victron Energy.

## Toolchain

- Python 3.13, set in `.python-version` and `requires-python`. It matches the interpreter in the runtime image, Wolfi's `python-3.13-base` package (ADR 0003). Change the target version only together with the runtime image.
- Dependencies are managed with [uv](https://docs.astral.sh/uv/). `uv.lock` is committed; CI and the image build use `--locked`, so update the lock in the same change as `pyproject.toml`.
- The Dockerfile's build stage installs the same Wolfi Python package into its own environment and into the runtime root filesystem, so the virtual environment matches `/usr/bin/python3.13`. Base images, CI actions, and downloaded CI tools are pinned by digest, commit SHA, or SHA-256; update pins together and keep the version comments accurate. Wolfi packages are not version-pinned, so image rebuilds are not byte-identical; the SBOM records exact versions. The weekly scheduled workflow refreshes the Wolfi base digest through a pull request, because Dependabot cannot follow its mutable tag.

## Verification

Run formatting, linting, unit tests, and secret scanning before merging. Add integration tests with mocked HTTP services for each external provider.

Every gate below runs in CI (`.github/workflows/ci.yml`) as a separately named job; the job names are required checks, so do not rename them. A failed, skipped, or empty run is not a pass.

| CI job | Local command |
|---|---|
| `lint` | `uv run ruff format --check .` and `uv run ruff check .` |
| `typecheck` | `uv run mypy --strict src` |
| `test` | `uv run pytest` (coverage must stay at or above 85%) |
| `secrets` | `gitleaks git --redact --verbose .` (full history) |
| `dependencies` | `uv export --locked --all-groups --no-emit-project --format requirements-txt --output-file requirements-audit.txt` then `uv run pip-audit --strict --require-hashes --disable-pip --requirement requirements-audit.txt` |
| `container` | `hadolint Dockerfile`, `docker build --tag vrm-alert-relay:ci .`, the hardened smoke test, an SBOM, a non-blocking report of all HIGH/CRITICAL findings, and `trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 vrm-alert-relay:ci` |

Run `uv sync` first. On hosts without Docker the `container` gates run only in CI; say so when reporting results.

Never weaken a gate to get a green run: no lowered coverage, no lowered Trivy severity, no `.trivyignore` entries. The image scan blocks only on HIGH/CRITICAL findings with an available fix and reports unfixed ones without blocking (see ADR 0001); do not loosen it further.

## Branches, reviews, and merges

- Branch names: `work/<chunk-id>-<slug>`, for example `work/B0-bootstrap`.
- Every code PR needs an independent review before merge.
- Merge with a merge commit; do not squash or rebase-merge. Never force-push a branch after it has been pushed.
- No attribution of any kind: no `Co-authored-by`, `Signed-off-by`, "generated with" notes, or tool, agent, or model credits in commits, PR titles or bodies, comments, or files.

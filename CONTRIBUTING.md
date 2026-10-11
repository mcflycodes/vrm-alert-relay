# Contributing

Contributions are welcome once the initial implementation is published.

Please keep integrations modular, include tests for behavioral changes, and use fictitious values in examples and fixtures. Never submit API credentials, VRM installation identifiers, device identifiers, phone numbers, DIDs, private hostnames, or private network addresses.

By contributing, you agree that your contribution is licensed under the MIT License. Do not submit Victron logos, copied documentation, proprietary API material, or other content that you do not have the right to redistribute.

Public-facing text must preserve the project's unofficial status and must not imply affiliation with or endorsement by Victron Energy.

## Running the checks

You need [uv](https://docs.astral.sh/uv/). It installs the Python version in `.python-version` (3.13) and the locked development tools:

```sh
uv sync
uv run ruff format --check .
uv run ruff check .
uv run mypy --strict src
uv run pytest
```

`uv run pytest` fails if coverage drops below 85%. Use `uv run ruff format .` and `uv run ruff check --fix .` to fix formatting and simple lint findings.

CI also scans the full git history for secrets with [gitleaks](https://github.com/gitleaks/gitleaks), audits the locked dependencies with `pip-audit`, and builds, smoke-tests, and scans the container image with [hadolint](https://github.com/hadolint/hadolint) and [Trivy](https://trivy.dev/). If you have those tools and Docker installed, the exact commands are listed in [AGENTS.md](AGENTS.md#verification). Every check must pass before a pull request is merged.

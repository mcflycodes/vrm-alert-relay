# 0003 Wolfi base image

**Updated:** 2026-10-12
**Status:** Accepted
**Date:** 2026-10-12

## Context

ADR 0001 chose a distroless base. The Debian 13 distroless Python image carried a steady set of HIGH and CRITICAL scanner findings in Debian packages that had no fix available. They did not block CI, but they kept every scan report noisy and made a real, fixable finding easier to miss. A trial built the same application on distroless, Wolfi, and `python:3.13-slim`, with the same hardened smoke test and scans:

- Distroless: 15 unfixed HIGH/CRITICAL findings, about 60 MB.
- Wolfi: no HIGH/CRITICAL findings, about 66 MB, no shell.
- Slim: 8 unfixed HIGH/CRITICAL findings, about 123 MB, with a shell.

## Decision

The runtime image is assembled from [Wolfi](https://github.com/wolfi-dev) packages into a `scratch` image:

- The build stage is `cgr.dev/chainguard/wolfi-base`, pinned by digest. Chainguard's free `python` image only publishes tags that follow the newest CPython minor, so Python comes from Wolfi's versioned `python-3.13-base` package, which keeps the 3.13 line.
- The build stage installs that package for itself and, with the base layout, CA certificates, and time zone data, into a separate root filesystem that becomes the runtime image. The runtime has no shell and no package manager.
- The relay user, paths, and state-directory ownership are unchanged: UID and GID 65532, `/opt/venv`, and `/var/lib/vrm-alert-relay` owned by `65532:65532` with mode `0700`. Existing state volumes and the Compose example keep working.
- Wolfi packages are installed at their newest version on every build, not pinned. Rebuilds are therefore not byte-identical, and each build's SBOM records the exact package versions.
- Dependabot cannot follow the mutable `latest` tag, so a weekly scheduled workflow rebuilds and re-scans `main` and opens a pull request when the base image's digest changes.

Everything else in ADR 0001's container and supply-chain decision stands.

## Alternatives considered

- Keep distroless (rejected: persistent unfixed findings with no project-side remedy).
- `python:3.13-slim` (rejected: larger, ships a shell and more packages, and still carries unfixed findings).
- Chainguard's `python` image (rejected: its free tags follow the newest CPython minor, so the Python version could change without a code change).

## Consequences

- Two builds of the same commit can contain different package versions. The SBOM, not the commit, identifies what an image contains.
- A rebuild picks up Wolfi's fixes without a code change, so the weekly scan reflects what a rebuild would ship.
- Pull requests opened by the scheduled workflow do not trigger CI by themselves; the maintainer closes and reopens them to run it.

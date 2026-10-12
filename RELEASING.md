# Releasing

**Updated:** 2026-10-12

Releases are made by pushing a version tag. [`.github/workflows/release.yml`](.github/workflows/release.yml) does the rest; nothing is published by hand.

## Versions and tags

Tags use SemVer: `vMAJOR.MINOR.PATCH`, optionally with `-alpha.N`, `-beta.N` or `-rc.N`. `pyproject.toml` holds the same version in canonical [PEP 440](https://peps.python.org/pep-0440/) form, and the workflow fails if the two differ:

| Tag | `pyproject.toml` version | Image tags | GitHub Release |
|---|---|---|---|
| `v0.1.0-rc.1` | `0.1.0rc1` | `0.1.0-rc.1` | pre-release |
| `v0.1.0-beta.2` | `0.1.0b2` | `0.1.0-beta.2` | pre-release |
| `v0.1.0` | `0.1.0` | `0.1.0`, `latest` | latest release |

Other forms, such as `0.1.0-rc1`, `0.1.0.rc1` or `v0.1.0+build.1`, are rejected. The tagged commit must be on `main`.

## Steps

1. On a branch, set `version` in `pyproject.toml`, run `uv lock` (the lock file records the project's version, and CI uses `--locked`), and merge the pull request once CI passes.
2. Tag the merge commit on `main` and push the tag:

   ```sh
   git switch main && git pull --ff-only
   git tag -a v0.1.0-rc.1 -m "v0.1.0-rc.1"
   git push origin v0.1.0-rc.1
   ```

3. Watch the Release workflow in the Actions tab. When it finishes, check the release notes and [verify the image](docs/deploy-docker.md#verifying-a-release-image).

To promote a release candidate, repeat the steps with the final version (`0.1.0`, tag `v0.1.0`). Only the version changes, so the code is the one that was tested as the candidate.

## What the workflow does

1. **prepare:** checks the tag's form, that `pyproject.toml` has the matching version, and that the commit is on `main`.
2. **build:** builds the image for `linux/amd64` and `linux/arm64` (arm64 through QEMU), smoke-tests each image's user and `--version`, runs the same Trivy gate as CI (HIGH and CRITICAL findings with a fix available block the release; unfixed ones are listed in the job summary), and generates a CycloneDX SBOM per platform. Only then does it push the image to `ghcr.io/mcflycodes/vrm-alert-relay` under the exact version tag, and check that each pushed platform image has the same configuration digest as the image it scanned.
3. **sign:** signs the image index and each platform image with cosign keyless signing through GitHub Actions OIDC, attests each platform's SBOM, verifies both, and, for a final release only, points `latest` at the new image.
4. **release:** creates the GitHub Release, marked as a pre-release for `-alpha`, `-beta` and `-rc` tags, with the image digest, a verification command, generated notes and the SBOMs attached.

It uses only the workflow's `GITHUB_TOKEN`; each job has only the permissions it needs.

## If a release fails

Nothing is pushed before the scan passes, so a failure in **prepare** or before the push in **build** publishes nothing: fix the cause, delete the tag (`git push origin :refs/tags/v0.1.0-rc.1` and `git tag -d v0.1.0-rc.1`), and tag again.

A failure after the push leaves an unsigned image under the version tag and no GitHub Release; an unsigned image fails verification, so it must not be deployed. Re-run the failed jobs from the Actions tab if the cause was transient. Otherwise release a new version rather than reusing the tag: do not move a tag or overwrite an image that may already have been pulled.

# Releasing

**Updated:** 2026-10-12

Releases are made by pushing a version tag. [`.github/workflows/release.yml`](.github/workflows/release.yml) does the rest; nothing is published by hand.

## Versions and tags

Tags use SemVer: `vMAJOR.MINOR.PATCH`, optionally with `-alpha.N`, `-beta.N` or `-rc.N`. `pyproject.toml` holds the same version in canonical [PEP 440](https://peps.python.org/pep-0440/) form, and the workflow fails if the two differ:

| Tag | `pyproject.toml` version | Image tags | GitHub Release |
|---|---|---|---|
| `v0.1.0-rc.1` | `0.1.0rc1` | `0.1.0-rc.1` | pre-release |
| `v0.1.0-beta.2` | `0.1.0b2` | `0.1.0-beta.2` | pre-release |
| `v0.1.0` | `0.1.0` | `0.1.0`, and `latest` if it is the highest stable version | latest release, on the same condition |

Other forms, such as `0.1.0-rc1`, `0.1.0.rc1` or `v0.1.0+build.1`, are rejected. The tagged commit must be on `main`.

## Steps

1. On a branch, set `version` in `pyproject.toml`, run `uv lock` (the lock file records the project's version, and CI uses `--locked`), and merge the pull request once CI passes.
2. Tag the merge commit on `main` and push the tag:

   ```sh
   git switch main && git pull --ff-only
   git tag -a v0.1.0-rc.1 -m "v0.1.0-rc.1"
   git push origin v0.1.0-rc.1
   ```

   Push one release tag at a time. Releases run one after another, but GitHub keeps only one waiting run: a third tag pushed while one release runs and another waits cancels the waiting run before it starts. That run published nothing; re-run it from the Actions tab.

3. Watch the Release workflow in the Actions tab. When it finishes, check the release notes and [verify the image](docs/deploy-docker.md#verifying-a-release-image).

To promote a release candidate, repeat the steps with the final version (`0.1.0`, tag `v0.1.0`). Only the version changes, so the code is the one that was tested as the candidate. Wolfi packages are not version-pinned, so the image is a new build with its own scan and SBOM.

## What the workflow does

Jobs run in this order, each only if the previous ones succeeded:

1. **prepare:** checks the tag's form, that `pyproject.toml` has the matching version, and that the commit is on `main`.
2. **build:** builds `linux/amd64` and `linux/arm64` (arm64 through QEMU) once, into an OCI layout. Everything after works on that layout: the build-log checks from CI, smoke tests of each platform (user, command, working directory, `--version`, the runtime contract, the state directory, TLS verification), the same Trivy gate as CI (HIGH and CRITICAL findings with a fix available block the release; unfixed ones are listed in the job summary), and a CycloneDX SBOM per platform. Nothing is pushed.
3. **publish:** pushes the layout's objects to `ghcr.io/mcflycodes/vrm-alert-relay` by digest, without a tag, and checks that the pushed image index and both platform manifests are byte-for-byte the built ones.
4. **sign:** signs the index and both platform images with cosign keyless signing through GitHub Actions OIDC, attests each platform's SBOM, and verifies the signatures and attestations against this workflow's identity.
5. **tag:** applies the version tag (`0.1.0-rc.1`) to the signed digest. It never moves an existing version tag to a different digest.
6. **release:** creates the GitHub Release, a pre-release for `-alpha`, `-beta` and `-rc` tags, with the image digest, a verification command, generated notes and the SBOMs attached. A stable release is marked latest only if its version is higher than every stable version already released.
7. **latest:** only for a stable release marked latest in step 6: points `latest` at the digest.

Releases run one at a time across the repository, so two cannot race on `latest`. The workflow uses only its `GITHUB_TOKEN`, and each job has only the permissions it needs.

## If a release fails

The job that failed decides what is left behind. Fix the cause first. "Retry" means deleting the tag (`git push origin :refs/tags/v0.1.0-rc.1`, then `git tag -d v0.1.0-rc.1`), tagging again and pushing; re-running only the failed jobs from the Actions tab also works, unless the fix needed a code change.

| Failed job | Left behind | What to do |
|---|---|---|
| prepare, build | Nothing published. | Retry. |
| publish | Possibly some blobs or manifests in GHCR, untagged and unsigned. | Retry. Untagged objects are harmless; nothing refers to them. |
| sign | An untagged image in GHCR, possibly with some of its signatures or attestations. | Retry. The rebuild gets a new digest, so the old one stays untagged and unused. |
| tag | A signed, attested image, untagged or under the version tag. | Re-run the failed jobs. If the version tag was applied, it points to a signed image, which is safe to use. |
| release | A signed image under the version tag, no GitHub Release. | Re-run the failed jobs. Do not retry from a new tag: the version tag in GHCR already points at this digest, and the tag job refuses to move it. |
| latest | Everything except the `latest` move. The GitHub Release may already be marked latest. | Re-run the failed job. |

Re-running a job reuses the run's own build: the digest and artifacts do not change. The image artifact is kept for 7 days, so re-run within that time. Release a new version rather than reuse a version tag in GHCR that already points to an image someone may have pulled.

To remove leftover untagged images, open the package's settings on GitHub (Your profile, Packages, `vrm-alert-relay`, Package settings) and delete the version with that digest. Its signatures and attestations are separate entries in the same package that refer to that digest (tagged `sha256-<digest>`, or untagged); delete those too. Never delete a digest that a version tag points to.

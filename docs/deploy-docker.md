# Deploying with Docker Compose

**Updated:** 2026-10-12

VRM Alert Relay is an unofficial, independent project. It is not affiliated with, sponsored by, or endorsed by Victron Energy.

This page deploys the relay with Docker Compose using [compose.example.yaml](../compose.example.yaml), which applies the container hardening of requirement R29: a non-root user, a read-only root filesystem, no Linux capabilities, `no-new-privileges`, secrets as read-only files, and one writable state volume. The relay starts in dry-run mode and sends nothing until you enable sending.

The examples use `/opt/vrm-alert-relay` as the deployment directory and fictitious values throughout. Commands that change root-owned files use `sudo`.

## Before you start

- A Linux host with Docker Engine and the Compose plugin (`docker compose version`).
- Outbound HTTPS from the host to the VRM API and to each provider you enable. The relay accepts no inbound connections and publishes no ports.
- An accurate clock (NTP) on the host and on the GX device. A reading stamped more than 60 seconds ahead of the host's clock is rejected, so clocks that disagree by more than a minute show up as "monitoring degraded".
- Local storage for Docker volumes. The state directory must be on a local filesystem, because file locking and SQLite's WAL mode are not reliable on NFS or other network filesystems ([operations.md](operations.md#the-state-directory)). The default `local` volume driver keeps volumes under Docker's data directory, which is fine as long as that is local disk.
- A VRM access token: see [vrm-credentials.md](vrm-credentials.md).

## 1. Build the image

No image is published yet, so build one from a checkout. Tag it with the version you built, so you can roll back to the previous tag later:

```sh
git clone https://github.com/mcflycodes/vrm-alert-relay.git
cd vrm-alert-relay
git checkout <release tag or commit>
tag="vrm-alert-relay:$(git describe --tags --always)"
docker build --tag "$tag" .
echo "$tag"
```

The image is built from Wolfi packages, which are not version-pinned, so two builds of the same commit can differ in package versions. The image's SBOM (CI publishes one for every build) records the exact versions. A rebuild reuses Docker's layer cache, and with it the packages installed last time, unless you build with `docker build --pull --no-cache`; do that to pick up the latest fixes.

Once release images are published, use `ghcr.io/mcflycodes/vrm-alert-relay:VERSION` instead of building, pinned by digest and [verified](#verifying-a-release-image) first. Set it as `VRM_ALERT_RELAY_IMAGE` in step 2, in place of the tag you built.

## Verifying a release image

Release images are published to `ghcr.io/mcflycodes/vrm-alert-relay` for `linux/amd64` and `linux/arm64`, tagged with the version without its `v` (tag `v0.1.0-rc.1` is image `0.1.0-rc.1`). `latest` follows the newest release that is not a pre-release. Each release lists the image's digest in its notes.

The release workflow signs every image with [Sigstore cosign](https://docs.sigstore.dev/) keyless signing: the signing certificate is issued to this repository's release workflow, running for a version tag, through GitHub Actions OIDC. No signing key exists to leak. It also attaches each platform's CycloneDX SBOM to that platform's image as a signed attestation, and to the GitHub Release.

With [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 2.x or 3.x, check the signature before you deploy, using the digest from the release notes:

```sh
image=ghcr.io/mcflycodes/vrm-alert-relay@sha256:0000000000000000000000000000000000000000000000000000000000000000
cosign verify \
  --certificate-identity-regexp '^https://github\.com/mcflycodes/vrm-alert-relay/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$image"
```

It prints the verified signatures and exits 0; any other result means the image was not published by the release workflow, so do not deploy it. To pin one release exactly, use `--certificate-identity https://github.com/mcflycodes/vrm-alert-relay/.github/workflows/release.yml@refs/tags/v0.1.0-rc.1` instead of the regular expression.

The SBOM attestations belong to the per-platform images, not to the multi-platform index. Look up the digest of your platform (`amd64` or `arm64`) with [jq](https://jqlang.org/), then verify its attestation:

```sh
platform_digest="$(docker buildx imagetools inspect --raw "$image" |
  jq -r '.manifests[] | select(.platform.architecture == "amd64") | .digest')"
cosign verify-attestation --type cyclonedx \
  --certificate-identity-regexp '^https://github\.com/mcflycodes/vrm-alert-relay/\.github/workflows/release\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "ghcr.io/mcflycodes/vrm-alert-relay@${platform_digest}" > /dev/null && echo "SBOM attestation verified"
```

The same SBOMs are attached to the GitHub Release as `sbom-linux-amd64.cdx.json` and `sbom-linux-arm64.cdx.json`.

## 2. Create the deployment directory

```sh
sudo install -d -m 0755 /opt/vrm-alert-relay
sudo install -d -m 0700 /opt/vrm-alert-relay/secrets
sudo install -m 0644 compose.example.yaml /opt/vrm-alert-relay/compose.yaml
echo "VRM_ALERT_RELAY_IMAGE=$tag" | sudo tee /opt/vrm-alert-relay/.env
cd /opt/vrm-alert-relay
```

Compose reads `VRM_ALERT_RELAY_IMAGE` from `.env`. Without it, the placeholder image name fails with an "invalid reference format" error. The `.env` file holds only the image name: never put secrets in it.

## 3. Write the configuration

Start from the example, readable by the container's group (65532) but not by other users, because it holds recipient phone numbers:

```sh
sudo install -m 0640 -o root -g 65532 /path/to/vrm-alert-relay/examples/config.example.yaml config.yaml
sudoedit config.yaml
```

Set your installations, rules and recipients. Leave `sending.enabled: false` and every provider disabled for now. Keep the `*_file` paths under `/run/secrets/`, where Compose mounts the secret files. [configuration.md](configuration.md) describes every setting.

## 4. Create the secret files

Compose without Swarm mounts each secret file into the container as it is on the host, read-only, at `/run/secrets/<name>`. The relay runs as UID 65532, so each file must belong to UID 65532, with mode `0400`. The relay warns about a secret file that group or others can read.

Create the empty file with the right owner and mode first, then write the secret into it without it appearing on a command line or in your shell history:

```sh
sudo install -m 0400 -o 65532 -g 65532 /dev/null secrets/vrm_token
read -rs -p 'VRM access token: ' secret; echo
printf '%s\n' "$secret" | sudo tee secrets/vrm_token > /dev/null
unset secret
```

`read -s` does not echo or record what you type, and `printf` is a shell builtin, so the value never appears in the process list. `sudo tee` writes into the existing file and keeps its owner and mode. Alternatively, run `sudoedit secrets/vrm_token` and paste the value; make sure your editor keeps no backup or swap copy.

Check the result. It should show `65532:65532 400` and a non-zero size:

```sh
sudo stat -c '%u:%g %a %s' secrets/vrm_token
```

Only `vrm_token` is needed in dry-run mode. Create the provider secrets the same way when you enable a provider ([step 9](#9-enable-sending)):

| Secret file | Configuration setting |
|---|---|
| `secrets/voipms_username` | `providers.voipms.username_file: /run/secrets/voipms_username` |
| `secrets/voipms_api_password` | `providers.voipms.password_file: /run/secrets/voipms_api_password` |
| `secrets/homeassistant_token` | `providers.homeassistant.token_file: /run/secrets/homeassistant_token` |
| `secrets/webhook_token` | `providers.webhook.auth_header_value_file: /run/secrets/webhook_token` |

Some hosts need more:

- **SELinux** (Fedora, RHEL and derivatives): the container may be denied access to the bind-mounted files. Label the deployment directory for container use, for example `sudo chcon -R -t container_file_t /opt/vrm-alert-relay`.
- **Rootless Docker or user-namespace remapping:** UID 65532 in the container maps to a different UID on the host. Give the files to that mapped UID instead.

## 5. The state volume

The Compose file mounts a named volume, `vrm-alert-relay-state`, at `/var/lib/vrm-alert-relay`. Docker initialises a new named volume from the image, which ships that directory owned by `65532:65532` with mode `0700`, so it needs no preparation. It is the container's only writable path.

To use a host directory instead, replace `state:/var/lib/vrm-alert-relay` in `compose.yaml` with a bind mount. Docker does not change a host directory's ownership, so create it for the relay user first:

```sh
sudo install -d -o 65532 -g 65532 -m 0700 /srv/vrm-alert-relay/state
```

If you run the container with another `user:`, the directory must belong to that UID instead. What the relay does when it cannot use the directory is described in [operations.md](operations.md#the-state-directory).

## 6. Check the configuration

```sh
docker compose run --rm --no-deps relay check-config
```

This contacts no service. Expect `result: ready: the configuration and its secret files are valid`, `live providers: none`, and a list of dry-run recipients. Fix every problem it lists, and read the warnings: they include recipients no rule uses and insecure settings. Exit codes are in [operations.md](operations.md#exit-codes).

## 7. Run in dry-run mode

Run one poll cycle in the foreground first:

```sh
docker compose run --rm relay run --once
```

It polls every installation once, logs what it would send and exits. Then start the service:

```sh
docker compose up -d
docker compose ps
```

Leave it in dry-run mode for a while, ideally several days, and read what it would have sent before enabling real sending. Keep VRM's own alarms enabled throughout: the relay supplements them (see [vrm-credentials.md](vrm-credentials.md#keep-native-vrm-alarms-enabled)).

## 8. Read the logs

The relay logs one JSON object per line. The Compose file keeps at most five 10 MB log files.

```sh
docker compose logs -f relay
```

With [jq](https://jqlang.org/) you can pick out records by their `event`:

```sh
# What the relay would have sent
docker compose logs --no-log-prefix relay | jq -c 'select(.event == "provider.dry_run") | {ts, provider, recipient, text}'

# Warnings and errors
docker compose logs --no-log-prefix relay | jq -c 'select(.level == "WARNING" or .level == "ERROR")'
```

Records worth knowing:

| `event` | Meaning |
|---|---|
| `service.started` | Startup. `dry_run` is `true` while no provider is live. |
| `config.warning` | A non-fatal configuration finding, such as a readable secret file. |
| `relay.cycle` | One poll cycle completed. |
| `provider.dry_run` | A message that was logged instead of sent. |
| `monitoring.degraded`, `monitoring.restored` | An installation's polling failed repeatedly, or recovered. |
| `provider.delivered`, `provider.failed`, `provider.ambiguous` | The outcome of a real provider call, with a `reason`. |
| `delivery.suppressed` | A message held back by the global cap. |
| `state.persistence_failed` | State storage is failing; the relay keeps alerting from memory. |

Phone numbers in logs show only their last four digits, and secrets are never logged.

## 9. Enable sending

For each provider you want to use:

1. Set it up at the provider: [voipms.md](voipms.md), [home-assistant.md](home-assistant.md), or your webhook receiver.
2. Create its secret files ([step 4](#4-create-the-secret-files)).
3. In `compose.yaml`, uncomment its entries under `services.relay.secrets` and under the top-level `secrets`.
4. In `config.yaml`, set `providers.<name>.enabled: true`.

Then set `sending.enabled: true`, and check and restart:

```sh
docker compose run --rm --no-deps relay check-config
docker compose up -d --force-recreate
```

`check-config` should now list the provider under `live providers`. The relay reads its configuration only at startup, so restart it after every change to `config.yaml`. To return to dry-run mode, set `sending.enabled: false` and restart.

## 10. Send a test notification

```sh
docker compose stop relay
docker compose run --rm relay test-notification --recipient owner_sms
docker compose start relay
```

The test message goes through the delivery engine like any alert, so the global cap, dry-run routing and attempt records apply, and it is recorded in the state directory. A running relay holds an exclusive lock on that directory, so the relay must be stopped first; otherwise the command exits with code 4. Keep the stop short: nothing is monitored while it is stopped.

The command prints one line, such as `test notification: delivered to owner_sms (live)`, and exits 0 when the message was delivered (or logged, in dry-run mode) and 1 when it was not. A dry-run recipient gets nothing: the message is only written to the log. [operations.md](operations.md#exit-codes) lists the exit codes.

## Optional health endpoint

Set `health.enabled: true` in `config.yaml`. By default it listens on `127.0.0.1:8080` inside the container, which only the container itself can reach, and no port is published. You can then:

- **Let Docker check it:** uncomment the `healthcheck` block in `compose.yaml`. `docker compose ps` then shows the container as healthy or unhealthy. The endpoint always answers 200, so this shows that the relay is alive and serving, not that monitoring is ok; read the document's `status` for that. Docker itself does not restart an unhealthy container.
- **Reach it from the host:** set `health.bind: 0.0.0.0` in `config.yaml` (`check-config` then warns that it is not loopback, which is expected inside a container) and publish the port on the host's loopback only:

  ```yaml
  services:
    relay:
      ports:
        - "127.0.0.1:8080:8080"
  ```

  Then `curl -s http://127.0.0.1:8080/health`. Do not publish it on every interface (`"8080:8080"`). The document holds no secrets or recipient data, but it does reveal the relay's version and state. If a monitoring system on another host needs it, restrict access with a firewall or an authenticating reverse proxy.

The document's fields are described in [operations.md](operations.md#health-endpoint).

## Upgrades

Every upgrade starts with a backup: it is what makes a [rollback](#rollback) possible, because a newer release may upgrade the state database's format and an older release cannot read it.

1. Read the release notes for configuration changes.
2. Build (or, later, pull) the new image with a new tag. Do not change `.env` yet, and keep the previous image for rollback.
3. Stop the relay and [take a backup](#back-up-the-state-volume). Note the archive's name.
4. Set the new tag in `.env` (`VRM_ALERT_RELAY_IMAGE`), and check the configuration with it: `docker compose run --rm --no-deps relay check-config`.
5. Start it: `docker compose up -d`.
6. Watch the logs for `service.started` and the first `relay.cycle`, with no `state.*` errors.

## Backup and restore

The state volume holds rule state, delivery records and the send history behind the rate limits. The commands below use a BusyBox image, pinned by digest, as a throwaway tool container with no network. They run as root inside that container, because they have to read and write files owned by UID 65532. Set these two variables first, in the deployment directory (the second needs [jq](https://jqlang.org/)):

```sh
cd /opt/vrm-alert-relay
busybox='busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e'  # BusyBox 1.37.0
state_volume="$(docker compose config --format json | jq -r '.volumes.state.name')"
echo "$state_volume"
```

`state_volume` is the volume the relay uses now: `vrm-alert-relay-state`, or the one named by `VRM_ALERT_RELAY_STATE_VOLUME` in `.env` after a restore.

### Back up the state volume

Stop the relay for the copy, so the SQLite database, its WAL file and the journal are consistent. The archive is owned by root with mode `0600`, in a directory only root can read, because it holds delivery records and message text:

```sh
sudo install -d -m 0700 backups
docker compose stop relay
archive="state-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
docker run --rm --network none \
  -v "$state_volume:/state:ro" -v "$PWD/backups:/backup" "$busybox" \
  sh -euc 'tar -C /state -czf "/backup/$1" . && chown 0:0 "/backup/$1" && chmod 0600 "/backup/$1"' sh "$archive"
echo "$archive"
```

Inside the archive, the files keep their numeric owner (65532) and modes. Then start the relay again with `docker compose start relay`, or, during an upgrade, continue with upgrade step 4.

### Restore into a new volume

A restore never empties or overwrites the volume in use. It checks the archive, restores it into a new volume, verifies the result, and only then points the relay at the new volume. The old volume stays untouched, so you can switch back to it.

1. Stop the relay and choose the archive:

   ```sh
   docker compose stop relay
   archive=state-20260115T120000Z.tar.gz
   ```

2. Check the archive. This lists it in full, which fails on a truncated or corrupt file, and requires the state database:

   ```sh
   docker run --rm --network none -v "$PWD/backups:/backup:ro" "$busybox" \
     sh -euc 'tar -tzf "/backup/$1" > /tmp/contents && cat /tmp/contents &&
       grep -qx "./relay-state.sqlite3" /tmp/contents && echo "archive ok"' sh "$archive"
   ```

   Stop if it does not end with `archive ok`.

3. Restore it into a new volume, set the owner and modes explicitly (directory `0700`, files `0600`, all owned by `65532:65532`), and check that the database is a SQLite file:

   ```sh
   new_volume="vrm-alert-relay-state-$(date -u +%Y%m%dT%H%M%SZ)"
   docker volume create "$new_volume"
   docker run --rm --network none \
     -v "$new_volume:/state" -v "$PWD/backups:/backup:ro" "$busybox" \
     sh -euc 'tar -C /state -xzf "/backup/$1"
       chown -R 65532:65532 /state
       chmod 0700 /state
       find /state -type f -exec chmod 0600 {} \;
       [ "$(head -c 15 /state/relay-state.sqlite3)" = "SQLite format 3" ]
       ls -lan /state
       echo "restore ok"' sh "$archive"
   ```

   Stop if it does not end with `restore ok`; the relay's current volume is unchanged.

4. Point the relay at the new volume and start it:

   ```sh
   sudo sed -i '/^VRM_ALERT_RELAY_STATE_VOLUME=/d' .env
   echo "VRM_ALERT_RELAY_STATE_VOLUME=$new_volume" | sudo tee -a .env
   docker compose up -d
   docker compose logs relay | grep -E '"event": ?"(service.started|relay.cycle|state\.[a-z_]+)"'
   ```

   Compose may warn that the volume was not created by Compose; that is expected. Look for `service.started` and `relay.cycle` without `state.*` errors.

To switch back, set `VRM_ALERT_RELAY_STATE_VOLUME` to the previous volume (the original one is `vrm-alert-relay-state`) and run `docker compose up -d` again. Once you are sure you no longer need an old volume, remove it with `docker volume rm <name>`.

Restoring older state can repeat notifications that were sent after the backup was taken, because the relay no longer knows it sent them. The global cap still applies.

## Rollback

Roll back state and image together, before the older image ever starts: if the newer release upgraded the state database's format, the older one cannot read it and would run from memory only.

1. Stop the relay: `docker compose stop relay`.
2. Restore the backup taken in upgrade step 3 into a new volume: follow [restore](#restore-into-a-new-volume) steps 2 and 3, then set `VRM_ALERT_RELAY_STATE_VOLUME` in `.env` as in restore step 4, but do not start the relay yet.
3. Set `VRM_ALERT_RELAY_IMAGE` in `.env` back to the previous image tag, and restore the previous `config.yaml` if you changed it.
4. Check the configuration with the older image: `docker compose run --rm --no-deps relay check-config`.
5. Start it: `docker compose up -d`, and watch the logs as after a restore.

The volume the newer release used is kept, so you can return to it when you upgrade again. Anything the relay recorded after the backup is not carried back, so some notifications sent since then may repeat, within the global cap.

## Uninstall

```sh
cd /opt/vrm-alert-relay
docker compose down --volumes   # removes the container, its network and the state volume
docker image rm "$(grep VRM_ALERT_RELAY_IMAGE .env | cut -d= -f2)"
cd / && sudo rm -rf /opt/vrm-alert-relay   # configuration, secret files and backups
```

Plain `docker compose down` keeps the state volume, for a later reinstall. Then revoke the credentials the relay used: the VRM access token, the Home Assistant token, the webhook token, and the VoIP.ms API password and its allowed IP addresses.

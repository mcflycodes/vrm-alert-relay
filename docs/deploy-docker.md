# Deploying with Docker Compose

**Updated:** 2026-10-11

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

Once release images are published, use `ghcr.io/OWNER/vrm-alert-relay:VERSION` (the placeholder in the Compose file), ideally pinned by digest, instead of building.

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

1. Read the release notes for configuration changes.
2. [Back up the state volume](#backup-and-restore).
3. Build (or, later, pull) the new image with a new tag, and set it in `.env`. Keep the previous image for rollback.
4. Check the configuration with the new image: `docker compose run --rm --no-deps relay check-config`.
5. Restart: `docker compose up -d`.
6. Watch the logs for `service.started` and the first `relay.cycle`, with no `state.*` errors.

State is kept across upgrades. A newer release may upgrade the state database's format when it starts.

## Backup and restore

The state volume holds rule state, delivery records and the send history behind the rate limits. Back it up before every upgrade. Stop the relay for the copy, so the SQLite database, its WAL file and the journal are consistent. Any image with `tar` will do; this uses BusyBox:

```sh
cd /opt/vrm-alert-relay
sudo install -d -m 0700 backups
docker compose stop relay
docker run --rm --network none \
  -v vrm-alert-relay-state:/state:ro -v "$PWD/backups:/backup" \
  busybox:1.37 tar -C /state -czf "/backup/state-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" .
docker compose start relay
```

The archive holds delivery records and message text, so keep it private.

To restore, stop the relay, replace the volume's contents, and fix the directory's owner and mode:

```sh
docker compose stop relay
docker run --rm --network none \
  -v vrm-alert-relay-state:/state -v "$PWD/backups:/backup:ro" \
  busybox:1.37 sh -c 'find /state -mindepth 1 -delete &&
    tar -C /state -xzpf /backup/state-20260115T120000Z.tar.gz &&
    chown 65532:65532 /state && chmod 0700 /state'
docker compose start relay
```

Restoring older state can repeat notifications that were sent after the backup was taken, because the relay no longer knows it sent them. The global cap still applies.

## Rollback

1. Set `VRM_ALERT_RELAY_IMAGE` in `.env` back to the previous image tag, and restore the previous `config.yaml` if you changed it.
2. Restart: `docker compose up -d`.

If the newer release upgraded the state database's format, the older one cannot read it. It does not touch the file, keeps alerting from memory, and reports `state_persistence.healthy: false` and sends a storage notice. In that case stop the relay, restore the backup taken before the upgrade, and start it again.

## Uninstall

```sh
cd /opt/vrm-alert-relay
docker compose down --volumes   # removes the container, its network and the state volume
docker image rm "$(grep VRM_ALERT_RELAY_IMAGE .env | cut -d= -f2)"
cd / && sudo rm -rf /opt/vrm-alert-relay   # configuration, secret files and backups
```

Plain `docker compose down` keeps the state volume, for a later reinstall. Then revoke the credentials the relay used: the VRM access token, the Home Assistant token, the webhook token, and the VoIP.ms API password and its allowed IP addresses.

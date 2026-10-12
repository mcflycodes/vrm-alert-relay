# VRM access and data freshness

**Updated:** 2026-10-11

VRM Alert Relay is an unofficial, independent project. It is not affiliated with, sponsored by, or endorsed by Victron Energy. Victron and VRM are named here only to describe compatibility.

The relay reads measurements from the VRM API with a VRM access token. It makes one request per installation per poll, `GET /installations/<site_id>/diagnostics`, and never writes to VRM or controls a device. The token, however, carries every permission of the VRM user it belongs to, so the user is what limits the damage if the token leaks. VRM's menus and role names change; the steps below describe them as at the time of writing.

## 1. Create a dedicated VRM user

Use a VRM user that exists only for the relay, not your own login:

1. Create a new VRM account for the relay, with its own email address (for example a mailbox alias) and a strong, unique password. Turn on two-factor authentication for it.
2. From an account that administers each installation you want to monitor, invite the relay's user to **only those installations**. Every installation it can see is one more a leaked token could reach.
3. Give it the **lowest access level that can read Diagnostics through the API**.

### Which access level

Which access level is enough to read Diagnostics through the API has not been verified for this project. Test it:

1. Invite the user with the **read-only** level first.
2. Create its token (below), configure the relay, and run one cycle in dry-run mode (`docker compose run --rm relay run --once`, see [deploy-docker.md](deploy-docker.md#7-run-in-dry-run-mode)).
3. If the log shows `"vrm fetch failed"` with `"vrm_failure": "auth"` and `"vrm_detail": "HTTP 403"` for the installation, the level is not enough. An `auth` failure marks the installation's monitoring degraded at once; the relay then retries hourly.

If read-only is refused, the next level up is **Technician**. Understand what that grants before using it: a Technician can change device settings and use the Remote Console, which can control the installation's equipment. Anyone holding the token could do the same through the API. If you have to use it:

- keep the invitation to the monitored installations only;
- protect the token file as described below, and keep the relay host itself locked down;
- revoke the token at once if the host or the file may have been exposed.

Never use an administrator account's token.

## 2. Create an access token

Log in to VRM as the relay's user and create a personal access token (under **Preferences → Integrations → Access tokens** at the time of writing). Give it a name that identifies the deployment, such as `alert-relay`. Copy it; VRM shows it only once.

Store it as the relay's `vrm.token_file`. With the Docker deployment, that is `secrets/vrm_token`, created as described in [deploy-docker.md](deploy-docker.md#4-create-the-secret-files) so that the token never appears in your shell history. The relay never logs it.

### Find the installation id

`vrm.installations[].site_id` is the numeric VRM installation id (`idSite`). When you open the installation in VRM, it is the number in the address bar after `/installation/`, for example `https://vrm.victronenergy.com/installation/123456/dashboard`. It is not the GX device's "VRM portal ID", which is a longer hexadecimal string.

### Find measurement codes

A rule's `measurement` names a record in the installation's Diagnostics data by its `code` and `instance` (and `service_type`, which matches the record's `dbusServiceType`, when those two are not unique). To list them, query the same endpoint the relay uses. This reads the token without echoing it and passes the header on standard input, so the token appears neither in your history nor in the process list:

```sh
read -rs -p 'VRM access token: ' token; echo
printf 'X-Authorization: Token %s\n' "$token" |
  curl -fsS -H @- 'https://vrmapi.victronenergy.com/v2/installations/123456/diagnostics?count=1000' |
  jq -c '.records[] | {code, instance, dbusServiceType, description, formattedValue}'
unset token
```

## Rotate or revoke the token

- **Rotate:** create a new token for the relay's user, write it into the secret file (the same `sudo tee` step as when you created it), restart the relay (`docker compose up -d --force-recreate`), confirm that polls succeed, then delete the old token in VRM.
- **Revoke:** delete the token in VRM. The relay's next poll fails with `auth` and every installation's monitoring is reported degraded, so you will notice if it was still in use.
- **Remove access:** removing the relay's user from an installation has the same effect for that installation.

## How fresh is the data

The relay can only see what the GX device has uploaded to VRM. The device uploads at its **log interval**, set on the GX device under **Settings → VRM online portal → Log interval**. Its default at the time of writing is 15 minutes, so a reading in VRM can be up to 15 minutes old before the relay polls it, and the relay's `vrm.poll_interval` (60 seconds by default) adds at most a minute to that.

- **For faster alerts, shorten the log interval** on the GX device, for example to 1 or 5 minutes. Polling the API more often than the device uploads does not make data fresher. A shorter interval uploads more data, which matters on a metered mobile connection.
- **Tune `stale_after_minutes` to match.** A rule reports stale data when its newest reading is older than `stale_after_minutes`. The default, 35 minutes, is two default log intervals plus five minutes of margin, so one late upload does not raise a false alarm. A reasonable rule is twice the log interval plus five minutes: 15 minutes for a 5-minute interval, 7 for a 1-minute interval. It must be longer than `vrm.poll_interval`.
- **The relay never polls faster than 30 seconds** (`vrm.poll_interval` minimum), and honours VRM's rate limits (`429` and `Retry-After`) with backoff.

A stale reading and a failing poll are different signals. Stale data means VRM answered but the measurement's newest reading is too old, for example because the GX device lost its connection; the rule's recipients get a "stale data" message. A failing poll means the relay could not get the data from VRM at all; the system recipients get "monitoring degraded" ([operations.md](operations.md#monitoring-degraded-and-restored)).

## Keep native VRM alarms enabled

VRM's own alarms and the GX device's alarms work independently of this relay. Keep them enabled for every condition that matters. The relay adds escalation, reminders and other delivery channels, but it is one more component that can fail: its host, its network path, the VRM API and the notification providers are all outside its control. It must not be the only safeguard for conditions that could cause injury, fire, flooding or equipment damage.

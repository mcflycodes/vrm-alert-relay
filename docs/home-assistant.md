# Home Assistant notifications

**Updated:** 2026-10-11

VRM Alert Relay is an unofficial, independent project. It is not affiliated with, sponsored by, or endorsed by Victron Energy, or with the Home Assistant project.

The `homeassistant` provider calls a Home Assistant `notify` action (service) for each message: `POST <base_url>/api/services/notify/<service>` with a bearer token and the body `{"message": "<text>", "title": "VRM Alert Relay"}`. Which answers count as delivered, refused or retried is described in [notifications.md](notifications.md#homeassistant). Home Assistant then delivers the notification however that notify action does: to the companion app, as a persistent notification, to a notify group, and so on.

## 1. Create a dedicated, non-admin user

Give the relay its own Home Assistant user, so its token can be revoked on its own and its actions are identifiable in Home Assistant's logbook.

1. In Home Assistant, go to **Settings → People** and add a person, for example `VRM Alert Relay`.
2. Turn on **Allow person to login**, set a username and a strong password, and leave **Administrator** off.
3. Log in as that user (a private browser window is easiest), open the user's profile, and on its **Security** tab create a **long-lived access token**. Copy it; Home Assistant shows it only once.
4. Log out.

A non-admin user cannot change Home Assistant's configuration, but Home Assistant has no per-action permissions: its token can still call other actions through the API, including ones that switch devices. Treat it as a sensitive credential, keep it in a secret file, and revoke it from the same **Security** tab if it may have leaked.

Store the token as the relay's secret file. With the Docker deployment, follow [deploy-docker.md](deploy-docker.md#4-create-the-secret-files) to create `secrets/homeassistant_token`, and uncomment `homeassistant_token` in `compose.yaml`.

## 2. Choose the notify action

The relay's recipients name a notify action without its `notify.` prefix. To see the ones available, open **Developer tools → Actions** in Home Assistant and type `notify.`. Common choices:

| Notify action | Recipient `service` | Delivers to |
|---|---|---|
| `notify.mobile_app_example_phone` | `mobile_app_example_phone` | The Home Assistant companion app on one phone. The name comes from the device name set in the app. |
| `notify.persistent_notification` | `persistent_notification` | A notification in Home Assistant's own sidebar. Useful for testing, and as a record. |
| `notify.relay_alerts` (a notify group you define) | `relay_alerts` | Several targets at once. See Home Assistant's notify group documentation. |

The relay calls notify actions by name, as listed under `notify.` above. It does not use the newer notify entities (`notify.send_message` with a target entity), so pick an action that appears by its own name.

Try the action in **Developer tools → Actions** first, with a test message, to confirm it reaches you.

## 3. Configure the relay

```yaml
recipients:
  owner_phone_app:
    provider: homeassistant
    service: mobile_app_example_phone
  ha_sidebar:
    provider: homeassistant
    service: persistent_notification

providers:
  homeassistant:
    enabled: true
    base_url: https://homeassistant.example.test:8123
    token_file: /run/secrets/homeassistant_token
```

Then add the recipients to rules (and, if you like, to `system_recipients`), set `sending.enabled: true`, run `check-config`, restart, and send a test with `test-notification --recipient owner_phone_app` ([deploy-docker.md](deploy-docker.md#10-send-a-test-notification)). Every setting is listed in [configuration.md](configuration.md#providershomeassistant).

The relay sends only a message and a fixed title. It cannot set companion-app options such as priority, sound or critical alerts. If you need those, point the relay's `webhook` provider at a Home Assistant automation with a webhook trigger instead, and have that automation call the notify action with the options you want; the message text is in the payload's `text` field ([notifications.md](notifications.md#webhook)).

## HTTP, HTTPS, or a private CA

The relay refuses plain `http://` unless you opt in, and always verifies certificates. Pick the first option that fits:

1. **HTTPS with a publicly trusted certificate**, for example from a reverse proxy or Home Assistant's own certificate setup. Nothing else is needed.
2. **HTTPS with a private CA or a self-signed certificate.** Put the CA certificate (or the self-signed certificate itself) in a PEM file and set `ca_file`. The provider then trusts only that file. The host name in `base_url` must match a name in the certificate: if the certificate names `homeassistant.example.test`, do not connect by IP address. With Docker, save the PEM file as `homeassistant-ca.pem` next to `compose.yaml`, readable by UID 65532 (mode `0444` is fine: it is not secret), and uncomment `homeassistant_ca.pem` in both `secrets` lists of `compose.yaml`, which mounts it read-only at `/run/secrets/homeassistant_ca.pem`:

   ```yaml
   providers:
     homeassistant:
       enabled: true
       base_url: https://homeassistant.example.test:8123
       token_file: /run/secrets/homeassistant_token
       ca_file: /run/secrets/homeassistant_ca.pem
   ```

3. **Plain HTTP with `allow_insecure_http: true`.** The token and every message then cross the network unencrypted, so anyone on the path can read the token, use it against Home Assistant, or change the messages. `check-config` warns about it every time. Consider it only when the traffic never leaves a network segment you control, such as both on one host or one isolated VLAN, and prefer option 2 whenever you can.

There is no setting that turns certificate verification off.

## Troubleshooting

Each attempt is logged with `"provider": "homeassistant"`, an `event` of `provider.delivered`, `provider.failed` or `provider.ambiguous`, a `retryable` flag and a `reason`. Configuration problems show up in `check-config` first.

| What you see | Likely cause |
|---|---|
| `check-config`: `providers.homeassistant.base_url: must be an https:// URL ...` | The URL uses `http://`. Use HTTPS, or opt in with `allow_insecure_http` (above). |
| `check-config`: `providers.homeassistant.ca_file: CA file could not be loaded as PEM certificates` | The file is missing in the container, not readable by UID 65532, or not PEM. |
| `provider.failed`, `retryable: false`, `reason: HttpStatusError` | Home Assistant answered 4xx: usually 401 (wrong or revoked token) or 400 (a notify action that does not exist, or a typo in `service`). Check the token and the action name in **Developer tools → Actions**. Not retried. |
| `provider.failed`, `retryable: true` | A timeout or connection failure before the request was sent, or an answer of 408, 425 or 429. Retried with backoff. Check that the relay's host can reach Home Assistant (DNS, firewall, port). |
| `provider.ambiguous`, `reason: HttpStatusError` | Home Assistant answered 5xx. The message may or may not have arrived; it is retried within the retry limit. |
| `provider.ambiguous`, `reason: HttpRedirectRefused` | A redirect, which the relay never follows: often HTTP redirected to HTTPS, or a reverse proxy that expects a different path. Use the final URL in `base_url`. |
| `provider.failed`, `retryable: true`, `reason: HttpTransportError`, right after a certificate change | TLS failed: the certificate does not match the host name, or is not signed by the CA in `ca_file` (or a public CA when there is no `ca_file`). |
| Requests start failing after several 401s | Home Assistant's IP ban (`http: ip_ban_enabled`) may have banned the relay's address after failed logins. Remove it from `ip_bans.yaml` in Home Assistant, fix the token, and restart Home Assistant. |
| `provider.delivered`, but nothing on the phone | Home Assistant accepted the call; delivery from there is up to Home Assistant and the companion app. Check the app's notification permissions and test the action in **Developer tools**. |

The relay does not log Home Assistant's response status or body, so the exact 4xx or 5xx code is visible only in Home Assistant's own logs.

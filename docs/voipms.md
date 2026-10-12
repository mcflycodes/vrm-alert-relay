# VoIP.ms SMS

**Updated:** 2026-10-11

VRM Alert Relay is an unofficial, independent project. It is not affiliated with, sponsored by, or endorsed by Victron Energy, or with VoIP.ms.

The `voipms` provider sends SMS from a VoIP.ms DID through the VoIP.ms REST API, using your own VoIP.ms account. What it sends and how it treats each answer is described in [notifications.md](notifications.md#voipms). VoIP.ms account settings, limits and prices change; check VoIP.ms's own documentation and pricing for the current state. Statements below about VoIP.ms are as of the time of writing.

## What you need

- A VoIP.ms account with a DID (phone number) that has SMS enabled. VoIP.ms sends SMS only to US and Canadian numbers, and the relay accepts only those.
- The relay host's public egress IP address, for the API allowlist. If the relay runs behind NAT, it is the address your traffic leaves from, not the host's private address.

## 1. Enable the API

In the VoIP.ms customer portal, open the API settings page (**Main Menu → SOAP and REST/JSON API** at the time of writing):

1. **Enable API.**
2. Set an **API password**. It is separate from your account password. Use a long random value used nowhere else; the relay never needs your account password.
3. Under **Enable IP Addresses**, add only the relay host's egress IP address. VoIP.ms refuses API calls from other addresses (`ip_not_enabled`), so a leaked API password is far less useful.

If your egress address changes (a dynamic residential IP, for example), the relay's calls start failing with `ip_not_enabled` until you update the allowlist. A static address, or a VPN or proxy host with one, avoids that.

## 2. Enable SMS on the DID

In the DID's settings, enable the SMS/MMS message service. The DID becomes the sender of every alert (`providers.voipms.did`).

**Messaging registration:** automated alerts are application-to-person (A2P) traffic. US carriers filter unregistered A2P traffic, and VoIP.ms requires messaging registration or verification for it. Complete whatever VoIP.ms currently requires for your DID before relying on it: unregistered messages may be refused or silently filtered by carriers, and a provider that accepted a message cannot tell the relay that a carrier dropped it later.

## 3. Set provider-side limits

The relay's global cap (20 per hour and 60 per day by default) bounds normal operation. In rare failure modes, such as state storage failing across restarts, each process enforces the cap from memory only, and provider-side limits are the final backstop (ADR 0002). Keep them in place:

- **Daily SMS limit:** at the time of writing, VoIP.ms limits SMS sent through the API to 100 per day by default. Keep a limit like this rather than raising it far above what alerting needs. The relay treats VoIP.ms's limit answers (`limit_reached`, `api_limit_exceeded`) as temporary and retries within its retry limit.
- **Balance alerts:** VoIP.ms accounts are prepaid. Set a low-balance notification in the portal, and keep enough funds that alerts do not stop when they matter. Consider a modest auto-recharge, or none, so that a runaway would exhaust a bounded amount.

## 4. Store the credentials

The relay needs three settings:

| Setting | Value |
|---|---|
| `providers.voipms.username_file` | A file holding your VoIP.ms account login (the email address). |
| `providers.voipms.password_file` | A file holding the **API password** from step 1. |
| `providers.voipms.did` | The SMS-enabled DID, quoted, for example `"202-555-0100"`. |

With the Docker deployment, create `secrets/voipms_username` and `secrets/voipms_api_password` as described in [deploy-docker.md](deploy-docker.md#4-create-the-secret-files), and uncomment both in `compose.yaml`. Then:

```yaml
recipients:
  owner_sms:
    provider: voipms
    phone: "+1 202 555 0142"

providers:
  voipms:
    enabled: true
    username_file: /run/secrets/voipms_username
    password_file: /run/secrets/voipms_api_password
    did: "202-555-0100"
```

Set `sending.enabled: true`, run `check-config`, restart, and send one test message with `test-notification --recipient owner_sms` ([deploy-docker.md](deploy-docker.md#10-send-a-test-notification)). Every setting is listed in [configuration.md](configuration.md#providersvoipms).

## Message length and cost

- Each SMS is at most 160 characters. Longer text is cut to 157 characters plus `...`. Keep level messages short so the useful part comes first: the default texts start with the level, rule and installation. Dry-run log records show the text exactly as it would be sent.
- Each alert is one SMS per recipient, plus any retries and reminders, all within the global cap. VoIP.ms charges per message; check VoIP.ms pricing for the current rate. With the default cap, the worst case is 60 messages a day.

## Ambiguous sends and reconciliation

When the relay cannot tell whether VoIP.ms accepted a message (a timeout after the request was sent, an unreadable answer, an unknown status, or a restart in the middle of a send), it looks the message up with VoIP.ms's `getSMS` before retrying, and counts it as sent only on an exact match of the message id, DID and recipient. If the lookup cannot prove either way, it retries, within the retry limit. A rare duplicate SMS is therefore possible, by design: the relay favours alerting over silence. The exact rules are in [notifications.md](notifications.md#voipms) and ADR 0002.

## Troubleshooting

VoIP.ms reports most errors as HTTP 200 with a `status` other than `success`. Each attempt is logged with `"provider": "voipms"`, an `event` of `provider.delivered`, `provider.failed` or `provider.ambiguous`, and the status as its `reason`. Lookups are logged as `provider.reconcile`.

| `reason` | Retried | Meaning and fix |
|---|---|---|
| `success` | n/a | VoIP.ms accepted the message. Delivery to the handset is up to the carriers. |
| `invalid_credentials` | No | The login or API password is wrong. Check both secret files, and that `password_file` holds the API password, not the account password. |
| `missing_credentials` | No | VoIP.ms did not receive the credentials. The relay always sends them, so check that `base_url` points straight at the VoIP.ms API and nothing in between rewrites the request. |
| `api_not_enabled` | No | The API is not enabled on the account (step 1). |
| `ip_not_enabled` | No | The relay's egress IP address is not on the API allowlist, or it has changed (step 1). |
| `invalid_did`, `missing_did` | No | `providers.voipms.did` is not a DID on this account, or SMS is not enabled on it (step 2). |
| `invalid_dst`, `missing_dst` | No | VoIP.ms does not accept the recipient's number for SMS. |
| `sms_toolong`, `missing_message` | No | Should not happen, because the relay trims to 160 characters; report it as a bug. |
| `invalid_method`, `missing_method` | No | The `base_url` does not point at the VoIP.ms REST API. |
| `limit_reached`, `api_limit_exceeded` | Yes | A VoIP.ms sending or API limit was reached. Messages are retried with backoff, within the retry limit. If it happens often, the relay is sending more than expected: look at why before raising the limit. |
| `method_maintenance` | Yes | VoIP.ms maintenance. Retried. |
| `sms_failed` | Yes | VoIP.ms could not send this time. Retried. |
| `unrecognized`, `missing`, `malformed_response` | Reconciled | An answer the relay does not recognise. The send is treated as ambiguous: looked up, then retried if needed. |
| `HttpStatusError`, `HttpTransportError`, `HttpTimeout` | Depends | An HTTP-level failure. Before the request was sent, it is retried; after, it is ambiguous and reconciled. Check the host's outbound HTTPS access. |

If messages show `provider.delivered` but never arrive, check the DID's messaging registration status and the VoIP.ms SMS log in the portal: carrier filtering happens after VoIP.ms accepts a message.

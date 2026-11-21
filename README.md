# SENTINEL

**English** · [ภาษาไทย](README.th.md)

A self-hosted **security monitor for one Windows PC and your websites**, built for a single admin. It watches the PC's protection, logs and installed software plus your sites' uptime and TLS. It raises findings with real evidence and sends short, plain-language alerts to Telegram, with exactly where to click to fix each one.

It runs on the PC itself (Node 22, SQLite, no Docker, no cloud backend) and listens on `127.0.0.1` only. You can reach it from your phone over Tailscale.

> The UI and Telegram messages are in **Thai**, with English underneath. Code, comments and tests are in English.

## What it watches

| Area | Details |
|---|---|
| **PC metrics** | CPU, memory, every disk, network and battery, every minute. Overload-aware, so a game or a build doesn't page you. |
| **Windows Event Log** | Logons (success/fail, RDP), new accounts, admin group changes, cleared logs, new services, Defender detections and Defender being switched off. |
| **Device health** (every 30 min, read-only) | Defender on and updated, firewall, Windows Update, BitLocker/device encryption, SSD health, battery wear, UAC, remote-control tools, programs listening on every network |
| **Persistence** | New auto-start entries and scheduled tasks are checked by digital signature. Fakes such as `svchost.exe` outside `C:\Windows` are rated critical. |
| **Defender exclusions** | Dangerous exclusions (a whole drive, temp folders, system binaries), a classic malware trick |
| **New programs** | Anything new in the installed-programs list. Unsigned programs, modified signatures (e.g. `HashMismatch`) and crack/repack names are flagged. |
| **Browser extensions** | Chrome, Brave, Edge, Vivaldi and Opera. Sideloaded or policy-forced extensions, broad permissions, and updates that quietly add permissions. |
| **Hosts / DNS / proxy** | Hosts lines that fake or block banks, Google, Microsoft, Defender or Telegram. Unknown DNS servers, remote proxies, PAC scripts, WinHTTP proxy, NRPT rules. |
| **Certificates, firewall, security switches** | New trusted root certificates (which let someone fake any site's padlock), new inbound firewall allow rules judged by program signature, folder and port, and switches such as Remote Desktop, WDigest, LSA protection, SmartScreen, SMB1 and the Guest account. |
| **USB drives, keyboards, Wi-Fi** | A USB drive the PC has never seen (caught even if pulled out before the next check), BadUSB-style "keyboards" built on hobby boards or arriving with a new drive, saved password-less Wi-Fi that auto-connects, and being on an open Wi-Fi right now. |
| **Defender scans** | Start quick/full/offline scans from the phone; the result arrives on Telegram. Optional weekly automatic quick scan. |
| **Websites / APIs** | HTTP status, latency, keyword, TLS expiry, security headers (SSRF-guarded) |
| **SENTINEL itself** | Password guessing, correct password with a wrong 2FA code, sign-in from a new device, plus a dead man's switch via healthchecks.io |

There are **34 detection rules** with adjustable thresholds. Every finding carries the log lines or values behind it, and most findings close on their own once the problem is fixed.

## Alerting and response

- Alert rules with dedup, repeat intervals, acknowledge and auto-resolve. Telegram delivery has retries and a delivery history.
- Incidents (open → acknowledged → investigating → resolved → closed) with timeline, notes, linked evidence and automatic correlation.
- A daily digest, plus a weekly summary: scans, new programs, backup test, reminders.
- From the phone, after a 2FA unlock: lock, sleep, restart or shut down the PC, close a program, open an app.

## Security of SENTINEL itself

- Argon2id password, TOTP 2FA, and fingerprint/passkey unlock (WebAuthn) for the app PIN.
- Step-up re-authentication for sensitive changes. Short sessions with an idle timeout.
- Hash-chained audit log. Secrets are encrypted with a local `master.key`.
- Daily backups, optionally copied to a cloud folder as **passphrase-encrypted** `.sbk` files (AES-256-GCM, scrypt).
- A **monthly automatic restore test** of the newest cloud copy, and a "test passphrase" button.
- Safe to test: under `LOCAL_TEST=1` / `POWER_DRY_RUN=1` no power, close-program, launch or scan command really runs.

## Getting started

Requirements: **Windows 10/11** and **Node.js 22.13+**.

```bash
npm install
npm run build
npm start
```

Open http://127.0.0.1:3001. On first run you create the admin password (at least 12 characters). Then turn on 2FA under **Settings → Account & MFA**.

To read the Security event log, run SENTINEL as Administrator, or add your account to *Event Log Readers* once (then sign out and in):

```bash
net localgroup "Event Log Readers" "%USERNAME%" /add
```

### Run in the background

Run this once, from an elevated terminal:

```bash
npm run service:install
```

This registers a scheduled task that starts SENTINEL hidden at sign-in, restarts it if it stops, and runs it with the rights it needs. Use `service:status`, `service:stop`, `service:start` and `service:uninstall` to manage it. Logs go to `data/logs/sentinel.log`.

### Phone access

Keep SENTINEL on `127.0.0.1` and publish it only inside your tailnet:

```bash
tailscale serve --bg --https=8443 http://127.0.0.1:3001
```

Don't use `tailscale funnel`, which would put it on the public internet. The web app can be installed on the phone's home screen.

### Telegram

**Alert Manager → Notifications → Connect Telegram**, follow the steps, then press **Send test**. The bot token is encrypted with `data/master.key`.

## Configuration (`.env`, all optional)

| Variable | Default | Meaning |
|---|---|---|
| `PORT` / `HOST` | `3001` / `127.0.0.1` | Local only by default |
| `DATA_DIR` | `data` | Database, key and backups |
| `ALLOW_PRIVATE_TARGETS` | `false` | `true` to monitor localhost/LAN URLs (blocked by the SSRF guard) |
| `ALLOWED_HOSTS` | (none) | Extra host names to answer, comma separated. IPs, `localhost` and `*.ts.net` always work (DNS-rebinding guard). |
| `COOKIE_SECURE` | `false` | `true` when served over HTTPS |
| `BACKUP_COPY_DIR` | (none) | A cloud-synced folder that receives a copy of every backup |
| `HEARTBEAT_URL` | (none) | healthchecks.io ping URL (dead man's switch) |
| `ANTHROPIC_API_KEY` | (none) | Optional AI summary of an incident (Claude). Off unless set. |

See [`.env.example`](.env.example).

## Data, backup and restore

- Everything lives in `data/`: `sentinel.db` (SQLite) and `master.key`. **Never commit this folder.**
- Backups are taken daily and 7 are kept. Restore with `npm run restore -- <backup file>`; the current data is moved aside, not deleted.
- Retention: metrics 15 days, security log 14 days, alerts/findings 90 days, incidents/audit 1 year or more.

## Tests

```bash
npm test                 # unit tests
npm run test:acceptance  # end-to-end against a real server with a scratch DB (~3 min)
npm run test:eval        # detection / correlation accuracy on labelled scenarios
npx tsc -b               # type check
```

## Project layout

```text
server/
  index.ts              schedulers and HTTP API (Express 5)
  db.ts                 schema and migrations (node:sqlite)
  lib/                  pure logic: detection helpers, judges, messages, crypto, SSRF guard …
  modules/              auth, device health, event log, detection, alerts, incidents, backup …
scripts/                device-health.ps1 (read-only snapshot), autostart, restore
web/src/                React 19 + Tailwind v4 + ECharts
tests/                  acceptance and detection-eval tests
docs/                   SRS, ADRs, database schema, test plan (Thai)
```

## Limits

- It detects from logs and settings it can read. It is **not an antivirus** and blocks nothing automatically.
- Websites hosted elsewhere are checked from the outside only (HTTP, TLS, headers).
- Correlation means "happened close together on the same asset", not proven cause.
- It has a single admin by design (see ADR-012).

## License

[MIT](LICENSE)

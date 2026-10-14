# Wazuh + OpenVAS Dashboard

A self-hosted dashboard for your home lab:

- Live Wazuh alerts (medium through critical), color-coded, auto-refreshing.
- A **Devices** inventory: add a device once, it's automatically registered
  as a Wazuh agent entry and an OpenVAS scan target; scan any device with
  a chosen scan type (Full and fast, Discovery, etc.) straight from the UI.
- Login with two roles: **admin** (add/delete devices, start scans) and
  **observer** (view alerts and devices only).
- An empty **Assistant** panel reserved for a future chatbot - no backend yet.

Node/Express backend, plain HTML/CSS/JS frontend. No build step.

## What it talks to

- **Wazuh indexer (OpenSearch)**, port 9200 by default - alerts live here
  (`wazuh-alerts-*` index).
- **Wazuh manager API**, port 55000 by default - used only to register/remove
  agents when you add/delete a device.
- **gvmd (GVM/OpenVAS)** over its GMP socket, port 9390 by default - creates
  targets, lists scan types, and starts/tracks scans.

## Setup

1. Install dependencies:
   ```bash
   npm install
   ```

2. Copy `.env.example` to `.env` and fill in your real values (see comments
   in the file for what each one is and how to find it):
   ```bash
   cp .env.example .env
   ```
   Generate a `SESSION_SECRET` with:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```

3. Create at least one admin login:
   ```bash
   npm run create-user
   ```
   It'll ask for a username, password, and role (`admin` or `observer`).
   Run it again to add more users - e.g. an `observer` account for people
   who should only view alerts/devices. Accounts are stored (bcrypt-hashed)
   in `data/users.json`, created automatically on first use.

   For scripted/non-interactive creation:
   ```bash
   CREATE_USER_NAME=admin CREATE_USER_PASS=secret CREATE_USER_ROLE=admin npm run create-user
   ```

4. Start it:
   ```bash
   npm start
   ```

5. Open `http://localhost:3000` - you'll land on the login page first.

## Roles

| Action                          | admin | observer |
|----------------------------------|:-----:|:--------:|
| View alerts                      |  ✅   |    ✅    |
| View devices                     |  ✅   |    ✅    |
| Add / delete devices             |  ✅   |    ❌    |
| Start an OpenVAS scan            |  ✅   |    ❌    |

Enforced server-side (every `/api/*` route checks the session), not just
hidden in the UI - an observer account can't do admin actions even by
calling the API directly.

## Devices

**Add a device** (name + IP, OS optional) and the dashboard automatically:

1. **Wazuh**: registers a new agent entry on the manager and gets back an
   agent ID + enrollment key. This is as far as *any* dashboard can
   automate it - actually installing/connecting the Wazuh agent **on the
   target machine** still requires running the agent installer there with
   that key (there's no way to remotely push software onto a box that
   doesn't already have an agent or SSH access set up). The device card
   shows the agent ID and a reminder once this step is pending.
2. **OpenVAS**: creates a scan Target for the device's IP. This part is
   fully automatic - OpenVAS scans over the network, no agent needed.

If either integration fails (wrong credentials, service unreachable), the
device is still saved with a clear per-service error badge - nothing is
silently lost.

**Scan a device**: pick a scan type from the dropdown (populated live from
your GVM instance's configured scan configs - Full and fast, Discovery,
etc.) and click Scan. The dashboard creates a Task bound to that device's
target + the chosen config, starts it, and polls progress until it
finishes, then refreshes the alerts list.

**Delete a device** removes its Wazuh agent entry and OpenVAS target too
(best-effort - any failure is reported as a warning rather than blocking
the deletion).

## Severity bands (alerts)

Wazuh `rule.level` is bucketed like this (edit `severityBand()` in
`lib/wazuh.js` if your ruleset maps it differently):

| Band     | rule.level |
|----------|-----------|
| Critical | ≥ 12      |
| High     | 10 – 11   |
| Medium   | 7 – 9     |

## Notes on TLS

Wazuh's indexer, the Wazuh manager API, and gvmd typically use self-signed
certs out of the box, so the `*_TLS_REJECT_UNAUTHORIZED` variables default
to `false` (skip verification). That's fine for a home lab talking to
`localhost`/your own LAN. If this ever leaves your own machine, put it
behind a reverse proxy with real TLS, set cookies to `secure`, and don't
loosen the rest further.

`GVM_USE_TLS=false` is only for setups where GMP is reached through a
plain-TCP proxy instead of gvmd's own TLS socket - leave it `true` unless
you know you need that.

## Project layout

```
server.js              Express app, auth + alerts + devices + scan routes
lib/wazuh.js            Queries the Wazuh indexer for alerts
lib/wazuhManager.js      Wazuh manager API client (agent register/remove)
lib/gvm.js               GMP client (targets, configs, tasks, start/status)
lib/users.js             User store (bcrypt-hashed, data/users.json)
lib/devices.js           Device store (data/devices.json)
lib/jsonStore.js         Tiny JSON-file read/write helper
lib/idgen.js             UUID generator (no extra dependency)
scripts/create-user.js   CLI to add admin/observer logins
public/login.html+js     Login page
public/index.html        Dashboard shell (tabs: Alerts / Devices / Assistant)
public/app.js             Frontend logic for all three tabs
public/style.css          Dark theme, badges, device cards, login page
.env.example              All config, copy to .env
data/                      users.json + devices.json, created on first use
```

## Extending it

- Wire a real model into the Assistant tab (`public/index.html` has the
  empty shell already).
- Add a `/api/scan/history` route (`get_reports`) to show past scan results.
- Push new critical alerts to a webhook (Slack/Discord) from `server.js`.
- Put this behind a reverse proxy with real TLS before exposing it beyond
  `localhost`.

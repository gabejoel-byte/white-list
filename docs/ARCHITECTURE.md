# Architecture

## Components

### Cloud dashboard / server (`server/`)
Node + Express + SQLite (`better-sqlite3`), no build step, no native crypto
(password hashing is stdlib scrypt). Serves two API surfaces and a static SPA:

- **`/api/v1/*`** — agent-facing: `enroll`, `heartbeat`. Bearer-token auth per
  device (`<deviceId>.<secret>`; only the scrypt hash of the secret is stored).
- **`/admin/api/*`** — dashboard: session-cookie auth; CRUD for policies,
  enrollment keys, devices; queue device commands; read events.
- **`/`** — the dashboard SPA (`public/`), vanilla JS, no framework/build.

Data model (`src/db.js`): `admins`, `sessions`, `enrollment_keys`, `policies`,
`devices`, `commands`, `events`.

Policy is stored compactly and expanded to the full wire shape by
`src/lib/policy.js` (`normalize()` merges a stored body over its level preset so
partial/old rows stay valid). Each save bumps `policies.version`; a device
acknowledges the version it has, and the server ships a new body only when its
version is higher.

### Endpoint agent (`agent/`)
Plain Node (CommonJS), stdlib-only HTTP client, one small dependency
(`node-windows`) for the service wrapper. Packaged with a bundled `node.exe` so
endpoints need nothing installed.

- **`src/index.js`** — two loops:
  - *heartbeat loop* (every `heartbeatSeconds`): report status/events, pull
    policy + commands, apply a new policy, ack promptly.
  - *enforce loop* (every `killIntervalMs`): sweep processes, kill VPN clients,
    re-assert the system proxy. Paused while a valid unlock window is active.
- **`src/enforce/apps.js`** — process sweep (with a critical-process allowlist so
  Windows/the agent are never killed) + AppLocker XML generation/apply.
- **`src/enforce/web.js`** — the filtering proxy (HTTP + HTTPS `CONNECT`),
  `hosts` sinkhole, system-proxy pinning, SafeSearch, domain matching.
- **`src/enforce/vpn.js`** — firewall rules, VPN client termination, DNS pinning.
- **`src/enforce/tamper.js`** — unlock gate (key hash / server command), service
  recovery hardening, uninstall authorisation.
- **`src/lib/config.js`** — local state in `%ProgramData%\WhitelistAgent`
  (admin-writable only): server URL, enrollment key, device token, stable
  machine id, and the last-applied policy (fail-closed).
- **`src/service.js`** / **`src/cli.js`** — service install/remove; local admin CLI.

### Installer (`installer/`)
`install.ps1` (deploy + service + watchdog task + ACL lockdown + enrol),
`watchdog.ps1` (SYSTEM task that keeps the service up), `uninstall.ps1`
(authorisation-gated teardown + full revert). `build.js` assembles `dist/`.

## Lifecycle

1. **Build** bakes `serverUrl` + `enrollmentKey` into the package.
2. **Install** (admin) deploys to `Program Files`, installs the service, locks
   files, registers the watchdog.
3. **Enroll**: agent posts the enrollment key + a stable machine id; server
   returns a device token. Re-installs on the same machine re-bind (no
   duplicate device rows).
4. **Heartbeat**: agent reports the policy version it holds; server returns a
   newer policy body when there is one, plus any queued commands.
5. **Enforce**: continuous, from the last-applied policy — survives reboots and
   offline periods.
6. **Manage**: change a device's policy, queue `unlock` / `refresh` /
   `uninstall` / `reenroll`, or `revoke` the token — all from the dashboard,
   effective on the next heartbeat.

## Design choices worth noting

- **Deny-by-default** in lockdown: whitelist modes block everything not listed,
  for both apps and web.
- **Defence in depth**: each control has a fast user-mode layer (kill / proxy /
  firewall) *and* a durable OS layer (AppLocker / hosts / DNS pin), so defeating
  one does not defeat the intent.
- **No TLS interception**: the web filter blocks by hostname (SNI/Host), never
  decrypting traffic — simpler, no root-CA install, privacy-preserving; the
  trade-off is per-URL (vs per-host) rules aren't possible.
- **Fail closed**, never fail open.

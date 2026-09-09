# Whitelist Cloud

Cloud-managed endpoint control for Windows. A central dashboard defines policy;
a small agent packaged with its own runtime is dropped onto any endpoint,
enrols itself, and enforces the policy continuously — app allow/deny, web
allow/deny and category filtering, VPN blocking, and tamper resistance.

```
   ┌──────────────────────┐        HTTPS         ┌───────────────────────────┐
   │  Cloud dashboard      │  enrol / heartbeat   │  Endpoint agent (service) │
   │  (server/)            │ ◀──────────────────▶ │  (agent/)                 │
   │  • policies           │   policy + commands  │  • app control (kill +    │
   │  • devices            │                      │    AppLocker)             │
   │  • enrollment keys    │                      │  • web filter proxy+hosts │
   │  • unlock / uninstall │                      │  • VPN firewall + DNS pin │
   └──────────────────────┘                      │  • watchdog + service     │
                                                  └───────────────────────────┘
```

## Platforms

One dashboard and one policy shape; each platform enforces it with the right
native mechanism. See each folder's README for details and honest limits.

| Platform | Folder | Enforcement | Status |
|----------|--------|-------------|--------|
| Windows | [agent/](agent/) | Service agent: process-kill + WDAC/AppLocker/IFEO, filtering proxy, firewall VPN block, watchdog | Built + tested |
| macOS | [macos/](macos/) | LaunchDaemon agent: process-kill + app-access profile, proxy + pf, shared [core/](core/) | Built + tested |
| Android | [android/](android/) | Android Management API (managed/Device Owner); wired into the dashboard | Built + tested |
| iOS / iPadOS | [ios/](ios/) | MDM configuration profiles on a supervised device | Built + tested |

Windows and macOS are installable agents. Android and iOS require **managed
enrollment** (Device Owner / supervised) — an installed app cannot control a
phone; that's the OS security model, not a limitation of this code.

## Three enforcement levels

| Level | Name     | Apps                    | Web                                            | VPN     |
|-------|----------|-------------------------|------------------------------------------------|---------|
| 1     | Monitor  | report only             | open, report only                              | allowed |
| 2     | Filtered | blacklist               | open; block listed domains + categories; SafeSearch | blocked |
| 3     | Lockdown | **whitelist** (only listed apps run) | **whitelist** (only listed domains reachable) | blocked |

Level 3 is the "kiosk" case: only the apps you list may run, and only the
websites you list are reachable — everything else is blocked. Level 2 is the
"open internet minus the bad stuff" case (block porn/gambling/etc. by category
or block specific sites). Level 1 just watches.

## Quick start

### 1. Run the dashboard

```bash
cd server
npm install
npm run init-admin -- admin 'YourStrongPassword'   # create the admin login
npm start                                          # http://localhost:8080
```

Open the dashboard, sign in, then:
1. **Policies** → create a policy, pick a level, fill the allow/deny lists and
   categories, and set an **admin unlock key** (your recovery path — keep it
   safe).
2. **Enrollment** → create an enrollment key bound to that policy.

Put the server behind HTTPS in production (a reverse proxy such as Caddy or
nginx). Set `HTTPS=1` so the session cookie is marked secure.

### 2. Build a deployable package

```bash
cd agent
npm install
node build.js --server https://your-dashboard.example.com --key ENR-xxxxxxxx --zip
```

This produces `installer/dist/WhitelistAgent/` (and a `.zip`), self-contained
including a bundled `node.exe` — the endpoint needs nothing pre-installed.

### 3. Install on an endpoint (as Administrator)

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

The agent installs as the `WhitelistAgent` service, registers a SYSTEM watchdog
task, locks its own files against standard users, enrols, and starts enforcing
within ~30 seconds. The device appears under **Devices** in the dashboard,
where you can change its policy, push commands, or revoke it live.

### Uninstalling

Uninstall is deliberately gated (that is the point of the tamper protection):

```powershell
# Authorised from the dashboard (Devices → ⋯ → Authorize uninstall), then:
powershell -ExecutionPolicy Bypass -File uninstall.ps1
# or with the admin unlock key:
powershell -ExecutionPolicy Bypass -File uninstall.ps1 -UnlockKey 'yourkey'
# admin recovery if the dashboard is gone:
powershell -ExecutionPolicy Bypass -File uninstall.ps1 -Force
```

## Repository layout

```
server/     cloud dashboard + policy API (Express + SQLite)
agent/      endpoint agent + enforcement modules + build script
installer/  install.ps1, uninstall.ps1, watchdog.ps1, dist/ (built packages)
shared/     wire protocol + category data
docs/       ARCHITECTURE.md, SECURITY.md
```

## Testing without touching the system

Run the agent with `WL_DRY_RUN=1` and every system-changing command is logged
instead of executed — safe to run on a dev box. This is how the enforcement
logic is exercised in development.

See **[docs/SECURITY.md](docs/SECURITY.md)** for the honest threat model —
what this stops, and where a signed kernel driver or full MDM would be required.

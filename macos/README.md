# Whitelist Cloud — macOS agent

Same dashboard, same policy shape, same three levels as the Windows agent —
enforced on macOS. Reuses the shared filtering core (`../core`).

## What enforces what

| Control | Mechanism | Notes |
|---|---|---|
| Apps | Runtime process sweep (`ps`/`kill`) + generated `com.apple.applicationaccess` profile | Runtime works on any Mac (agent runs as root). The profile is kernel-enforced only on a **supervised/MDM-managed** Mac — generated here for MDM push. |
| Web | Shared filtering proxy + `networksetup` system proxy (all services) + `/etc/hosts` sinkhole | Whitelist forces all traffic through the proxy; blacklist/categories sinkholed. No TLS interception. |
| VPN | `pf` anchor blocking OpenVPN/WireGuard/IKEv2/PPTP/GRE + kill known VPN clients | |
| Persistence | root LaunchDaemon, `RunAtLoad` + `KeepAlive` (relaunches if killed) | |
| Uninstall | `uninstall.sh` refuses without dashboard authorisation / unlock / `--force` | |

## Install (as root)

```bash
sudo ./installer/install.sh --server https://your-dashboard.example.com --key ENR-xxxx
```

Bundle a `node` binary next to the package (or have Node on PATH) so the
endpoint needs nothing pre-installed. Test any logic without touching the system
with `WL_DRY_RUN=1`; run `npm test` for the pure + proxy tests.

## Honest limits

Same as elsewhere (see `../docs/SECURITY.md`): this contains a standard user and
slows a local admin. Robust, admin-proof app allow-listing on macOS needs the
Mac to be **supervised via MDM** so the `applicationaccess` profile is enforced —
the runtime sweep is the fallback on an unmanaged Mac. SIP/root and a locked
LaunchDaemon raise the bar but a determined admin in Recovery mode can still
intervene.

# Security & threat model

This document is deliberately honest about what the system enforces and where
its limits are. Read it before relying on it.

## Intended deployment

Device-management software for machines the deploying organisation **owns or
administers** — schools, libraries, kiosks, supervised/family devices, managed
corporate fleets. Enrolment is explicit (an installer run by an administrator),
the dashboard owner holds the unlock key, and there is a documented admin
recovery path (`uninstall.ps1 -Force`). It is not spyware and is not designed to
hide from the machine's rightful administrator.

## Threat model

The primary adversary is a **standard (non-administrator) user** of the endpoint
who wants to run blocked apps, reach blocked sites, or remove the agent. Against
that user the controls below are effective.

A **local administrator** is explicitly *not* fully contained by user-mode
software — see "Limits" below. Where you need to contain an admin-level
adversary, the endpoint should be locked down so the target user is not an admin
(this software assumes that), and/or paired with the OS-level mechanisms noted.

## What enforces what

| Control | Mechanism | Strength |
|---|---|---|
| App allow/deny | Process-list sweep + `taskkill` every few seconds | Immediate; a killed app relaunches only to be killed again. Renamed binaries defeat name-based rules — that is why AppLocker is layered on. |
| App allow/deny (durable) | Generated **AppLocker** policy (`Set-AppLockerPolicy`) | Kernel-enforced deny-by-default; survives renames; needs the Application Identity service + admin to apply. |
| Web allow/deny | Local filtering proxy (Host header / HTTPS `CONNECT` SNI), system proxy pinned to it and re-asserted each tick | Whitelist = deny-by-default. Filters without decrypting TLS (blocks by hostname, no MITM). |
| Web (proxy-unaware apps) | `hosts` file sinkhole to `0.0.0.0` | Catches clients that ignore the system proxy. |
| Category filtering | Bundled category→domain map (+ optional filtering DNS resolver) | Covers the seed lists; production should sync a maintained feed. |
| SafeSearch | `hosts` pin to search engines' safe VIPs | Forces safe results on Google/Bing/YouTube. |
| VPN blocking | Firewall rules on OpenVPN/WireGuard/IKEv2/PPTP/L2TP/GRE + killing known VPN clients + DNS pinning | Blocks the common consumer VPNs and stops DNS redirection. |
| Persistence | Windows service (auto-start, restart-on-crash in ~2s) + SYSTEM watchdog task (restarts if stopped, every 60s) | Killing the process or stopping the service does not keep it down. |
| Uninstall protection | Uninstaller refuses without dashboard authorisation or the admin unlock key | Standard users cannot remove it. |
| File protection | `icacls` removes standard-user modify/delete on the install + data dirs | Standard users cannot tamper with binaries, token, or policy. |

## Fail-closed

If the dashboard is unreachable, the agent keeps enforcing the **last policy it
successfully applied** (persisted to disk). Loss of connectivity relaxes
nothing; it only delays policy *updates*.

## Limits (be honest about these)

User-mode software running on an OS the adversary fully controls cannot be made
tamper-proof against that adversary. Specifically, a user with **local
administrator / SYSTEM** rights can, with effort:

- boot to Safe Mode or WinRE and disable the service/task from outside it;
- edit the `hosts` file, firewall, or proxy back (the agent re-asserts on its
  next tick — a race, not a wall);
- use an admin-privileged VPN/tunnel on a non-standard port, or DNS-over-HTTPS
  to an endpoint not in the block list;
- take ownership of the protected folders (`icacls` is an admin-reversible ACL).

Closing these requires mechanisms outside user-mode application code:

- **Do not give the target user admin rights** — the single most important
  control; the rest of this design assumes it.
- **AppLocker / WDAC** (partly integrated here) or full app allow-listing
  policy pushed by Group Policy / Intune.
- **A signed kernel driver / minifilter or a Protected Process** for
  self-defence that survives an admin (a substantial, separately-signed
  undertaking).
- **Enterprise MDM (Intune / a real MDM)** for enrolment and persistence that a
  local admin cannot casually revoke.
- **BIOS/UEFI + disk encryption + disabled external boot** to stop offline
  tampering.

## Operational security notes

- Serve the dashboard over **HTTPS** and set `HTTPS=1` (secure cookies). The
  agent↔server protocol should always be HTTPS in production; enrollment keys
  and device tokens are bearer secrets.
- **Device tokens** are stored hashed (scrypt) server-side; the plaintext lives
  only on its endpoint in an admin-only directory.
- The **unlock key** is stored only as a SHA-256 hash (in the policy and, on the
  endpoint, in the local policy file). It is your recovery path — losing it
  means falling back to `-Force` admin recovery.
- **Revoke** a lost/stolen device from the dashboard; its token stops working on
  the next heartbeat.
- Rotate/revoke **enrollment keys** if a package leaks; existing devices are
  unaffected (they use device tokens, not the enrollment key, after first run).

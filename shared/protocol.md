# Wire protocol (agent ⇄ cloud)

All requests are JSON over HTTPS. The agent authenticates every call with a
per-device bearer token issued at enrollment.

## Enrollment (one time)

```
POST /api/v1/enroll
{ "enrollmentKey": "<org key from dashboard>", "hostname": "...", "os": "...", "machineId": "<stable hw id>" }
-> 200 { "deviceId": "...", "deviceToken": "...", "policyVersion": 0 }
```

The enrollment key is created in the dashboard and can be revoked. `machineId`
is a stable hardware-derived id so a re-install re-binds to the same device row
rather than creating a duplicate.

## Heartbeat + policy pull (every `heartbeatSeconds`)

```
POST /api/v1/heartbeat
Authorization: Bearer <deviceToken>
{ "policyVersion": 7, "agentVersion": "1.0.0", "status": {...}, "events": [...] }
-> 200 {
     "policyVersion": 8,
     "policy": { ...full policy, only when version changed... } | null,
     "commands": [ { "id":"...", "type":"unlock|reenroll|uninstall|refresh", ... } ],
     "unlockToken": null
   }
```

The agent reports the policy version it currently has; the server returns a new
policy only when its version is higher. `commands` carries out-of-band actions
(temporary unlock, forced refresh, authorized uninstall).

## Policy shape

```jsonc
{
  "version": 8,
  "level": 3,                 // 1 = monitor, 2 = open+blacklist/categories, 3 = lockdown/whitelist
  "apps": {
    "mode": "whitelist",      // whitelist | blacklist | off
    "allow": ["chrome.exe", "C:\\Path\\allowed.exe"],
    "deny":  ["steam.exe"],
    "killIntervalMs": 3000
  },
  "web": {
    "mode": "whitelist",      // whitelist | blacklist | off
    "allowDomains": ["example.com", "*.school.edu"],
    "denyDomains": ["facebook.com"],
    "categories": ["pornography", "gambling", "malware"],  // blocked categories
    "proxyPort": 18080,
    "forceSafeSearch": true
  },
  "vpn": { "block": true },
  "tamper": {
    "preventUninstall": true,
    "watchdog": true,
    "unlockKeyHash": "<argon2/sha256 of the dashboard unlock key>"
  },
  "heartbeatSeconds": 30
}
```

## Levels (convenience presets the dashboard expands into the shape above)

- **Level 1 — Monitor**: report only, no blocking.
- **Level 2 — Filtered**: internet open; block `denyDomains` + `categories`;
  apps blacklist only; SafeSearch forced.
- **Level 3 — Lockdown**: apps `whitelist` (only `allow` may run), web
  `whitelist` (only `allowDomains` reachable), VPN blocked, tamper on.

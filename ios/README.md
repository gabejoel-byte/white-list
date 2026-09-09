# Whitelist Cloud — iOS (MDM)

iOS gives an installed app **no** way to block other apps or filter system-wide
traffic. The only route to real control is **MDM on a supervised device**. This
component maps a Whitelist Cloud policy to an iOS configuration profile and
provides the MDM enrollment + command scaffolding.

> **There is no sideload path.** A device must be *supervised* (enrolled via
> Apple Configurator or Apple Business/School Manager) for the app allow-list,
> global proxy, and non-removable-profile controls to take effect. This is
> Apple's security model — no code can work around it.

## What it enforces (real Apple payload keys)

| Whitelist Cloud | iOS profile |
|---|---|
| apps whitelist | `com.apple.applicationaccess` → `allowListedAppBundleIDs` (supervised) |
| apps blacklist | `com.apple.applicationaccess` → `blockedAppBundleIDs` |
| web whitelist | `com.apple.webcontent-filter` BuiltIn: `AutoFilterEnabled` + `PermittedURLs` (only these) |
| web blacklist + categories | `com.apple.webcontent-filter` → `DenyListURLs` |
| web whitelist (all apps) | `com.apple.proxy.http.global` → force traffic through the cloud filtering proxy (supervised) |
| block VPN | `allowVPNCreation: false` (supervised) |
| prevent uninstall | `allowAppRemoval: false` + `PayloadRemovalDisallowed: true` |
| single-app lockdown | `com.apple.app.lock` (Single App Mode) |

`src/profile-map.js` and `src/plist.js` are pure and unit-tested (`npm test`,
12 tests) — no Apple account needed to verify the mapping.

## What a live deployment additionally requires (Apple side)

1. **Apple Developer account** + an **MDM push certificate** (APNs). You obtain a
   vendor signing cert, then a push cert via the Apple Push Certificates Portal;
   its **topic** goes in the enrollment profile.
2. An **HTTPS MDM endpoint** serving the check-in + command protocol. **This is
   now implemented in the dashboard server** (`server/src/routes/mdm.js`):
   `GET /mdm/enroll`, `PUT /mdm/checkin` (Authenticate/TokenUpdate/CheckOut),
   `PUT /mdm/command` (delivers queued `InstallProfile` etc.). Device/command
   storage is in SQLite; the APNs wake client is `server/src/lib/apns.js`
   (activates when `APNS_CERT`/`APNS_KEY` are set). Configure with
   `MDM_SERVER_URL` + `MDM_TOPIC`. Manage from the dashboard's **iOS** tab.
   Production hardening still to add: CMS signature verification on device
   messages and SCEP device identity (called out in the code).
3. **Supervision**: enroll the device via **Apple Configurator** (USB) or **Apple
   Business/School Manager** (automated enrollment). Supervision is what unlocks
   the restrictions above.

## Flow

```
dashboard policy ─▶ profile-map.js ─▶ .mobileconfig
                                         │
device enrolls (supervised) ─▶ MDM ─▶ InstallProfile(mobileconfig) ─▶ enforced
```

## Honest limits

- Supervised enrollment is mandatory; you cannot silently manage an existing
  personal iPhone. Provisioning happens via Configurator/ABM (typically at setup
  or after erase).
- The BuiltIn web filter applies to Safari and WebKit; the global HTTP proxy
  (supervised) is what extends filtering to other apps.
- A user can erase a supervised device only if you haven't also disabled that;
  `allowEraseContentAndSettings: false` (a restriction) can be added if desired.

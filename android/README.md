# Whitelist Cloud — Android (managed)

Android's security model means a normally-installed app **cannot** block other
apps or filter system-wide traffic. Real control requires the device to be
**managed** — enrolled as a Device Owner. The clean, supported way to do that
without writing and maintaining a custom Device Policy Controller is Google's
**Android Management API (AMAPI)**: Google provides the on-device agent (the
*Android Device Policy* app); you provide policy from the cloud.

This component maps a Whitelist Cloud policy to an AMAPI `Policy` resource and
pushes it. Same dashboard, same three levels — enforced by Google's managed
agent on the device.

```
Dashboard policy ──▶ policy-map.js ──▶ AMAPI Policy ──▶ Android Device Policy ──▶ device
   (shared shape)      (this module)     (Google)         (on-device agent)
```

## What it enforces (all real AMAPI fields)

| Whitelist Cloud | Android Management API |
|---|---|
| apps whitelist | `playStoreMode: WHITELIST` + allowed pkgs `installType: FORCE_INSTALLED` (or `KIOSK`) |
| apps blacklist | `playStoreMode: BLACKLIST` + denied pkgs `installType: BLOCKED` |
| web whitelist | Chrome `managedConfiguration`: `URLBlocklist:["*"]` + `URLAllowlist:[…]` |
| web blacklist + categories | Chrome `URLBlocklist:[denied + category domains]` |
| SafeSearch | Chrome `ForceGoogleSafeSearch:true`, `IncognitoModeAvailability:1` |
| block VPN | `vpnConfigDisabled:true` (+ optional `alwaysOnVpnPackage` with lockdown) |
| prevent uninstall | `uninstallAppsDisabled:true`, `factoryResetDisabled:true` |
| level-3 lockdown | `kioskCustomLauncherEnabled:true` |

`policy-map.js` is pure and unit-tested (`npm test`) — no credentials needed to
verify the mapping. `amapi.js` performs the live calls.

## One-time cloud setup

1. **Create a Google Cloud project** and enable the **Android Management API**
   (APIs & Services → Enable APIs → "Android Management API").
2. **Create a service account** in that project, grant it the
   *Android Management User* role, and download a **JSON key**.
3. **Create an enterprise** bound to the project. The simplest path is the
   [AMAPI quickstart `signup url` → `enterprises.create`] flow, or Google's
   colab/quickstart. You get an enterprise name like `enterprises/LC0abc123`.

## Configure this component

```bash
cd android
npm install                              # pulls googleapis
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
export ENTERPRISE_NAME=enterprises/LC0abc123
```

## Push a policy + enroll a device

```js
const amapi = require('./src/amapi');

// 1. Push a policy (reuse the dashboard's policy object).
await amapi.applyPolicy('lockdown', {
  level: 3, kiosk: true,
  apps: { mode: 'whitelist', allow: ['com.android.chrome', 'com.example.reader'] },
  web:  { mode: 'whitelist', allowDomains: ['school.edu'], forceSafeSearch: true },
  vpn:  { block: true },
  tamper: { preventUninstall: true },
});

// 2. Create an enrollment token → turn token.value into a QR code.
const tok = await amapi.createEnrollmentToken('lockdown');
console.log(tok.value); // encode as QR
```

## Enroll the device (must be managed)

A device becomes managed only during provisioning:

- **New / factory-reset device:** on the first setup screen tap 6× to open the
  QR scanner, then scan the enrollment-token QR. The device provisions as a
  fully-managed (Device Owner) device with Android Device Policy installed.
- **Testing:** `adb` can set the device owner for a DPC, but for AMAPI the
  QR/factory-reset provisioning is the supported route.

Once enrolled, the device polls Google for its policy; changing the policy in
the dashboard and re-pushing updates the device automatically.

## Integrating with the dashboard

The server already stores policies in the shared shape. To drive Android from
the dashboard, add a small route that calls `amapi.applyPolicy(policyId, body)`
whenever an Android-targeted policy is saved, and surface AMAPI devices in the
Devices view alongside the Windows agents. (Next step — not yet wired.)

## Honest limits

- The device **must be enrolled as managed** (Device Owner). You cannot silently
  convert someone's existing, unmanaged phone — provisioning happens at setup or
  after a factory reset. This is Android's design, not a limitation of the code.
- Web filtering here is enforced **in Chrome** via managed configuration. Other
  browsers must be blocked (omit them from a whitelist, or `BLOCKED` them) or
  they bypass the filter; routing everything through an always-on filtering VPN
  (`alwaysOnVpnPackage`) is the stronger option.

'use strict';
// Translate a Whitelist Cloud policy (the shared shape used by the dashboard and
// the Windows agent) into an Android Management API `Policy` resource.
//
// This is a PURE function — no network, no credentials — so it is fully unit
// tested. The live push happens in amapi.js. Every field name below is a real
// Android Management API field (verified against Google's Policy reference):
//   playStoreMode, applications[].installType, applications[].managedConfiguration,
//   uninstallAppsDisabled, factoryResetDisabled, vpnConfigDisabled,
//   alwaysOnVpnPackage, kioskCustomLauncherEnabled.
// Chrome URL filtering uses Chrome's managed configuration keys URLBlocklist /
// URLAllowlist / ForceGoogleSafeSearch / IncognitoModeAvailability.

const CHROME = 'com.android.chrome';
let CATEGORIES = {};
try { CATEGORIES = require('./data/categories.json'); } catch { CATEGORIES = {}; }

function categoryDomains(cats) {
  const out = [];
  for (const c of cats || []) for (const d of CATEGORIES[c] || []) out.push(d);
  return [...new Set(out)];
}

// Chrome managed configuration wants URL *patterns*, not bare hosts. A bare
// "example.com" becomes the Chromium pattern that matches the domain and its
// subdomains on any scheme/path.
function urlPattern(domain) {
  const d = String(domain).trim().toLowerCase();
  if (!d) return null;
  if (d.startsWith('*.')) return d;           // already a pattern
  return d;                                   // Chromium treats "example.com" as domain+subdomains
}
function patterns(list) { return (list || []).map(urlPattern).filter(Boolean); }

function chromeManagedConfig(web) {
  const cfg = {};
  if (web.mode === 'whitelist') {
    cfg.URLBlocklist = ['*'];                                  // block everything…
    cfg.URLAllowlist = patterns(web.allowDomains);            // …except the allow list
  } else if (web.mode === 'blacklist') {
    cfg.URLBlocklist = patterns([...(web.denyDomains || []), ...categoryDomains(web.categories)]);
  }
  if (web.forceSafeSearch) {
    cfg.ForceGoogleSafeSearch = true;
    cfg.IncognitoModeAvailability = 1;   // 1 = incognito disabled (else it bypasses filtering)
  }
  return cfg;
}

// Build the applications[] array.
function applications(policy) {
  const apps = policy.apps || {};
  const web = policy.web || {};
  const list = [];
  const kiosk = !!policy.kiosk;

  if (apps.mode === 'whitelist') {
    for (const pkg of apps.allow || []) {
      list.push({ packageName: pkg, installType: kiosk ? 'KIOSK' : 'FORCE_INSTALLED' });
    }
  } else if (apps.mode === 'blacklist') {
    for (const pkg of apps.deny || []) list.push({ packageName: pkg, installType: 'BLOCKED' });
  }

  // Chrome carries web filtering. Force-install it (unless a whitelist that
  // deliberately omits a browser) and attach the managed config.
  if (web.mode && web.mode !== 'off') {
    const existing = list.find((a) => a.packageName === CHROME);
    const mc = chromeManagedConfig(web);
    if (existing) existing.managedConfiguration = mc;
    else list.push({ packageName: CHROME, installType: 'FORCE_INSTALLED', managedConfiguration: mc });
  }
  return list;
}

function mapPolicy(policy) {
  const apps = policy.apps || {};
  const web = policy.web || {};
  const vpn = policy.vpn || {};
  const tamper = policy.tamper || {};

  const out = {
    // App control.
    playStoreMode: apps.mode === 'whitelist' ? 'WHITELIST' : 'BLACKLIST',
    applications: applications(policy),

    // Tamper resistance.
    uninstallAppsDisabled: !!tamper.preventUninstall,
    factoryResetDisabled: !!tamper.preventUninstall,

    // VPN: block the user from configuring their own VPN to tunnel around us.
    vpnConfigDisabled: !!vpn.block,

    // Housekeeping that makes a managed device behave.
    installUnknownSourcesAllowed: false,
    developerSettingsDisabled: (policy.level || 3) >= 2,
  };

  // Kiosk (single-purpose) mode for lockdown when requested.
  if (policy.kiosk && apps.mode === 'whitelist') {
    out.kioskCustomLauncherEnabled = true;
  }

  // Optional: route all traffic through a nominated filtering VPN app.
  if (vpn.block && policy.filteringVpnPackage) {
    out.alwaysOnVpnPackage = { packageName: policy.filteringVpnPackage, lockdownEnabled: true };
  }
  return out;
}

module.exports = { mapPolicy, chromeManagedConfig, applications, categoryDomains, CHROME };

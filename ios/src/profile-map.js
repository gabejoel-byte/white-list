'use strict';
// Translate a Whitelist Cloud policy into an iOS configuration profile
// (.mobileconfig) enforced by MDM on a SUPERVISED device. Pure — unit tested.
//
// Payloads used (all real Apple MDM payload types / keys, verified against
// Apple's device-management reference):
//   com.apple.applicationaccess   restrictions incl. app allow/deny, allowAppRemoval,
//                                  allowVPNCreation  (supervised)
//   com.apple.webcontent-filter    BuiltIn filter: AutoFilterEnabled, PermittedURLs,
//                                  DenyListURLs
//   com.apple.proxy.http.global    force all traffic through our filtering proxy
//                                  (supervised) — used for web whitelist lockdown
//   com.apple.app.lock             Single App Mode for kiosk lockdown
const crypto = require('crypto');
const { build } = require('./plist');

let CATEGORIES = {};
try { CATEGORIES = require('./data/categories.json'); } catch { CATEGORIES = {}; }

const uuid = () => crypto.randomUUID().toUpperCase();

function categoryDomains(cats) {
  const out = [];
  for (const c of cats || []) for (const d of CATEGORIES[c] || []) out.push(d);
  return [...new Set(out)];
}
// iOS content filter wants full URLs; expand a bare domain to an https URL.
function toUrl(d) { const s = String(d).trim().toLowerCase(); return s.startsWith('http') ? s : `https://${s.replace(/^\*\./, '')}`; }

function payloadCommon(type, display) {
  return {
    PayloadType: type,
    PayloadVersion: 1,
    PayloadIdentifier: `cloud.whitelist.${type}`,
    PayloadUUID: uuid(),
    PayloadDisplayName: display,
  };
}

// Restrictions + app allow/deny + VPN + uninstall lock.
function restrictionsPayload(policy) {
  const apps = policy.apps || {}, vpn = policy.vpn || {}, tamper = policy.tamper || {};
  const p = { ...payloadCommon('com.apple.applicationaccess', 'Restrictions') };
  if (tamper.preventUninstall) p.allowAppRemoval = false;
  if (vpn.block) p.allowVPNCreation = false;           // supervised: block user VPNs
  if (apps.mode === 'whitelist') p.allowListedAppBundleIDs = apps.allow || [];
  else if (apps.mode === 'blacklist') p.blockedAppBundleIDs = apps.deny || [];
  return p;
}

// Safari/system web content filter (BuiltIn).
function webFilterPayload(web) {
  const p = { ...payloadCommon('com.apple.webcontent-filter', 'Web Content Filter'), FilterType: 'BuiltIn' };
  if (web.mode === 'whitelist') {
    // BuiltIn + AutoFilterEnabled + PermittedURLs => only these reachable.
    p.AutoFilterEnabled = true;
    p.PermittedURLs = (web.allowDomains || []).map(toUrl);
  } else if (web.mode === 'blacklist') {
    p.AutoFilterEnabled = !!web.forceSafeSearch; // auto-block adult when safe-search on
    p.DenyListURLs = [...(web.denyDomains || []), ...categoryDomains(web.categories)].map(toUrl);
  }
  return p;
}

// Force all HTTP/S through our cloud filtering proxy (supervised) for the
// strongest web control (covers non-Safari apps too).
function globalProxyPayload(web) {
  return {
    ...payloadCommon('com.apple.proxy.http.global', 'Global HTTP Proxy'),
    ProxyType: 'Manual',
    ProxyServer: web.proxyHost || '127.0.0.1',
    ProxyServerPort: web.proxyPort || 18080,
    ProxyCaptiveLoginAllowed: false,
  };
}

function appLockPayload(bundleId) {
  return { ...payloadCommon('com.apple.app.lock', 'Single App Mode'), App: { Identifier: bundleId } };
}

// Build the ordered payload list for a policy.
function payloads(policy) {
  const list = [restrictionsPayload(policy)];
  const web = policy.web || {};
  if (web.mode && web.mode !== 'off') {
    list.push(webFilterPayload(web));
    if (web.mode === 'whitelist' && policy.forceProxy) list.push(globalProxyPayload(web));
  }
  if (policy.kiosk && policy.apps?.mode === 'whitelist' && (policy.apps.allow || []).length === 1) {
    list.push(appLockPayload(policy.apps.allow[0]));
  }
  return list;
}

// Full removable-or-locked profile object.
function profile(policy, { organization = 'Whitelist Cloud' } = {}) {
  return {
    PayloadType: 'Configuration',
    PayloadVersion: 1,
    PayloadIdentifier: 'cloud.whitelist.profile',
    PayloadUUID: uuid(),
    PayloadDisplayName: `Whitelist Cloud — Level ${policy.level || 3}`,
    PayloadOrganization: organization,
    // On a supervised device this makes the profile non-removable by the user.
    PayloadRemovalDisallowed: !!(policy.tamper && policy.tamper.preventUninstall),
    PayloadContent: payloads(policy),
  };
}

function buildProfile(policy, opts) { return build(profile(policy, opts)); }

module.exports = {
  buildProfile, profile, payloads,
  restrictionsPayload, webFilterPayload, globalProxyPayload, appLockPayload,
  categoryDomains,
};

'use strict';
// Expands a compact dashboard form into the full wire policy, and normalizes
// whatever is stored so old rows still validate.

function preset(level) {
  switch (Number(level)) {
    case 1: // Monitor
      return {
        apps: { mode: 'off', allow: [], deny: [], killIntervalMs: 4000 },
        web:  { mode: 'off', allowDomains: [], denyDomains: [], categories: [], forceSafeSearch: false },
        vpn:  { block: false },
      };
    case 2: // Filtered internet
      return {
        apps: { mode: 'blacklist', allow: [], deny: [], killIntervalMs: 4000 },
        web:  { mode: 'blacklist', allowDomains: [], denyDomains: [], categories: ['pornography', 'malware'], forceSafeSearch: true },
        vpn:  { block: true },
      };
    case 3: // Lockdown
    default:
      return {
        apps: { mode: 'whitelist', allow: [], deny: [], killIntervalMs: 2500 },
        web:  { mode: 'whitelist', allowDomains: [], denyDomains: [], categories: [], forceSafeSearch: true },
        vpn:  { block: true },
      };
  }
}

// Merge a raw stored body over its level preset so partial rows are complete.
function normalize(body) {
  const b = typeof body === 'string' ? JSON.parse(body) : (body || {});
  const level = b.level || 3;
  const base = preset(level);
  const out = {
    version: b.version || 1,
    level,
    apps: { ...base.apps, ...(b.apps || {}) },
    web:  { ...base.web,  ...(b.web  || {}) },
    vpn:  { ...base.vpn,  ...(b.vpn  || {}) },
    tamper: {
      preventUninstall: b.tamper?.preventUninstall ?? (level >= 2),
      watchdog:         b.tamper?.watchdog ?? (level >= 2),
      unlockKeyHash:    b.tamper?.unlockKeyHash || null,
    },
    heartbeatSeconds: b.heartbeatSeconds || 30,
    proxyPort: b.proxyPort || b.web?.proxyPort || 18080,
  };
  out.web.proxyPort = out.proxyPort;
  // De-dupe / clean list fields.
  for (const k of ['allow', 'deny']) out.apps[k] = uniq(out.apps[k]);
  for (const k of ['allowDomains', 'denyDomains', 'categories']) out.web[k] = uniq(out.web[k]);
  return out;
}

function uniq(arr) {
  return [...new Set((arr || []).map((s) => String(s).trim().toLowerCase()).filter(Boolean))];
}

module.exports = { preset, normalize };

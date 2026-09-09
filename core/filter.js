'use strict';
// Platform-agnostic web-filtering decision logic, shared by every agent
// (Windows, macOS, …). Pure — no I/O — so it is unit-tested once and reused.
// Category data is INJECTED by the caller (each platform bundles its own
// categories.json) so this module stays data-free and dependency-free.

function normHost(h) { return String(h || '').toLowerCase().replace(/:.*/, '').replace(/\.$/, ''); }

function domainMatches(host, pattern) {
  host = normHost(host);
  pattern = String(pattern).toLowerCase().trim();
  if (!pattern) return false;
  // "*.example.com" = subdomains only (strict). A bare "example.com" matches
  // the apex AND its subdomains, so use that form when you want both.
  if (pattern.startsWith('*.')) return host.endsWith('.' + pattern.slice(2));
  return host === pattern || host.endsWith('.' + pattern);
}

function categoryDomains(cats, categoriesMap = {}) {
  const out = [];
  for (const c of cats || []) for (const d of categoriesMap[c] || []) out.push(d);
  return [...new Set(out)];
}

// allow | deny decision for a hostname under a web policy.
function verdict(host, web, categoriesMap = {}) {
  host = normHost(host);
  if (!web || web.mode === 'off') return 'allow';
  if (web.mode === 'whitelist') {
    return (web.allowDomains || []).some((p) => domainMatches(host, p)) ? 'allow' : 'deny';
  }
  if (web.mode === 'blacklist') {
    const blocked = [...(web.denyDomains || []), ...categoryDomains(web.categories, categoriesMap)];
    return blocked.some((p) => domainMatches(host, p)) ? 'deny' : 'allow';
  }
  return 'allow';
}

module.exports = { normHost, domainMatches, categoryDomains, verdict };

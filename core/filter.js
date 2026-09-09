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

// hosts-file lines that force SafeSearch by pinning search domains to the
// providers' published "safe" VIP addresses. Google SafeSearch and YouTube
// strict Restricted Mode both use 216.239.38.120; Bing strict is 204.79.197.220.
// (hosts can't CNAME, so we pin the IPs — the standard method schools use.)
function safeSearchHostsLines() {
  const GOOGLE_SAFE = '216.239.38.120';   // forcesafesearch.google.com
  const YT_RESTRICT = '216.239.38.120';   // restrict.youtube.com (strict)
  const BING_STRICT = '204.79.197.220';   // strict.bing.com
  const google = ['www.google.com', 'google.com', 'www.google.co.uk', 'www.google.ca',
    'www.google.com.au', 'www.google.de', 'www.google.fr', 'www.google.es', 'www.google.co.in'];
  const youtube = ['www.youtube.com', 'm.youtube.com', 'youtube.com',
    'www.youtube-nocookie.com', 'youtubei.googleapis.com', 'youtube.googleapis.com'];
  const out = [];
  for (const d of google) out.push(`${GOOGLE_SAFE} ${d}`);
  for (const d of youtube) out.push(`${YT_RESTRICT} ${d}`);
  out.push(`${BING_STRICT} www.bing.com`, `${BING_STRICT} bing.com`);
  return out;
}

module.exports = { normHost, domainMatches, categoryDomains, verdict, safeSearchHostsLines };

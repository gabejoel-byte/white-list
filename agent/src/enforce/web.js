'use strict';
// Web control. Layers, again defence in depth:
//   1. Local filtering proxy (this process) — inspects the Host header on plain
//      HTTP and the CONNECT target on HTTPS, and allows/denies by domain. In
//      whitelist mode everything not on the allow list is refused; in blacklist
//      mode denied domains + resolved category domains are refused.
//   2. System proxy pinned to this proxy (WinINET registry), re-asserted every
//      loop so a user toggling it off is corrected within one cycle.
//   3. hosts file entries — sinkhole blacklisted / category domains to 0.0.0.0
//      so even proxy-unaware clients are blocked, and force SafeSearch by
//      mapping search engines to their safe VIPs.
const fs = require('fs');
const { log, run, ps, isDryRun, requireMode } = require('../lib/util');
const coreFilter = require('../../../core/filter');
const { createFilterProxy } = require('../../../core/proxy');

let CATEGORIES = {};
try { CATEGORIES = require('../data/categories.json'); } catch { CATEGORIES = {}; }
let BYPASS = {};
try { BYPASS = require('../data/bypass.json'); } catch { BYPASS = {}; }

const HOSTS_PATH = 'C:\\Windows\\System32\\drivers\\etc\\hosts';
const MARK_BEGIN = '# >>> whitelist-agent (managed) >>>';
const MARK_END = '# <<< whitelist-agent (managed) <<<';

// SafeSearch enforcement VIPs (standard published values).
const SAFE_SEARCH = {
  'www.google.com': 'forcesafesearch.google.com',
  'www.bing.com': 'strict.bing.com',
  'www.youtube.com': 'restrict.youtube.com',
  'm.youtube.com': 'restrict.youtube.com',
  'youtube.com': 'restrict.youtube.com',
};

// Filtering logic now lives in the shared core; re-export with this agent's
// bundled category map injected, so callers/tests keep the 2-arg signatures.
const { normHost, domainMatches } = coreFilter;
const categoryDomains = (cats) => coreFilter.categoryDomains(cats, CATEGORIES);
const verdict = (host, web) => coreFilter.verdict(host, web, CATEGORIES);

// ---------------- filtering proxy (shared core) ----------------
let currentWeb = { mode: 'off' };
const onBlockCbs = [];
function onBlock(cb) { onBlockCbs.push(cb); }

const proxy = createFilterProxy({
  getPolicy: () => currentWeb,
  categories: CATEGORIES,
  onBlock: (host) => { for (const cb of onBlockCbs) try { cb(host); } catch {} },
  onLog: (m) => log('web:', m),
});
function startProxy(port) { if (!isDryRun()) proxy.start(port); }

// ---------------- hosts file + system proxy ----------------
function buildHostsBlock(web) {
  const lines = [MARK_BEGIN];
  const toSink = new Set();
  if (web.mode === 'blacklist') {
    for (const d of [...(web.denyDomains || []), ...categoryDomains(web.categories)]) {
      toSink.add(normHost(d)); toSink.add('www.' + normHost(d));
    }
  }
  // Close DNS-over-HTTPS bypass: sinkhole known DoH endpoints so browsers can't
  // resolve around the hosts filter.
  if (web.blockDoH) for (const h of BYPASS.dohHosts || []) toSink.add(normHost(h));
  // Close VPN-provider domains so VPN apps can't fetch config or connect.
  if (web.blockVpnDomains) for (const d of BYPASS.vpnDomains || []) { toSink.add(normHost(d)); toSink.add('www.' + normHost(d)); }
  for (const d of toSink) lines.push(`0.0.0.0 ${d}`);
  if (web.forceSafeSearch) {
    // Real SafeSearch enforcement: Google SafeSearch + YouTube strict Restricted
    // Mode + Bing Strict, by pinning the search domains to their safe VIPs.
    for (const l of coreFilter.safeSearchHostsLines()) lines.push(l);
  }
  lines.push(MARK_END);
  return lines.join('\r\n');
}

function writeHosts(web) {
  requireMode('to rewrite the hosts file'); // guard the direct-fs mutation too
  if (isDryRun()) { log('web: (dry) would rewrite hosts block'); return; }
  let content = '';
  try { content = fs.readFileSync(HOSTS_PATH, 'utf8'); } catch { content = ''; }
  const re = new RegExp(`${MARK_BEGIN}[\\s\\S]*?${MARK_END}`, 'g');
  content = content.replace(re, '').replace(/\r?\n{3,}/g, '\r\n\r\n').trimEnd();
  const next = content + '\r\n' + buildHostsBlock(web) + '\r\n';
  try { fs.writeFileSync(HOSTS_PATH, next); log('web: hosts file updated'); }
  catch (e) { log('web: hosts write failed (need admin):', e.message); }
}

// The WinINET registry key WinINET actually reads. Overridable via
// WL_PROXY_REGKEY so tests write to a throwaway key and can never touch the
// machine's real proxy settings.
const PROXY_REGKEY = process.env.WL_PROXY_REGKEY
  || 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';

async function setSystemProxy(web) {
  const enable = web.mode === 'whitelist'; // force everything through the proxy
  const key = PROXY_REGKEY;
  if (enable) {
    await run('reg.exe', ['add', key, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '1', '/f']);
    await run('reg.exe', ['add', key, '/v', 'ProxyServer', '/d', `127.0.0.1:${web.proxyPort || 18080}`, '/f']);
    // No bypass list -> everything is filtered.
    await run('reg.exe', ['add', key, '/v', 'ProxyOverride', '/d', '', '/f']);
  } else {
    // Blacklist/monitor modes rely on hosts + firewall, not a forced proxy.
    await run('reg.exe', ['delete', key, '/v', 'ProxyServer', '/f']);
    await run('reg.exe', ['add', key, '/v', 'ProxyEnable', '/t', 'REG_DWORD', '/d', '0', '/f']);
  }
}

// Set the in-memory filtering rules and start the local proxy. This performs
// NO system mutation (no registry, hosts, or DNS changes) — safe to call from
// tests without an execution mode. Splitting this out is measure (1): the part
// that could brick connectivity is isolated behind integrateSystem().
function setPolicy(web) {
  currentWeb = web || { mode: 'off' };
  if (currentWeb.mode !== 'off') startProxy(currentWeb.proxyPort || 18080);
  return currentWeb;
}

// Wire the OS into the proxy: pin the system proxy, rewrite the hosts block,
// flush DNS. These go through run(), so they inherit the execution-mode guard —
// calling this without WL_LIVE=1 / WL_DRY_RUN=1 throws instead of mutating.
async function integrateSystem(web) {
  writeHosts(web);
  await setSystemProxy(web);
  await run('ipconfig.exe', ['/flushdns']); // apply hosts changes immediately
}

async function apply(web) {
  setPolicy(web);
  await integrateSystem(currentWeb);
}

// Cheap re-assertion for the fast enforcement loop: only re-pin the system
// proxy registry values (no hosts rewrite / DNS flush), so a user who toggles
// the proxy off is corrected within one tick without the heavier work.
async function reassertSystemProxy() {
  if (currentWeb.mode === 'whitelist') await setSystemProxy(currentWeb);
}

module.exports = {
  apply, setPolicy, integrateSystem, setSystemProxy, reassertSystemProxy,
  startProxy, verdict, domainMatches, onBlock, buildHostsBlock, categoryDomains,
  PROXY_REGKEY,
};

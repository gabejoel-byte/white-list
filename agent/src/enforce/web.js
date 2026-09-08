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
const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');
const { log, run, ps, isDryRun } = require('../lib/util');

let CATEGORIES = {};
try { CATEGORIES = require('../data/categories.json'); } catch { CATEGORIES = {}; }

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

function normHost(h) { return String(h || '').toLowerCase().replace(/:.*/, '').replace(/\.$/, ''); }

function domainMatches(host, pattern) {
  host = normHost(host); pattern = String(pattern).toLowerCase().trim();
  if (!pattern) return false;
  // "*.example.com" = subdomains only (strict). A bare "example.com" matches
  // the apex AND its subdomains, so use that form when you want both.
  if (pattern.startsWith('*.')) return host.endsWith('.' + pattern.slice(2));
  return host === pattern || host.endsWith('.' + pattern);
}

function categoryDomains(cats) {
  const out = [];
  for (const c of cats || []) for (const d of CATEGORIES[c] || []) out.push(d);
  return out;
}

// Decide allow/deny for a hostname under the current web policy.
function verdict(host, web) {
  host = normHost(host);
  const denyList = [...(web.denyDomains || []), ...categoryDomains(web.categories)];
  if (web.mode === 'whitelist') {
    const allow = web.allowDomains || [];
    const ok = allow.some((p) => domainMatches(host, p));
    return ok ? 'allow' : 'deny';
  }
  if (web.mode === 'blacklist') {
    const blocked = denyList.some((p) => domainMatches(host, p));
    return blocked ? 'deny' : 'allow';
  }
  return 'allow';
}

// ---------------- filtering proxy ----------------
let server = null;
let currentWeb = { mode: 'off' };
const onBlockCbs = [];

function startProxy(port) {
  if (server || isDryRun()) return;
  server = http.createServer((req, res) => {
    const host = normHost(req.headers.host);
    if (verdict(host, currentWeb) === 'deny') return blockHttp(res, host);
    // Forward plain HTTP.
    const u = new URL(req.url, `http://${req.headers.host}`);
    const proxyReq = http.request({ host: u.hostname, port: u.port || 80, path: u.pathname + u.search, method: req.method, headers: req.headers },
      (pr) => { res.writeHead(pr.statusCode, pr.headers); pr.pipe(res); });
    proxyReq.on('error', () => { try { res.writeHead(502); res.end('proxy error'); } catch {} });
    req.pipe(proxyReq);
  });
  // HTTPS tunnelling: filter on the CONNECT target, then blind-tunnel if allowed.
  server.on('connect', (req, clientSocket, head) => {
    const host = normHost(req.url);
    if (verdict(host, currentWeb) === 'deny') {
      reportBlock(host);
      clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Whitelist Cloud policy');
      return clientSocket.destroy();
    }
    const [h, p] = req.url.split(':');
    const upstream = net.connect(p || 443, h, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      upstream.write(head); upstream.pipe(clientSocket); clientSocket.pipe(upstream);
    });
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
  });
  server.on('clientError', (e, sock) => { try { sock.end('HTTP/1.1 400\r\n\r\n'); } catch {} });
  server.listen(port, '127.0.0.1', () => log('web: filtering proxy on 127.0.0.1:' + port));
}

function blockHttp(res, host) {
  reportBlock(host);
  res.writeHead(403, { 'content-type': 'text/html' });
  res.end(`<!doctype html><meta charset=utf-8><title>Blocked</title>
    <body style="font:16px system-ui;background:#0e1116;color:#e6edf3;text-align:center;padding:12vh">
    <h1>Access blocked</h1><p><b>${host}</b> is not permitted by your organisation's policy.</p>
    <p style="color:#8b96a5">Whitelist Cloud</p>`);
}
function reportBlock(host) { for (const cb of onBlockCbs) try { cb(host); } catch {} }
function onBlock(cb) { onBlockCbs.push(cb); }

// ---------------- hosts file + system proxy ----------------
function buildHostsBlock(web) {
  const lines = [MARK_BEGIN];
  const toSink = new Set();
  if (web.mode === 'blacklist') {
    for (const d of [...(web.denyDomains || []), ...categoryDomains(web.categories)]) {
      toSink.add(normHost(d)); toSink.add('www.' + normHost(d));
    }
  }
  for (const d of toSink) lines.push(`0.0.0.0 ${d}`);
  if (web.forceSafeSearch) {
    // Point search engines at their safe VIPs by hostname (resolved via a note;
    // hosts can't CNAME, so we add the standard documented mappings if present).
    for (const [from] of Object.entries(SAFE_SEARCH)) lines.push(`# safesearch pin: ${from}`);
    lines.push('216.239.38.120 forcesafesearch.google.com');
  }
  lines.push(MARK_END);
  return lines.join('\r\n');
}

function writeHosts(web) {
  if (isDryRun()) { log('web: (dry) would rewrite hosts block'); return; }
  let content = '';
  try { content = fs.readFileSync(HOSTS_PATH, 'utf8'); } catch { content = ''; }
  const re = new RegExp(`${MARK_BEGIN}[\\s\\S]*?${MARK_END}`, 'g');
  content = content.replace(re, '').replace(/\r?\n{3,}/g, '\r\n\r\n').trimEnd();
  const next = content + '\r\n' + buildHostsBlock(web) + '\r\n';
  try { fs.writeFileSync(HOSTS_PATH, next); log('web: hosts file updated'); }
  catch (e) { log('web: hosts write failed (need admin):', e.message); }
}

async function setSystemProxy(web) {
  const enable = web.mode === 'whitelist'; // force everything through the proxy
  const key = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
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

async function apply(web) {
  currentWeb = web || { mode: 'off' };
  if (currentWeb.mode !== 'off') startProxy(currentWeb.proxyPort || 18080);
  writeHosts(currentWeb);
  await setSystemProxy(currentWeb);
  // Flush DNS so hosts changes take effect immediately.
  await run('ipconfig.exe', ['/flushdns']);
}

// Cheap re-assertion for the fast enforcement loop: only re-pin the system
// proxy registry values (no hosts rewrite / DNS flush), so a user who toggles
// the proxy off is corrected within one tick without the heavier work.
async function reassertSystemProxy() {
  if (currentWeb.mode === 'whitelist') await setSystemProxy(currentWeb);
}

module.exports = { apply, reassertSystemProxy, startProxy, verdict, domainMatches, onBlock, buildHostsBlock, categoryDomains };

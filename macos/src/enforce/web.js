'use strict';
// macOS web control. Reuses the shared filtering proxy; integrates with macOS:
//   * system proxy pinned to the local proxy via `networksetup` on every
//     network service, re-asserted each loop.
//   * /etc/hosts sinkhole for blacklist/category domains + SafeSearch pins.
const fs = require('fs');
const { log, run, isDryRun, requireMode } = require('../lib/util');
const { createFilterProxy } = require('../../../core/proxy');
const { categoryDomains, normHost, safeSearchHostsLines } = require('../../../core/filter');

let CATEGORIES = {};
try { CATEGORIES = require('../data/categories.json'); } catch { CATEGORIES = {}; }

const HOSTS_PATH = '/etc/hosts';
const MARK_BEGIN = '# >>> whitelist-agent (managed) >>>';
const MARK_END = '# <<< whitelist-agent (managed) <<<';

let currentWeb = { mode: 'off' };
const onBlockCbs = [];
function onBlock(cb) { onBlockCbs.push(cb); }

const proxy = createFilterProxy({
  getPolicy: () => currentWeb,
  categories: CATEGORIES,
  onBlock: (h) => { for (const cb of onBlockCbs) try { cb(h); } catch {} },
  onLog: (m) => log('web:', m),
});

function setPolicy(web) {                 // no system mutation
  currentWeb = web || { mode: 'off' };
  if (currentWeb.mode !== 'off') proxy.start(currentWeb.proxyPort || 18080);
  return currentWeb;
}

async function listNetworkServices() {
  if (isDryRun()) return ['Wi-Fi'];
  const { stdout } = await run('/usr/sbin/networksetup', ['-listallnetworkservices']);
  return stdout.split(/\r?\n/).slice(1).map((s) => s.replace(/^\*/, '').trim()).filter(Boolean);
}

async function setSystemProxy(web) {
  const port = web.proxyPort || 18080;
  const enable = web.mode === 'whitelist';
  for (const svc of await listNetworkServices()) {
    if (enable) {
      await run('/usr/sbin/networksetup', ['-setwebproxy', svc, '127.0.0.1', String(port)]);
      await run('/usr/sbin/networksetup', ['-setsecurewebproxy', svc, '127.0.0.1', String(port)]);
      await run('/usr/sbin/networksetup', ['-setwebproxystate', svc, 'on']);
      await run('/usr/sbin/networksetup', ['-setsecurewebproxystate', svc, 'on']);
    } else {
      await run('/usr/sbin/networksetup', ['-setwebproxystate', svc, 'off']);
      await run('/usr/sbin/networksetup', ['-setsecurewebproxystate', svc, 'off']);
    }
  }
}

function buildHostsBlock(web) {
  const lines = [MARK_BEGIN];
  const sink = new Set();
  if (web.mode === 'blacklist') {
    for (const d of [...(web.denyDomains || []), ...categoryDomains(web.categories, CATEGORIES)]) {
      sink.add(normHost(d)); sink.add('www.' + normHost(d));
    }
  }
  for (const d of sink) lines.push(`0.0.0.0 ${d}`);
  if (web.forceSafeSearch) for (const l of safeSearchHostsLines()) lines.push(l);
  lines.push(MARK_END);
  return lines.join('\n');
}

function writeHosts(web) {
  requireMode('to rewrite /etc/hosts');
  if (isDryRun()) { log('web: (dry) would rewrite hosts block'); return; }
  let content = '';
  try { content = fs.readFileSync(HOSTS_PATH, 'utf8'); } catch { content = ''; }
  content = content.replace(new RegExp(`${MARK_BEGIN}[\\s\\S]*?${MARK_END}`, 'g'), '').replace(/\n{3,}/g, '\n\n').trimEnd();
  try { fs.writeFileSync(HOSTS_PATH, content + '\n' + buildHostsBlock(web) + '\n'); log('web: /etc/hosts updated'); }
  catch (e) { log('web: hosts write failed (need root):', e.message); }
}

async function integrateSystem(web) {
  writeHosts(web);
  await setSystemProxy(web);
  await run('/usr/bin/dscacheutil', ['-flushcache']);
  await run('/usr/bin/killall', ['-HUP', 'mDNSResponder']);
}

async function apply(web) { setPolicy(web); await integrateSystem(currentWeb); }
async function reassertSystemProxy() { if (currentWeb.mode === 'whitelist') await setSystemProxy(currentWeb); }

module.exports = { apply, setPolicy, integrateSystem, setSystemProxy, reassertSystemProxy, buildHostsBlock, onBlock };

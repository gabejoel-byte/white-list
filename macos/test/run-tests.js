'use strict';
// macOS agent tests. No system mutation: pure logic + a live proxy exercised
// through the shared core (localhost only).
const assert = require('assert');
const http = require('http');
const apps = require('../src/enforce/apps');
const vpn = require('../src/enforce/vpn');
const { createFilterProxy } = require('../../core/proxy');
const CATEGORIES = require('../src/data/categories.json');

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); console.log('  \x1b[32mPASS\x1b[0m', name); passed++; }
  catch (e) { console.log('  \x1b[31mFAIL\x1b[0m', name, '\n       ', e.message); failed++; }
}
const section = (s) => console.log('\n' + s);

(async () => {
  section('macOS app control decisions');
  const procs = [
    { name: 'safari', pid: 1 }, { name: 'terminal', pid: 2 },
    { name: 'finder', pid: 3 },   // critical
    { name: 'launchd', pid: 4 },  // critical
    { name: 'steam', pid: 5 },
  ];
  await test('whitelist kills non-allowed, spares criticals', () => {
    const k = apps.decideKills(procs, { mode: 'whitelist', allow: ['safari'] }).map((x) => x.name).sort();
    assert.deepStrictEqual(k, ['steam', 'terminal']);
  });
  await test('blacklist kills only denied', () => {
    const k = apps.decideKills(procs, { mode: 'blacklist', deny: ['steam'] }).map((x) => x.name);
    assert.deepStrictEqual(k, ['steam']);
  });
  await test('app-access profile lists the right bundle ids', () => {
    const xml = apps.buildProfile({ mode: 'whitelist', allow: ['com.apple.Safari'] });
    assert.match(xml, /com\.apple\.applicationaccess\.new/);
    assert.match(xml, /whitelistedAppBundleIDs/);
    assert.match(xml, /com\.apple\.Safari/);
  });

  section('macOS vpn rules');
  await test('pf rules block the common VPN ports', () => {
    const r = vpn.pfRules();
    assert.match(r, /port 1194/);   // OpenVPN
    assert.match(r, /port 51820/);  // WireGuard
    assert.match(r, /proto gre/);   // PPTP
  });

  section('shared filtering proxy (no system changes)');
  const originPort = 19021, proxyPort = 18092;
  let webPolicy = { mode: 'whitelist', allowDomains: ['allowed.test'] };
  const proxy = createFilterProxy({ getPolicy: () => webPolicy, categories: CATEGORIES });
  const origin = http.createServer((q, r) => r.end('ORIGIN-OK')).listen(originPort, '127.0.0.1');
  proxy.start(proxyPort);
  await new Promise((r) => setTimeout(r, 300));
  const reqVia = (host) => new Promise((res) => {
    const r = http.request({ host: '127.0.0.1', port: proxyPort, method: 'GET', path: `http://127.0.0.1:${originPort}/`, headers: { host } },
      (rs) => { let b = ''; rs.on('data', (d) => (b += d)); rs.on('end', () => res({ s: rs.statusCode, b })); });
    r.on('error', (e) => res({ s: -1, b: e.message })); r.end();
  });
  await test('allowed host forwards (200)', async () => { const r = await reqVia('allowed.test'); assert.strictEqual(r.s, 200); assert.match(r.b, /ORIGIN-OK/); });
  await test('blocked host refused (403)', async () => { const r = await reqVia('blocked.test'); assert.strictEqual(r.s, 403); });
  await test('blacklist category domain refused', async () => {
    webPolicy = { mode: 'blacklist', denyDomains: [], categories: ['pornography'] };
    const r = await reqVia('pornhub.com'); assert.strictEqual(r.s, 403);
  });
  origin.close(); proxy.stop();

  console.log(`\n${failed ? '\x1b[31m' : '\x1b[32m'}${passed} passed, ${failed} failed\x1b[0m`);
  process.exit(failed ? 1 : 0);
})();

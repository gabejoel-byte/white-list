'use strict';
// Self-contained test suite for the agent's enforcement logic.
//
// SAFETY: this suite never mutates the real machine.
//   * The filtering-proxy tests use web.setPolicy() (in-memory rules + a
//     localhost server only) — no registry/hosts/DNS writes at all.
//   * The one test that exercises the system-proxy writer points it at a
//     THROWAWAY registry key via WL_PROXY_REGKEY, runs it, verifies it, then
//     deletes that key — and asserts the machine's REAL proxy is untouched.
//   * A guard test proves that a system command with no execution mode chosen
//     throws instead of running.
//
// Run: node test/run-tests.js   (or: npm test)

// Must be set BEFORE requiring web.js (it reads the env at load time).
const SCRATCH_KEY = 'HKCU\\Software\\WhitelistAgentTest';
process.env.WL_PROXY_REGKEY = SCRATCH_KEY;

const assert = require('assert');
const http = require('http');
const { execFileSync } = require('child_process');
const util = require('../src/lib/util');
const web = require('../src/enforce/web');

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); console.log('  \x1b[32mPASS\x1b[0m', name); passed++; }
  catch (e) { console.log('  \x1b[31mFAIL\x1b[0m', name, '\n       ', e.message); failed++; }
}
const section = (s) => console.log('\n' + s);

function reqThroughProxy(port, hostHeader, originPort) {
  return new Promise((resolve) => {
    const r = http.request({ host: '127.0.0.1', port, method: 'GET', path: `http://127.0.0.1:${originPort}/`, headers: { host: hostHeader } },
      (res) => { let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => resolve({ status: res.statusCode, body: b })); });
    r.on('error', (e) => resolve({ status: -1, body: e.message }));
    r.end();
  });
}

function regQuery(key, value) {
  try { return execFileSync('reg.exe', ['query', key, '/v', value], { encoding: 'utf8' }); }
  catch (e) { return 'ERR:' + (e.stderr || e.message); }
}

(async () => {
  // ---- 1. domain matching semantics ----
  section('domain matching');
  await test('bare domain matches apex + subdomains', () => {
    assert.strictEqual(web.domainMatches('example.com', 'example.com'), true);
    assert.strictEqual(web.domainMatches('sub.example.com', 'example.com'), true);
  });
  await test('*.wildcard matches subdomains only, NOT apex', () => {
    assert.strictEqual(web.domainMatches('a.wikipedia.org', '*.wikipedia.org'), true);
    assert.strictEqual(web.domainMatches('wikipedia.org', '*.wikipedia.org'), false);
  });
  await test('no false-positive substring match', () => {
    assert.strictEqual(web.domainMatches('notexample.com', 'example.com'), false);
    assert.strictEqual(web.domainMatches('example.com.evil.com', 'example.com'), false);
  });

  // ---- 2. verdicts per mode ----
  section('policy verdicts');
  await test('whitelist: only listed domains allowed', () => {
    const p = { mode: 'whitelist', allowDomains: ['example.com', '*.school.edu'] };
    assert.strictEqual(web.verdict('example.com', p), 'allow');
    assert.strictEqual(web.verdict('mail.school.edu', p), 'allow');
    assert.strictEqual(web.verdict('evil.com', p), 'deny');
  });
  await test('blacklist: listed domains + categories denied, rest allowed', () => {
    const p = { mode: 'blacklist', denyDomains: ['facebook.com'], categories: ['pornography'] };
    assert.strictEqual(web.verdict('facebook.com', p), 'deny');
    assert.strictEqual(web.verdict('m.facebook.com', p), 'deny');
    assert.strictEqual(web.verdict('pornhub.com', p), 'deny');
    assert.strictEqual(web.verdict('wikipedia.org', p), 'allow');
  });
  await test('off: everything allowed', () => {
    assert.strictEqual(web.verdict('anything.com', { mode: 'off' }), 'allow');
  });

  // ---- 3. live filtering proxy, NO system mutation ----
  section('live filtering proxy (no system changes)');
  const originPort = 19011, proxyPort = 18091;
  const origin = http.createServer((q, r) => r.end('ORIGIN-OK')).listen(originPort, '127.0.0.1');
  web.setPolicy({ mode: 'whitelist', allowDomains: ['allowed.test'], proxyPort }); // in-memory only
  await new Promise((r) => setTimeout(r, 300));
  await test('allowed host is forwarded to origin (200)', async () => {
    const res = await reqThroughProxy(proxyPort, 'allowed.test', originPort);
    assert.strictEqual(res.status, 200);
    assert.match(res.body, /ORIGIN-OK/);
  });
  await test('blocked host is refused (403)', async () => {
    const res = await reqThroughProxy(proxyPort, 'blocked.test', originPort);
    assert.strictEqual(res.status, 403);
  });
  origin.close();

  // ---- 4. execution-mode guard (measure 2) ----
  section('execution-mode guard');
  await test('system command throws when no mode is set (unset)', async () => {
    util.setMode('unset');
    await assert.rejects(
      () => web.integrateSystem({ mode: 'whitelist', proxyPort }),
      /no execution mode set/,
    );
  });

  // ---- 5. system proxy writes to SCRATCH key only (measure 1) ----
  section('system proxy uses scratch registry key');
  // Snapshot the REAL proxy state so we can prove we didn't touch it.
  const realBefore = regQuery('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', 'ProxyServer');
  await test('setSystemProxy writes only to the scratch key', async () => {
    util.setLive();                                   // deliberately live for this test
    await web.setSystemProxy({ mode: 'whitelist', proxyPort: 18091 });
    const scratch = regQuery(SCRATCH_KEY, 'ProxyServer');
    assert.match(scratch, /127\.0\.0\.1:18091/, 'scratch key should hold our proxy');
  });
  await test('REAL Internet Settings proxy is unchanged', () => {
    const realAfter = regQuery('HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', 'ProxyServer');
    assert.strictEqual(realAfter, realBefore, 'real proxy must be identical to before the test');
  });

  // ---- 6. app control: pure kill-decision logic (no processes harmed) ----
  section('app control decisions');
  const apps = require('../src/enforce/apps');
  const procList = [
    { name: 'chrome.exe', pid: 100 },
    { name: 'notepad.exe', pid: 101 },
    { name: 'explorer.exe', pid: 102 },   // critical — never killed
    { name: 'lsass.exe', pid: 103 },      // critical — never killed
    { name: 'game.exe', pid: 104 },
  ];
  await test('whitelist kills everything not allowed (but never criticals)', () => {
    const kills = apps.decideKills(procList, { mode: 'whitelist', allow: ['chrome.exe'] });
    const names = kills.map((k) => k.name).sort();
    assert.deepStrictEqual(names, ['game.exe', 'notepad.exe']);
    assert.ok(!names.includes('explorer.exe') && !names.includes('lsass.exe'));
  });
  await test('blacklist kills only denied', () => {
    const kills = apps.decideKills(procList, { mode: 'blacklist', deny: ['game.exe'] });
    assert.deepStrictEqual(kills.map((k) => k.name), ['game.exe']);
  });
  await test('off mode kills nothing', () => {
    assert.deepStrictEqual(apps.decideKills(procList, { mode: 'off' }), []);
  });
  await test('AppLocker support: Home=false, Enterprise/Pro=true', () => {
    assert.strictEqual(apps.appLockerSupported('Microsoft Windows 11 Home'), false);
    assert.strictEqual(apps.appLockerSupported('Microsoft Windows 11 Enterprise'), true);
    assert.strictEqual(apps.appLockerSupported('Microsoft Windows 11 Pro'), true);
  });
  await test('IFEO commands set a Debugger no-op per denied exe', () => {
    const cmds = apps.ifeoCommands(['game.exe', 'C:\\x\\bad.exe']);
    assert.strictEqual(cmds.length, 2);
    assert.deepStrictEqual(cmds[0].slice(0, 2), ['add', 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\game.exe']);
    assert.ok(cmds[0].includes('Debugger'));
    assert.strictEqual(cmds[1][1].endsWith('\\bad.exe'), true); // basename used
  });
  await test('WDAC build script is audit-mode by default, enforce on request', () => {
    const audit = apps.wdacBuildScript({ mode: 'whitelist', allow: ['C:\\A\\a.exe'] });
    assert.match(audit.script, /Set-RuleOption .* -Option 3(?! -Delete)/);  // audit kept
    assert.match(audit.script, /ConvertFrom-CIPolicy/);
    const enf = apps.wdacBuildScript({ mode: 'whitelist', allow: ['C:\\A\\a.exe'] }, { enforce: true });
    assert.match(enf.script, /-Option 3 -Delete/);                          // audit removed => enforce
  });

  // Cleanup: delete the scratch key and reset mode.
  try { execFileSync('reg.exe', ['delete', SCRATCH_KEY, '/f'], { stdio: 'ignore' }); } catch { /* may not exist */ }
  util.setMode('unset');

  console.log(`\n${failed ? '\x1b[31m' : '\x1b[32m'}${passed} passed, ${failed} failed\x1b[0m`);
  origin.unref?.();
  process.exit(failed ? 1 : 0);
})();

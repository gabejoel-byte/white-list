'use strict';
// Tests the dashboard's Android integration lib without any GCP credentials:
// the pure mapping must work, and the network paths must fail closed.
const assert = require('assert');
const android = require('../src/lib/android');

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); console.log('  \x1b[32mPASS\x1b[0m', name); passed++; }
  catch (e) { console.log('  \x1b[31mFAIL\x1b[0m', name, '\n       ', e.message); failed++; }
}

(async () => {
  console.log('\nAndroid dashboard integration');

  await test('status reports not-configured without creds', () => {
    delete process.env.GOOGLE_APPLICATION_CREDENTIALS;
    delete process.env.ENTERPRISE_NAME;
    const s = android.status();
    assert.strictEqual(s.configured, false);
  });

  await test('preview maps a stored policy body to an AMAPI Policy (no creds needed)', () => {
    const body = JSON.stringify({
      level: 3,
      apps: { mode: 'whitelist', allow: ['com.android.chrome'] },
      web: { mode: 'whitelist', allowDomains: ['school.edu'], forceSafeSearch: true },
      vpn: { block: true },
      tamper: { preventUninstall: true },
    });
    const m = android.preview(body);
    assert.strictEqual(m.playStoreMode, 'WHITELIST');
    assert.strictEqual(m.vpnConfigDisabled, true);
    assert.strictEqual(m.uninstallAppsDisabled, true);
    const chrome = m.applications.find((a) => a.packageName === 'com.android.chrome');
    assert.ok(chrome, 'chrome present');
    assert.deepStrictEqual(chrome.managedConfiguration.URLAllowlist, ['school.edu']);
  });

  await test('pushPolicy fails closed (409) when not configured', async () => {
    await assert.rejects(() => android.pushPolicy('1', '{}'), (e) => e.message === 'android_not_configured' && e.status === 409);
  });

  await test('listDevices returns [] when not configured (no throw)', async () => {
    assert.deepStrictEqual(await android.listDevices(), []);
  });

  console.log(`\n${failed ? '\x1b[31m' : '\x1b[32m'}${passed} passed, ${failed} failed\x1b[0m`);
  process.exit(failed ? 1 : 0);
})();

'use strict';
// Pure tests for the Android Management API policy mapping — no credentials,
// no network. Verifies our policy shape produces the right AMAPI fields.
const assert = require('assert');
const { mapPolicy, chromeManagedConfig, CHROME } = require('../src/policy-map');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); console.log('  \x1b[32mPASS\x1b[0m', name); passed++; }
  catch (e) { console.log('  \x1b[31mFAIL\x1b[0m', name, '\n       ', e.message); failed++; }
}
const section = (s) => console.log('\n' + s);

section('app control mapping');
test('whitelist -> playStoreMode WHITELIST + allowed apps FORCE_INSTALLED', () => {
  const p = mapPolicy({ level: 3, apps: { mode: 'whitelist', allow: ['com.example.reader'] }, web: { mode: 'off' } });
  assert.strictEqual(p.playStoreMode, 'WHITELIST');
  const reader = p.applications.find((a) => a.packageName === 'com.example.reader');
  assert.strictEqual(reader.installType, 'FORCE_INSTALLED');
});
test('kiosk whitelist -> installType KIOSK + kioskCustomLauncherEnabled', () => {
  const p = mapPolicy({ level: 3, kiosk: true, apps: { mode: 'whitelist', allow: ['com.example.kiosk'] }, web: { mode: 'off' } });
  assert.strictEqual(p.applications[0].installType, 'KIOSK');
  assert.strictEqual(p.kioskCustomLauncherEnabled, true);
});
test('blacklist -> playStoreMode BLACKLIST + denied apps BLOCKED', () => {
  const p = mapPolicy({ level: 2, apps: { mode: 'blacklist', deny: ['com.bad.app'] }, web: { mode: 'off' } });
  assert.strictEqual(p.playStoreMode, 'BLACKLIST');
  assert.strictEqual(p.applications.find((a) => a.packageName === 'com.bad.app').installType, 'BLOCKED');
});

section('web filtering via Chrome managed config');
test('whitelist web -> URLBlocklist [*] + URLAllowlist', () => {
  const mc = chromeManagedConfig({ mode: 'whitelist', allowDomains: ['school.edu'] });
  assert.deepStrictEqual(mc.URLBlocklist, ['*']);
  assert.deepStrictEqual(mc.URLAllowlist, ['school.edu']);
});
test('blacklist web -> URLBlocklist includes denied + category domains', () => {
  const mc = chromeManagedConfig({ mode: 'blacklist', denyDomains: ['facebook.com'], categories: ['pornography'] });
  assert.ok(mc.URLBlocklist.includes('facebook.com'));
  assert.ok(mc.URLBlocklist.includes('pornhub.com')); // from category map
});
test('forceSafeSearch -> ForceGoogleSafeSearch + YouTube strict + incognito disabled', () => {
  const mc = chromeManagedConfig({ mode: 'blacklist', denyDomains: [], forceSafeSearch: true });
  assert.strictEqual(mc.ForceGoogleSafeSearch, true);
  assert.strictEqual(mc.ForceYouTubeRestrict, 2);
  assert.strictEqual(mc.IncognitoModeAvailability, 1);
});
test('web policy force-installs Chrome with the managed config attached', () => {
  const p = mapPolicy({ level: 2, apps: { mode: 'blacklist', deny: [] }, web: { mode: 'blacklist', denyDomains: ['x.com'] } });
  const chrome = p.applications.find((a) => a.packageName === CHROME);
  assert.strictEqual(chrome.installType, 'FORCE_INSTALLED');
  assert.ok(chrome.managedConfiguration.URLBlocklist.includes('x.com'));
});

section('tamper + vpn mapping');
test('preventUninstall -> uninstallAppsDisabled + factoryResetDisabled', () => {
  const p = mapPolicy({ level: 3, apps: { mode: 'whitelist', allow: [] }, web: { mode: 'off' }, tamper: { preventUninstall: true } });
  assert.strictEqual(p.uninstallAppsDisabled, true);
  assert.strictEqual(p.factoryResetDisabled, true);
});
test('vpn.block -> vpnConfigDisabled true', () => {
  const p = mapPolicy({ level: 3, apps: { mode: 'whitelist', allow: [] }, web: { mode: 'off' }, vpn: { block: true } });
  assert.strictEqual(p.vpnConfigDisabled, true);
});
test('filteringVpnPackage -> alwaysOnVpnPackage with lockdown', () => {
  const p = mapPolicy({ level: 3, apps: { mode: 'whitelist', allow: [] }, web: { mode: 'off' }, vpn: { block: true }, filteringVpnPackage: 'com.filter.vpn' });
  assert.deepStrictEqual(p.alwaysOnVpnPackage, { packageName: 'com.filter.vpn', lockdownEnabled: true });
});

console.log(`\n${failed ? '\x1b[31m' : '\x1b[32m'}${passed} passed, ${failed} failed\x1b[0m`);
process.exit(failed ? 1 : 0);

'use strict';
// Pure tests for the iOS profile mapping + plist serializer. No network.
const assert = require('assert');
const pm = require('../src/profile-map');
const { build } = require('../src/plist');
const mdm = require('../src/mdm');

let passed = 0, failed = 0;
function test(name, fn) {
  try { fn(); console.log('  \x1b[32mPASS\x1b[0m', name); passed++; }
  catch (e) { console.log('  \x1b[31mFAIL\x1b[0m', name, '\n       ', e.message); failed++; }
}
const section = (s) => console.log('\n' + s);
const find = (list, type) => list.find((p) => p.PayloadType === type);

section('plist serializer');
test('serializes dict/array/bool/int with escaping', () => {
  const xml = build({ K: 'a&b', N: 5, B: true, A: ['x'] });
  assert.match(xml, /<key>K<\/key>\s*<string>a&amp;b<\/string>/);
  assert.match(xml, /<integer>5<\/integer>/);
  assert.match(xml, /<true\/>/);
  assert.match(xml, /<array>[\s\S]*<string>x<\/string>[\s\S]*<\/array>/);
});
test('Buffer becomes <data> base64', () => {
  assert.match(build({ D: Buffer.from('hi') }), /<data>aGk=<\/data>/);
});

section('app restrictions mapping');
test('whitelist -> allowListedAppBundleIDs', () => {
  const p = pm.restrictionsPayload({ apps: { mode: 'whitelist', allow: ['com.apple.Safari'] } });
  assert.deepStrictEqual(p.allowListedAppBundleIDs, ['com.apple.Safari']);
});
test('blacklist -> blockedAppBundleIDs', () => {
  const p = pm.restrictionsPayload({ apps: { mode: 'blacklist', deny: ['com.game.x'] } });
  assert.deepStrictEqual(p.blockedAppBundleIDs, ['com.game.x']);
});
test('preventUninstall -> allowAppRemoval false; vpn.block -> allowVPNCreation false', () => {
  const p = pm.restrictionsPayload({ apps: { mode: 'off' }, tamper: { preventUninstall: true }, vpn: { block: true } });
  assert.strictEqual(p.allowAppRemoval, false);
  assert.strictEqual(p.allowVPNCreation, false);
});

section('web content filter mapping');
test('whitelist -> BuiltIn + AutoFilter + PermittedURLs (https-expanded)', () => {
  const p = pm.webFilterPayload({ mode: 'whitelist', allowDomains: ['school.edu'] });
  assert.strictEqual(p.FilterType, 'BuiltIn');
  assert.strictEqual(p.AutoFilterEnabled, true);
  assert.deepStrictEqual(p.PermittedURLs, ['https://school.edu']);
});
test('blacklist -> DenyListURLs includes denied + category domains', () => {
  const p = pm.webFilterPayload({ mode: 'blacklist', denyDomains: ['facebook.com'], categories: ['pornography'] });
  assert.ok(p.DenyListURLs.includes('https://facebook.com'));
  assert.ok(p.DenyListURLs.some((u) => u.includes('pornhub.com')));
});

section('full profile assembly');
test('lockdown profile: restrictions + filter + non-removable + proxy', () => {
  const prof = pm.profile({
    level: 3, kiosk: false, forceProxy: true,
    apps: { mode: 'whitelist', allow: ['com.apple.Safari', 'com.app.reader'] },
    web: { mode: 'whitelist', allowDomains: ['school.edu'], proxyHost: 'proxy.example.com', proxyPort: 8080 },
    vpn: { block: true }, tamper: { preventUninstall: true },
  });
  assert.strictEqual(prof.PayloadRemovalDisallowed, true);
  assert.ok(find(prof.PayloadContent, 'com.apple.applicationaccess'));
  assert.ok(find(prof.PayloadContent, 'com.apple.webcontent-filter'));
  const proxy = find(prof.PayloadContent, 'com.apple.proxy.http.global');
  assert.strictEqual(proxy.ProxyServer, 'proxy.example.com');
  assert.strictEqual(proxy.ProxyServerPort, 8080);
});
test('single-app whitelist + kiosk -> app.lock payload', () => {
  const prof = pm.profile({ level: 3, kiosk: true, apps: { mode: 'whitelist', allow: ['com.kiosk.app'] }, web: { mode: 'off' } });
  const lock = find(prof.PayloadContent, 'com.apple.app.lock');
  assert.strictEqual(lock.App.Identifier, 'com.kiosk.app');
});
test('buildProfile emits valid plist XML', () => {
  const xml = pm.buildProfile({ level: 2, apps: { mode: 'blacklist', deny: [] }, web: { mode: 'blacklist', denyDomains: ['x.com'] } });
  assert.match(xml, /<!DOCTYPE plist/);
  assert.match(xml, /com\.apple\.webcontent-filter/);
});

section('MDM scaffolding');
test('enrollment profile has com.apple.mdm payload with ServerURL + Topic', () => {
  const xml = mdm.enrollmentProfile({ serverUrl: 'https://mdm.example.com', topic: 'com.apple.mgmt.External.abc' });
  assert.match(xml, /com\.apple\.mdm/);
  assert.match(xml, /https:\/\/mdm\.example\.com\/mdm\/command/);
  assert.match(xml, /com\.apple\.mgmt\.External\.abc/);
});
test('InstallProfile command wraps the mobileconfig as <data>', () => {
  const xml = mdm.installProfileCommand('<plist>x</plist>');
  assert.match(xml, /InstallProfile/);
  assert.match(xml, /<data>/);
});

console.log(`\n${failed ? '\x1b[31m' : '\x1b[32m'}${passed} passed, ${failed} failed\x1b[0m`);
process.exit(failed ? 1 : 0);

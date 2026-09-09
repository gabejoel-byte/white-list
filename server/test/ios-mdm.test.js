'use strict';
// iOS MDM tests: plist parse round-trip, profile generation, and the live
// check-in -> command -> acknowledge protocol against the real route handlers.
// Uses a throwaway DATA_DIR so it never touches the real dashboard database.
const os = require('os');
const path = require('path');
const fs = require('fs');
const http = require('http');
const assert = require('assert');

const TMP = fs.mkdtempSync(path.join(os.tmpdir(), 'wl-ios-'));
process.env.DATA_DIR = TMP;
process.env.MDM_SERVER_URL = 'https://mdm.example.com';
process.env.MDM_TOPIC = 'com.apple.mgmt.External.test';

const { build } = require('../../ios/src/plist');
const { parse } = require('../src/lib/plist-parse');
const ios = require('../src/lib/ios');
const db = require('../src/db');
const express = require('express');
const mdmRoutes = require('../src/routes/mdm');

let passed = 0, failed = 0;
async function test(name, fn) {
  try { await fn(); console.log('  \x1b[32mPASS\x1b[0m', name); passed++; }
  catch (e) { console.log('  \x1b[31mFAIL\x1b[0m', name, '\n       ', e.message); failed++; }
}
const section = (s) => console.log('\n' + s);

function req(server, method, path, body, ctype = 'application/xml') {
  return new Promise((resolve) => {
    const { port } = server.address();
    const r = http.request({ host: '127.0.0.1', port, method, path, headers: { 'content-type': ctype } },
      (res) => { let b = ''; res.on('data', (d) => (b += d)); res.on('end', () => resolve({ status: res.statusCode, body: b })); });
    r.on('error', (e) => resolve({ status: -1, body: e.message }));
    if (body) r.write(body); r.end();
  });
}

(async () => {
  section('plist round-trip');
  await test('serialize -> parse preserves dict/array/int/bool/data', () => {
    const orig = { Name: 'a&b <ok>', N: 42, B: true, Arr: ['x', 'y'], Data: Buffer.from('hi') };
    const back = parse(build(orig));
    assert.strictEqual(back.Name, 'a&b <ok>');
    assert.strictEqual(back.N, 42);
    assert.strictEqual(back.B, true);
    assert.deepStrictEqual(back.Arr, ['x', 'y']);
    assert.strictEqual(back.Data.toString(), 'hi');
  });

  section('profile generation');
  await test('enrollment profile is served when MDM_SERVER_URL + topic set', () => {
    const xml = ios.enrollmentProfile();
    assert.match(xml, /com\.apple\.mdm/);
    assert.match(xml, /https:\/\/mdm\.example\.com\/mdm\/command/);
  });
  await test('policy profile maps a stored policy to a .mobileconfig', () => {
    const body = JSON.stringify({ level: 3, apps: { mode: 'whitelist', allow: ['com.apple.Safari'] }, web: { mode: 'whitelist', allowDomains: ['school.edu'] }, vpn: { block: true }, tamper: { preventUninstall: true } });
    const xml = ios.policyProfile(body);
    assert.match(xml, /com\.apple\.applicationaccess/);
    assert.match(xml, /com\.apple\.webcontent-filter/);
  });

  section('live MDM protocol (checkin -> command -> ack)');
  const app = express();
  app.use('/mdm', mdmRoutes);
  const server = await new Promise((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  const UDID = 'ABC-123-UDID';

  await test('TokenUpdate check-in registers the device', async () => {
    const token = Buffer.from('deadbeef', 'hex');
    const body = build({ MessageType: 'TokenUpdate', UDID, Token: token, PushMagic: 'MAGIC', Topic: process.env.MDM_TOPIC });
    const r = await req(server, 'PUT', '/mdm/checkin', body);
    assert.strictEqual(r.status, 200);
    const dev = db.prepare('SELECT * FROM ios_devices WHERE udid=?').get(UDID);
    assert.strictEqual(dev.push_magic, 'MAGIC');
    assert.strictEqual(dev.push_token, 'deadbeef');
  });

  await test('queued InstallProfile is delivered on Idle poll', async () => {
    // Seed a policy and queue its profile onto the device.
    const info = db.prepare('INSERT INTO policies (name, version, body) VALUES (?, 1, ?)')
      .run('iosL3', JSON.stringify({ level: 3, apps: { mode: 'whitelist', allow: ['com.apple.Safari'] }, web: { mode: 'off' }, tamper: { preventUninstall: true } }));
    await ios.applyPolicy(UDID, info.lastInsertRowid);
    const r = await req(server, 'PUT', '/mdm/command', build({ UDID, Status: 'Idle' }));
    assert.strictEqual(r.status, 200);
    assert.match(r.body, /InstallProfile/);
    const cmd = parse(r.body);
    assert.ok(cmd.CommandUUID, 'has a CommandUUID');
    // Acknowledge it → next poll returns empty.
    const ack = await req(server, 'PUT', '/mdm/command', build({ UDID, Status: 'Acknowledged', CommandUUID: cmd.CommandUUID }));
    assert.strictEqual(ack.status, 200);
    assert.strictEqual(ack.body.trim(), '', 'no more commands');
  });

  server.close();
  try { fs.rmSync(TMP, { recursive: true, force: true }); } catch { /* db may be locked on win */ }
  console.log(`\n${failed ? '\x1b[31m' : '\x1b[32m'}${passed} passed, ${failed} failed\x1b[0m`);
  process.exit(failed ? 1 : 0);
})();

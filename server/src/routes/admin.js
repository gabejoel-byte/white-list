'use strict';
// Dashboard API: login + CRUD for policies, enrollment keys, devices, commands.
const express = require('express');
const db = require('../db');
const { token, sha256 } = require('../lib/crypto');
const { requireAdmin, createSession, verifySecret } = require('../lib/auth');
const { normalize, preset } = require('../lib/policy');
const android = require('../lib/android');
const ios = require('../lib/ios');

const router = express.Router();

// ---- auth ----
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username || '');
  if (!admin || !verifySecret(password || '', admin.pass_hash)) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  const sid = createSession(admin.id);
  res.cookie('sid', sid, { httpOnly: true, sameSite: 'lax', secure: !!process.env.HTTPS });
  res.json({ ok: true, username: admin.username });
});

router.post('/logout', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(req.cookies.sid);
  res.clearCookie('sid');
  res.json({ ok: true });
});

router.get('/me', requireAdmin, (req, res) => res.json({ username: req.admin.username }));

// Everything below requires an admin session.
router.use(requireAdmin);

// ---- policies ----
router.get('/policies', (req, res) => {
  const rows = db.prepare('SELECT id, name, version, body, updated_at FROM policies ORDER BY name').all();
  res.json(rows.map((r) => ({ ...r, body: normalize(r.body) })));
});

router.post('/policies', (req, res) => {
  const { name, level = 3, body = {} } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name_required' });
  const merged = normalize({ ...preset(level), ...body, level });
  const info = db.prepare('INSERT INTO policies (name, version, body) VALUES (?, 1, ?)')
    .run(name, JSON.stringify(merged));
  res.json({ id: info.lastInsertRowid });
});

router.put('/policies/:id', (req, res) => {
  const id = +req.params.id;
  const cur = db.prepare('SELECT * FROM policies WHERE id = ?').get(id);
  if (!cur) return res.status(404).json({ error: 'not_found' });
  const { name, body, unlockKey } = req.body || {};
  const merged = normalize({ ...JSON.parse(cur.body), ...(body || {}) });
  // If an unlock key was (re)set, store only its hash into the policy body.
  if (typeof unlockKey === 'string' && unlockKey.length) {
    merged.tamper.unlockKeyHash = sha256(unlockKey);
  }
  db.prepare('UPDATE policies SET name=?, body=?, version=version+1, updated_at=datetime(\'now\') WHERE id=?')
    .run(name || cur.name, JSON.stringify(merged), id);
  res.json({ ok: true, version: cur.version + 1 });
});

router.delete('/policies/:id', (req, res) => {
  db.prepare('UPDATE devices SET policy_id=NULL WHERE policy_id=?').run(+req.params.id);
  db.prepare('DELETE FROM policies WHERE id=?').run(+req.params.id);
  res.json({ ok: true });
});

// ---- enrollment keys ----
router.get('/enrollment-keys', (req, res) => {
  res.json(db.prepare('SELECT id, key, label, policy_id, revoked, created_at FROM enrollment_keys ORDER BY id DESC').all());
});

router.post('/enrollment-keys', (req, res) => {
  const { label, policyId } = req.body || {};
  const key = 'ENR-' + token(12);
  const info = db.prepare('INSERT INTO enrollment_keys (key, label, policy_id) VALUES (?, ?, ?)')
    .run(key, label || null, policyId || null);
  res.json({ id: info.lastInsertRowid, key });
});

router.post('/enrollment-keys/:id/revoke', (req, res) => {
  db.prepare('UPDATE enrollment_keys SET revoked=1 WHERE id=?').run(+req.params.id);
  res.json({ ok: true });
});

// ---- devices ----
router.get('/devices', (req, res) => {
  const rows = db.prepare(`
    SELECT d.*, p.name AS policy_name, p.version AS policy_target_version
    FROM devices d LEFT JOIN policies p ON p.id = d.policy_id
    ORDER BY d.last_seen DESC NULLS LAST`).all();
  const now = Date.now();
  res.json(rows.map((d) => ({
    id: d.id, hostname: d.hostname, label: d.label, os: d.os, machineId: d.machine_id,
    policyId: d.policy_id, policyName: d.policy_name,
    policyVersion: d.policy_version, policyTargetVersion: d.policy_target_version,
    agentVersion: d.agent_version, lastSeen: d.last_seen, revoked: !!d.revoked,
    status: d.status ? JSON.parse(d.status) : null,
    online: d.last_seen ? (now - Date.parse(d.last_seen + 'Z')) < 120000 : false,
  })));
});

router.put('/devices/:id/policy', (req, res) => {
  const { policyId } = req.body || {};
  db.prepare('UPDATE devices SET policy_id=?, policy_version=0 WHERE id=?').run(policyId || null, req.params.id);
  res.json({ ok: true });
});

// Friendly name for a device (so you can tell machines apart).
router.put('/devices/:id/label', (req, res) => {
  const label = (req.body?.label || '').toString().slice(0, 80).trim() || null;
  db.prepare('UPDATE devices SET label=? WHERE id=?').run(label, req.params.id);
  res.json({ ok: true, label });
});

router.post('/devices/:id/command', (req, res) => {
  const { type, payload } = req.body || {};
  const allowed = ['unlock', 'refresh', 'uninstall', 'reenroll'];
  if (!allowed.includes(type)) return res.status(400).json({ error: 'bad_command' });
  const id = token(8);
  db.prepare('INSERT INTO commands (id, device_id, type, payload) VALUES (?, ?, ?, ?)')
    .run(id, req.params.id, type, payload ? JSON.stringify(payload) : null);
  res.json({ ok: true, id });
});

router.post('/devices/:id/revoke', (req, res) => {
  db.prepare('UPDATE devices SET revoked=1 WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

router.get('/devices/:id/events', (req, res) => {
  res.json(db.prepare('SELECT kind, detail, at FROM events WHERE device_id=? ORDER BY at DESC LIMIT 200').all(req.params.id));
});

// ---- Android (Android Management API) ----
router.get('/android/status', (req, res) => res.json(android.status()));

// Preview the AMAPI Policy a stored policy maps to (works without GCP creds).
router.get('/android/policies/:id/preview', (req, res) => {
  const p = db.prepare('SELECT * FROM policies WHERE id = ?').get(+req.params.id);
  if (!p) return res.status(404).json({ error: 'not_found' });
  res.json(android.preview(p.body));
});

// Push a stored policy to Android Management API (requires configuration).
router.post('/android/policies/:id/push', async (req, res) => {
  const p = db.prepare('SELECT * FROM policies WHERE id = ?').get(+req.params.id);
  if (!p) return res.status(404).json({ error: 'not_found' });
  try { res.json(await android.pushPolicy(String(p.id), p.body)); }
  catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

router.post('/android/policies/:id/enrollment-token', async (req, res) => {
  try { res.json(await android.createEnrollmentToken(String(req.params.id), req.body || {})); }
  catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

router.get('/android/devices', async (req, res) => {
  try { res.json(await android.listDevices()); }
  catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

// ---- iOS (Apple MDM) ----
router.get('/ios/status', (req, res) => res.json(ios.status()));

// Preview the .mobileconfig a stored policy maps to (works without Apple creds).
router.get('/ios/policies/:id/preview', (req, res) => {
  const p = db.prepare('SELECT * FROM policies WHERE id = ?').get(+req.params.id);
  if (!p) return res.status(404).json({ error: 'not_found' });
  res.set('content-type', 'text/plain').send(ios.policyProfile(p.body));
});

// Download a policy's .mobileconfig for the FREE path (Apple Configurator /
// manual install) — no MDM/Apple Developer account needed.
router.get('/ios/policies/:id/profile.mobileconfig', (req, res) => {
  const p = db.prepare('SELECT * FROM policies WHERE id = ?').get(+req.params.id);
  if (!p) return res.status(404).json({ error: 'not_found' });
  const safe = (p.name || 'policy').replace(/[^a-z0-9]+/gi, '-').toLowerCase();
  res.set('content-type', 'application/x-apple-aspen-config');
  res.set('content-disposition', `attachment; filename="whitelist-${safe}.mobileconfig"`);
  res.send(ios.policyProfile(p.body));
});

router.get('/ios/devices', (req, res) => res.json(ios.listDevices()));

// Queue a policy's profile onto an enrolled device (+ APNs wake).
router.post('/ios/devices/:udid/apply/:policyId', async (req, res) => {
  try { res.json(await ios.applyPolicy(req.params.udid, +req.params.policyId)); }
  catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

module.exports = router;

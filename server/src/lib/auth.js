'use strict';
const db = require('../db');
const { token, hashSecret, verifySecret } = require('./crypto');

const SESSION_TTL_HOURS = 12;

function createSession(adminId) {
  const t = token(32);
  db.prepare(
    `INSERT INTO sessions (token, admin_id, expires_at)
     VALUES (?, ?, datetime('now', '+${SESSION_TTL_HOURS} hours'))`
  ).run(t, adminId);
  return t;
}

function adminFromSession(t) {
  if (!t) return null;
  const row = db.prepare(
    `SELECT a.id, a.username FROM sessions s
     JOIN admins a ON a.id = s.admin_id
     WHERE s.token = ? AND s.expires_at > datetime('now')`
  ).get(t);
  return row || null;
}

// Gate for the dashboard/admin API.
function requireAdmin(req, res, next) {
  const admin = adminFromSession(req.cookies?.sid);
  if (!admin) return res.status(401).json({ error: 'unauthorized' });
  req.admin = admin;
  next();
}

// Gate for the agent API: Bearer <deviceToken>.
function requireDevice(req, res, next) {
  const hdr = req.get('authorization') || '';
  const m = hdr.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'no_token' });
  const provided = m[1];
  // Device tokens are "<deviceId>.<secret>"; we look up by id then verify.
  const dot = provided.indexOf('.');
  if (dot < 0) return res.status(401).json({ error: 'bad_token' });
  const deviceId = provided.slice(0, dot);
  const secret = provided.slice(dot + 1);
  const dev = db.prepare('SELECT * FROM devices WHERE id = ? AND revoked = 0').get(deviceId);
  if (!dev || !verifySecret(secret, dev.token_hash)) {
    return res.status(401).json({ error: 'bad_token' });
  }
  req.device = dev;
  next();
}

module.exports = { createSession, adminFromSession, requireAdmin, requireDevice, hashSecret, verifySecret };

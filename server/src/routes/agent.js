'use strict';
// Agent-facing API: enrollment, heartbeat, policy pull, command delivery.
const express = require('express');
const db = require('../db');
const { token, hashSecret } = require('../lib/crypto');
const { requireDevice } = require('../lib/auth');
const { normalize } = require('../lib/policy');

const router = express.Router();

function logEvent(deviceId, kind, detail) {
  db.prepare('INSERT INTO events (device_id, kind, detail) VALUES (?, ?, ?)')
    .run(deviceId, kind, typeof detail === 'string' ? detail : JSON.stringify(detail || {}));
}

// POST /api/v1/enroll
router.post('/enroll', (req, res) => {
  const { enrollmentKey, hostname, os, machineId } = req.body || {};
  if (!enrollmentKey || !machineId) return res.status(400).json({ error: 'missing_fields' });

  const key = db.prepare('SELECT * FROM enrollment_keys WHERE key = ? AND revoked = 0').get(enrollmentKey);
  if (!key) return res.status(403).json({ error: 'invalid_enrollment_key' });

  const secret = token(32);
  const tokenHash = hashSecret(secret);

  // Re-enroll (same machine) rebinds rather than duplicating.
  const existing = db.prepare('SELECT * FROM devices WHERE machine_id = ?').get(machineId);
  let deviceId;
  if (existing) {
    deviceId = existing.id;
    db.prepare(
      `UPDATE devices SET token_hash=?, hostname=?, os=?, revoked=0, policy_id=COALESCE(policy_id, ?)
       WHERE id=?`
    ).run(tokenHash, hostname || existing.hostname, os || existing.os, key.policy_id, deviceId);
  } else {
    deviceId = token(12);
    db.prepare(
      `INSERT INTO devices (id, machine_id, token_hash, hostname, os, policy_id, policy_version)
       VALUES (?, ?, ?, ?, ?, ?, 0)`
    ).run(deviceId, machineId, tokenHash, hostname || null, os || null, key.policy_id || null);
  }
  logEvent(deviceId, 'enroll', { hostname, os, via: key.label || key.id });

  res.json({ deviceId, deviceToken: `${deviceId}.${secret}`, policyVersion: 0 });
});

// POST /api/v1/heartbeat
router.post('/heartbeat', requireDevice, (req, res) => {
  const dev = req.device;
  const { policyVersion = 0, agentVersion, status, events } = req.body || {};

  db.prepare('UPDATE devices SET last_seen=datetime(\'now\'), agent_version=?, status=?, policy_version=? WHERE id=?')
    .run(agentVersion || dev.agent_version, JSON.stringify(status || {}), policyVersion, dev.id);

  if (Array.isArray(events)) {
    for (const e of events.slice(0, 100)) logEvent(dev.id, e.kind || 'agent', e);
  }

  // Resolve effective policy for this device.
  let policyRow = null;
  if (dev.policy_id) policyRow = db.prepare('SELECT * FROM policies WHERE id = ?').get(dev.policy_id);
  let policy = null;
  let serverVersion = policyVersion;
  if (policyRow) {
    serverVersion = policyRow.version;
    if (policyRow.version > policyVersion) {
      policy = normalize(policyRow.body);
      policy.version = policyRow.version;
    }
  }

  // Pull queued commands.
  const cmds = db.prepare('SELECT * FROM commands WHERE device_id=? AND delivered=0').all(dev.id);
  if (cmds.length) {
    const mark = db.prepare('UPDATE commands SET delivered=1 WHERE id=?');
    for (const c of cmds) mark.run(c.id);
  }

  res.json({
    policyVersion: serverVersion,
    policy,
    commands: cmds.map((c) => ({ id: c.id, type: c.type, payload: c.payload ? JSON.parse(c.payload) : null })),
  });
});

module.exports = router;

'use strict';
// Apple MDM device-facing endpoints: check-in, command polling, enrollment.
// Devices speak plist; we parse incoming with plist-parse and reply with the
// command plists built in ios/src/mdm.js.
//
// PRODUCTION NOTE: a real deployment also verifies the CMS signature on device
// messages and authenticates the device's TLS identity (SCEP). This implements
// the protocol flow and storage; signature/identity verification is the
// documented hardening step (see ios/README.md).
const express = require('express');
const db = require('../db');
const { parse } = require('../lib/plist-parse');
const ios = require('../lib/ios');

const router = express.Router();
// Capture the raw plist body for every content-type the device may send.
router.use(express.text({ type: () => true, limit: '512kb' }));

function ok(res) { res.set('content-type', 'application/xml'); res.status(200).end(); }

// Enrollment profile download (install on a supervised device).
router.get('/enroll', (req, res) => {
  try { res.set('content-type', 'application/x-apple-aspen-config').send(ios.enrollmentProfile()); }
  catch (e) { res.status(e.status || 500).json({ error: e.message }); }
});

// Check-in: Authenticate / TokenUpdate / CheckOut.
router.put('/checkin', (req, res) => {
  let msg = {};
  try { msg = parse(req.body) || {}; } catch { return res.status(400).end(); }
  const udid = msg.UDID;
  if (!udid) return res.status(400).end();

  switch (msg.MessageType) {
    case 'Authenticate':
      db.prepare(`INSERT INTO ios_devices (udid, topic) VALUES (?, ?)
                  ON CONFLICT(udid) DO UPDATE SET topic=excluded.topic`).run(udid, msg.Topic || null);
      return ok(res);
    case 'TokenUpdate': {
      const token = Buffer.isBuffer(msg.Token) ? msg.Token.toString('hex') : null;
      db.prepare(`INSERT INTO ios_devices (udid, push_token, push_magic, topic, last_seen)
                  VALUES (?, ?, ?, ?, datetime('now'))
                  ON CONFLICT(udid) DO UPDATE SET push_token=excluded.push_token,
                    push_magic=excluded.push_magic, topic=excluded.topic, last_seen=datetime('now')`)
        .run(udid, token, msg.PushMagic || null, msg.Topic || null);
      return ok(res);
    }
    case 'CheckOut':
      db.prepare('DELETE FROM ios_devices WHERE udid = ?').run(udid);
      return ok(res);
    default:
      return ok(res);
  }
});

// Command polling: device reports status; we hand back the next queued command.
router.put('/command', (req, res) => {
  let msg = {};
  try { msg = parse(req.body) || {}; } catch { return res.status(400).end(); }
  const udid = msg.UDID;
  if (!udid) return res.status(400).end();
  db.prepare('UPDATE ios_devices SET last_seen=datetime(\'now\') WHERE udid = ?').run(udid);

  // Record the result of the previous command.
  if (msg.CommandUUID && msg.Status && msg.Status !== 'Idle') {
    db.prepare('UPDATE ios_commands SET status=? WHERE udid=? AND command_uuid=?')
      .run(msg.Status.toLowerCase(), udid, msg.CommandUUID);
    if (msg.QueryResponses) {
      db.prepare('UPDATE ios_devices SET info=? WHERE udid=?').run(JSON.stringify(msg.QueryResponses), udid);
    }
  }
  if (msg.Status === 'NotNow') return ok(res); // device busy; try again later

  // Deliver the next queued command, if any.
  const next = db.prepare("SELECT * FROM ios_commands WHERE udid=? AND status='queued' ORDER BY id LIMIT 1").get(udid);
  if (!next) return ok(res); // empty 200 = no commands
  db.prepare('UPDATE ios_commands SET status=? WHERE id=?').run('sent', next.id);
  res.set('content-type', 'application/xml').status(200).send(next.payload);
});

module.exports = router;

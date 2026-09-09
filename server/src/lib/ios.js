'use strict';
// Dashboard-side iOS/MDM integration: build profiles from stored policies,
// queue MDM commands, and wake devices via APNs. Pure mapping works without any
// Apple credentials; only the APNs wake needs the push cert.
const crypto = require('crypto');
const db = require('../db');
const apns = require('./apns');
const { normalize } = require('./policy');
const profileMap = require('../../../ios/src/profile-map');
const mdm = require('../../../ios/src/mdm');

function serverUrl() { return process.env.MDM_SERVER_URL || null; }
function topic() { return process.env.MDM_TOPIC || null; }

function status() {
  return {
    serverUrl: serverUrl(),
    topic: topic(),
    apnsConfigured: apns.isConfigured(),
    ready: !!(serverUrl() && topic()),          // enough to enroll + serve profiles
    deviceCount: db.prepare('SELECT COUNT(*) c FROM ios_devices').get().c,
  };
}

// The .mobileconfig a supervised device installs to hand management to us.
function enrollmentProfile() {
  if (!serverUrl() || !topic()) { const e = new Error('mdm_not_configured'); e.status = 409; throw e; }
  return mdm.enrollmentProfile({ serverUrl: serverUrl(), topic: topic() });
}

// The policy profile (what actually enforces the rules) for a stored policy.
function policyProfile(policyBody) {
  const p = normalize(policyBody);
  // Only force a global HTTP proxy if a REAL reachable proxy host is configured.
  // Otherwise rely on the built-in web content filter (PermittedURLs /
  // DenyListURLs) — pointing iOS at a dead proxy would break all networking.
  if (p.web?.mode === 'whitelist' && process.env.FILTER_PROXY_HOST) {
    p.forceProxy = true;
    p.web.proxyHost = process.env.FILTER_PROXY_HOST;
  }
  return profileMap.buildProfile(p);
}

// Queue an InstallProfile command for a device and (best-effort) wake it.
async function applyPolicy(udid, policyId) {
  const dev = db.prepare('SELECT * FROM ios_devices WHERE udid = ?').get(udid);
  if (!dev) { const e = new Error('device_not_found'); e.status = 404; throw e; }
  const pol = db.prepare('SELECT * FROM policies WHERE id = ?').get(policyId);
  if (!pol) { const e = new Error('policy_not_found'); e.status = 404; throw e; }
  const xml = policyProfile(pol.body);
  const commandUuid = crypto.randomUUID().toUpperCase();
  const commandXml = mdm.installProfileCommand(xml);
  db.prepare('INSERT INTO ios_commands (udid, command_uuid, request_type, payload) VALUES (?, ?, ?, ?)')
    .run(udid, commandUuid, 'InstallProfile', commandXml);
  db.prepare('UPDATE ios_devices SET policy_id = ? WHERE udid = ?').run(policyId, udid);
  const wake = await apns.push(dev.push_token, dev.push_magic, dev.topic || topic()).catch((e) => ({ sent: false, reason: e.message }));
  return { queued: true, commandUuid, wake };
}

function listDevices() {
  return db.prepare('SELECT udid, push_token IS NOT NULL AS enrolled, policy_id, info, last_seen, enrolled_at FROM ios_devices ORDER BY last_seen DESC').all()
    .map((d) => ({ ...d, info: d.info ? JSON.parse(d.info) : null }));
}

module.exports = { status, enrollmentProfile, policyProfile, applyPolicy, listDevices, serverUrl, topic };

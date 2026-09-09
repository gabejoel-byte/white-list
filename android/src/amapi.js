'use strict';
// Thin client over Google's Android Management API. Requires:
//   * a Google Cloud project with the Android Management API enabled,
//   * a service account JSON key (path in GOOGLE_APPLICATION_CREDENTIALS),
//   * an enterprise created under that project (ENTERPRISE_NAME, e.g.
//     "enterprises/LC0123...").
// See README.md for the one-time setup. Without credentials this module loads
// but its calls will fail — that is expected; the policy mapping (policy-map.js)
// is what runs and is tested offline.
const { mapPolicy } = require('./policy-map');

let google;
try { ({ google } = require('googleapis')); }
catch { /* googleapis not installed yet; run `npm install` in android/ */ }

function client() {
  if (!google) throw new Error('googleapis not installed — run `npm install` in android/');
  const auth = new google.auth.GoogleAuth({
    scopes: ['https://www.googleapis.com/auth/androidmanagement'],
  });
  return google.androidmanagement({ version: 'v1', auth });
}

const ENTERPRISE = () => {
  const e = process.env.ENTERPRISE_NAME;
  if (!e) throw new Error('set ENTERPRISE_NAME (e.g. enterprises/LC0...)');
  return e;
};

// Push a Whitelist Cloud policy under a given name (e.g. "lockdown").
async function applyPolicy(policyId, whitelistPolicy) {
  const am = client();
  const name = `${ENTERPRISE()}/policies/${policyId}`;
  const body = mapPolicy(whitelistPolicy);
  const res = await am.enterprises.policies.patch({ name, requestBody: body });
  return res.data;
}

// Create an enrollment token that binds a newly-provisioned device to a policy.
// The token's value is what you turn into the enrollment QR code.
async function createEnrollmentToken(policyId, { oneTime = false, durationSeconds = 3600 } = {}) {
  const am = client();
  const res = await am.enterprises.enrollmentTokens.create({
    parent: ENTERPRISE(),
    requestBody: {
      policyName: `${ENTERPRISE()}/policies/${policyId}`,
      oneTimeOnly: oneTime,
      duration: `${durationSeconds}s`,
    },
  });
  return res.data; // { value, qrCode, ... }
}

async function listDevices() {
  const am = client();
  const res = await am.enterprises.devices.list({ parent: ENTERPRISE() });
  return res.data.devices || [];
}

// Issue a device command: LOCK, REBOOT, RESET_PASSWORD, RELINQUISH_OWNERSHIP, etc.
async function deviceCommand(deviceName, type) {
  const am = client();
  const res = await am.enterprises.devices.issueCommand({ name: deviceName, requestBody: { type } });
  return res.data;
}

module.exports = { applyPolicy, createEnrollmentToken, listDevices, deviceCommand };

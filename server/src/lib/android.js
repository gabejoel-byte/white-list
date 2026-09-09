'use strict';
// Dashboard-side Android Management API integration. Degrades gracefully: the
// policy → AMAPI mapping always works (pure), while anything that talks to
// Google is gated behind isConfigured() so the dashboard is usable without a
// GCP project wired up.
const { mapPolicy } = require('../../../android/src/policy-map');
const { normalize } = require('./policy');

let amapi = null;
try { amapi = require('../../../android/src/amapi'); } catch { amapi = null; }

function isConfigured() {
  return !!(process.env.GOOGLE_APPLICATION_CREDENTIALS && process.env.ENTERPRISE_NAME && amapi);
}

function status() {
  return {
    configured: isConfigured(),
    enterprise: process.env.ENTERPRISE_NAME || null,
    hasCredentials: !!process.env.GOOGLE_APPLICATION_CREDENTIALS,
    sdkLoaded: !!amapi,
  };
}

// Map a stored policy row's body → AMAPI Policy resource (pure, no network).
function preview(policyBody) {
  return mapPolicy(normalize(policyBody));
}

async function pushPolicy(policyId, policyBody) {
  if (!isConfigured()) { const e = new Error('android_not_configured'); e.status = 409; throw e; }
  return amapi.applyPolicy(policyId, normalize(policyBody));
}

async function createEnrollmentToken(policyId, opts) {
  if (!isConfigured()) { const e = new Error('android_not_configured'); e.status = 409; throw e; }
  return amapi.createEnrollmentToken(policyId, opts);
}

async function listDevices() {
  if (!isConfigured()) return [];
  return amapi.listDevices();
}

module.exports = { isConfigured, status, preview, pushPolicy, createEnrollmentToken, listDevices };

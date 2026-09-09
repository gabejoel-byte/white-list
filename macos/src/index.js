#!/usr/bin/env node
'use strict';
// Whitelist Agent for macOS. Mirrors the Windows agent: enrolls, heartbeats,
// enforces the cloud policy continuously, fails closed on the last-known policy.
const os = require('os');
const cfgStore = require('./lib/config');
const { log, setDryRun, setLive, isDryRun } = require('./lib/util');
const { makeClient } = require('../../core/api');
const apps = require('./enforce/apps');
const web = require('./enforce/web');
const vpn = require('./enforce/vpn');

const AGENT_VERSION = require('../package.json').version;

let cfg = cfgStore.load();
if (!cfg.serverUrl || !cfg.enrollmentKey) {
  try {
    const b = JSON.parse(require('fs').readFileSync(require('path').join(__dirname, '..', 'baked-config.json'), 'utf8'));
    cfg.serverUrl = cfg.serverUrl || b.serverUrl;
    cfg.enrollmentKey = cfg.enrollmentKey || b.enrollmentKey;
  } catch { /* none baked */ }
}
if (process.env.WL_SERVER) cfg.serverUrl = process.env.WL_SERVER;
if (process.env.WL_ENROLL_KEY) cfg.enrollmentKey = process.env.WL_ENROLL_KEY;
if (process.env.WL_DRY_RUN === '1') setDryRun(true); else setLive();
cfgStore.save(cfg);

if (!cfg.serverUrl) { log('FATAL: no serverUrl configured'); process.exit(1); }
const client = makeClient(cfg.serverUrl);

let policy = cfgStore.loadPolicy();
let policyVersion = policy?.version || 0;
const pendingEvents = [];
function emit(kind, detail) {
  pendingEvents.push({ kind, detail: typeof detail === 'string' ? detail : JSON.stringify(detail), at: new Date().toISOString() });
  if (pendingEvents.length > 200) pendingEvents.splice(0, pendingEvents.length - 200);
}
web.onBlock((h) => emit('web_block', h));

async function ensureEnrolled() {
  if (cfg.deviceToken) return true;
  if (!cfg.enrollmentKey) { log('no token and no enrollment key'); return false; }
  try {
    const r = await client.enroll({ enrollmentKey: cfg.enrollmentKey, hostname: os.hostname(), os: `darwin ${os.release()}`, machineId: cfgStore.machineId(cfg) });
    cfg.deviceToken = r.deviceToken; cfg.deviceId = r.deviceId; cfgStore.save(cfg);
    log('enrolled as device', r.deviceId); return true;
  } catch (e) { log('enroll failed:', e.message); return false; }
}

async function applyPolicy(p) {
  log('applying policy v' + p.version, 'level', p.level);
  await web.apply(p.web);
  await vpn.apply(p.vpn);
  if (p.apps?.mode !== 'off') await apps.applyDurable(p.apps).catch((e) => log('durable:', e.message));
  policy = p; policyVersion = p.version; cfgStore.savePolicy(p);
  emit('policy_applied', { version: p.version, level: p.level });
}

async function heartbeat() {
  if (!(await ensureEnrolled())) return;
  try {
    const events = pendingEvents.splice(0, pendingEvents.length);
    const r = await client.heartbeat(cfg.deviceToken, {
      policyVersion, agentVersion: AGENT_VERSION,
      status: { level: policy?.level, hostname: os.hostname(), platform: 'darwin', uptime: Math.round(process.uptime()) },
      events,
    });
    if (r.policy && r.policy.version > policyVersion) { await applyPolicy(r.policy); setTimeout(heartbeat, 1500); }
  } catch (e) {
    if (e.status === 401) { log('token rejected — clearing'); delete cfg.deviceToken; cfgStore.save(cfg); }
    else log('heartbeat failed (keeping last policy):', e.message);
  }
}

async function enforceTick() {
  if (!policy) return;
  try {
    if (policy.apps?.mode && policy.apps.mode !== 'off') { const k = await apps.sweep(policy.apps); if (k.length) emit('app_block', k.join(',')); }
    if (policy.vpn?.block) { const k = await vpn.killVpnProcesses(); if (k.length) emit('vpn_block', k.join(',')); }
    if (policy.web?.mode === 'whitelist') await web.reassertSystemProxy();
  } catch (e) { log('enforce tick error:', e.message); }
}

async function main() {
  log(`whitelist-agent (macOS) v${AGENT_VERSION} starting dryRun=${isDryRun()} server=${cfg.serverUrl}`);
  if (policy) { log('restoring last-known policy v' + policy.version); await applyPolicy(policy).catch((e) => log(e.message)); }
  await heartbeat();
  setInterval(heartbeat, (policy?.heartbeatSeconds || 30) * 1000);
  setInterval(enforceTick, policy?.apps?.killIntervalMs || 3000);
}
process.on('uncaughtException', (e) => log('uncaught:', e.message));
process.on('unhandledRejection', (e) => log('unhandledRejection:', String(e)));
main();

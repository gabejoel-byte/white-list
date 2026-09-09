#!/usr/bin/env node
'use strict';
// Whitelist Agent — endpoint enforcement daemon.
// Enrolls with the cloud, pulls its policy, and enforces it continuously.
// Fails closed: if the server is unreachable the last-known policy stays active.
const os = require('os');
const cfgStore = require('./lib/config');
const { makeClient } = require('./lib/api');
const { log, setDryRun, setLive, isDryRun } = require('./lib/util');
const apps = require('./enforce/apps');
const web = require('./enforce/web');
const vpn = require('./enforce/vpn');
const tamper = require('./enforce/tamper');

const AGENT_VERSION = require('./../package.json').version;

let cfg = cfgStore.load();
// Fall back to a config baked into the package at build time (server URL +
// enrollment key), so a turn-key package enrolls with zero configuration.
if (!cfg.serverUrl || !cfg.enrollmentKey) {
  try {
    const baked = require('path').join(__dirname, '..', 'baked-config.json');
    const b = JSON.parse(require('fs').readFileSync(baked, 'utf8'));
    cfg.serverUrl = cfg.serverUrl || b.serverUrl;
    cfg.enrollmentKey = cfg.enrollmentKey || b.enrollmentKey;
  } catch { /* none baked */ }
}
if (process.env.WL_SERVER) cfg.serverUrl = process.env.WL_SERVER;
if (process.env.WL_ENROLL_KEY) cfg.enrollmentKey = process.env.WL_ENROLL_KEY;
// Running the daemon is an explicit intent to enforce, so it opts into live
// mode — unless WL_DRY_RUN=1 was set, which wins. Any other entry point
// (ad-hoc scripts, tests) that never chooses a mode hits the run() guard.
if (process.env.WL_DRY_RUN === '1') setDryRun(true); else setLive();
cfgStore.save(cfg);

if (!cfg.serverUrl) { log('FATAL: no serverUrl configured (set WL_SERVER or config.json)'); process.exit(1); }
const client = makeClient(cfg.serverUrl);

let policy = cfgStore.loadPolicy();      // last applied policy (fail-closed)
let policyVersion = policy?.version || 0;
const pendingEvents = [];

function emit(kind, detail) {
  pendingEvents.push({ kind, detail: typeof detail === 'string' ? detail : JSON.stringify(detail), at: new Date().toISOString() });
  if (pendingEvents.length > 200) pendingEvents.splice(0, pendingEvents.length - 200);
}
web.onBlock((host) => emit('web_block', host));

async function ensureEnrolled() {
  if (cfg.deviceToken) return true;
  if (!cfg.enrollmentKey) { log('no deviceToken and no enrollmentKey — cannot enroll'); return false; }
  try {
    const r = await client.enroll({
      enrollmentKey: cfg.enrollmentKey,
      hostname: os.hostname(),
      os: `${process.platform} ${os.release()}`,
      machineId: cfgStore.machineId(cfg),
    });
    cfg.deviceToken = r.deviceToken; cfg.deviceId = r.deviceId; cfgStore.save(cfg);
    log('enrolled as device', r.deviceId);
    return true;
  } catch (e) { log('enroll failed:', e.message); return false; }
}

async function applyPolicy(p) {
  log('applying policy v' + p.version, 'level', p.level);
  await web.apply(p.web);
  await vpn.apply(p.vpn, { dnsResolver: p.web?.dnsResolver });
  if (p.apps?.mode !== 'off') await apps.applyDurable(p.apps).catch((e) => log('durable apps:', e.message));
  if (p.tamper?.preventUninstall) await tamper.hardenService().catch(() => {});
  policy = p; policyVersion = p.version;
  cfgStore.savePolicy(p);
  emit('policy_applied', { version: p.version, level: p.level });
}

async function handleCommands(commands) {
  for (const c of commands || []) {
    log('command:', c.type);
    if (c.type === 'unlock') { tamper.unlockFromServer(c.payload?.minutes || 15); emit('unlock', 'server'); }
    else if (c.type === 'refresh') { policyVersion = 0; }
    else if (c.type === 'uninstall') { tamper.authorizeUninstall(); emit('uninstall_authorized', 'server'); }
    else if (c.type === 'reenroll') { delete cfg.deviceToken; cfgStore.save(cfg); }
  }
}

// Slow loop: talk to the server, pull policy + commands.
async function heartbeat() {
  if (!(await ensureEnrolled())) return;
  try {
    const events = pendingEvents.splice(0, pendingEvents.length);
    const r = await client.heartbeat(cfg.deviceToken, {
      policyVersion,
      agentVersion: AGENT_VERSION,
      status: {
        level: policy?.level, unlockActive: tamper.unlockActive(),
        hostname: os.hostname(), uptime: Math.round(process.uptime()),
      },
      events,
    });
    await handleCommands(r.commands);
    if (r.policy && r.policy.version > policyVersion) {
      await applyPolicy(r.policy);
      // Ack the new version promptly so the dashboard shows "synced" fast,
      // instead of waiting a full heartbeat interval.
      setTimeout(heartbeat, 1500);
    }
  } catch (e) {
    if (e.status === 401) { log('token rejected — clearing for re-enroll'); delete cfg.deviceToken; cfgStore.save(cfg); }
    else log('heartbeat failed (keeping last policy):', e.message);
  }
}

// Fast loop: continuous enforcement of whatever policy is currently active.
async function enforceTick() {
  if (!policy || tamper.unlockActive()) return;
  try {
    if (policy.apps?.mode && policy.apps.mode !== 'off') {
      const killed = await apps.sweep(policy.apps);
      if (killed.length) emit('app_block', killed.join(','));
    }
    if (policy.vpn?.block) {
      const k = await vpn.killVpnProcesses();
      if (k.length) emit('vpn_block', k.join(','));
    }
    // Re-assert the system proxy so a user toggling it off is corrected fast.
    if (policy.web?.mode === 'whitelist') await web.reassertSystemProxy();
  } catch (e) { log('enforce tick error:', e.message); }
}

async function main() {
  log(`whitelist-agent v${AGENT_VERSION} starting (dryRun=${isDryRun()}) server=${cfg.serverUrl}`);
  if (policy) { log('restoring last-known policy v' + policy.version); await applyPolicy(policy).catch((e) => log(e.message)); }

  await heartbeat();
  const hbMs = (policy?.heartbeatSeconds || 30) * 1000;
  setInterval(heartbeat, hbMs);

  const fastMs = policy?.apps?.killIntervalMs || 3000;
  setInterval(enforceTick, fastMs);
}

process.on('uncaughtException', (e) => log('uncaught:', e.message));
process.on('unhandledRejection', (e) => log('unhandledRejection:', String(e)));
main();

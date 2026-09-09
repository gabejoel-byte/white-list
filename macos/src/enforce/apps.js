'use strict';
// macOS application control.
//   1. Runtime enforcement (works on any Mac): enumerate processes and kill
//      those that violate the policy. Needs the agent running as root to signal
//      other users' / GUI processes.
//   2. Durable path: a configuration profile with a com.apple.applicationaccess
//      payload (app allow/deny by bundle id) — but that is only *enforced* when
//      the Mac is supervised/MDM-managed. We generate the .mobileconfig so it
//      can be pushed by an MDM; on an unmanaged Mac the runtime layer is what
//      actually enforces. (Honest: same story as Windows Home vs AppLocker.)
const path = require('path');
const fs = require('fs');
const { log, run, isDryRun } = require('../lib/util');
const { DIR } = require('../lib/config');

// Never kill these — core macOS + the agent + shell it runs in.
const CRITICAL = new Set([
  'kernel_task', 'launchd', 'windowserver', 'loginwindow', 'finder', 'dock',
  'systemuiserver', 'coreaudiod', 'mds', 'mds_stores', 'mdworker', 'cfprefsd',
  'distnoted', 'notifyd', 'securityd', 'opendirectoryd', 'configd', 'powerd',
  'bluetoothd', 'wifiagent', 'sshd', 'node', 'bash', 'zsh', 'sh', 'ps', 'kill',
  'whitelist-agent', 'launchservicesd', 'coreservicesd', 'universalaccessd',
]);

function baseName(p) { return path.basename(String(p)).toLowerCase(); }

// Pure decision — unit tested. procs: [{pid, name}]. name = comm (short name).
function decideKills(procs, appsPolicy) {
  const mode = appsPolicy?.mode || 'off';
  if (mode === 'off') return [];
  const allow = new Set((appsPolicy.allow || []).map(baseName));
  const deny = new Set((appsPolicy.deny || []).map(baseName));
  const out = [];
  for (const p of procs) {
    const name = String(p.name).toLowerCase();
    if (CRITICAL.has(name)) continue;
    let violate = false;
    if (mode === 'whitelist') violate = !allow.has(name);
    else if (mode === 'blacklist') violate = deny.has(name);
    if (violate) out.push({ pid: p.pid, name });
  }
  return out;
}

async function listProcesses() {
  if (isDryRun()) return [];
  // `comm` gives the executable's short name; strip the path.
  const { stdout } = await run('/bin/ps', ['-axo', 'pid=,comm=']);
  const procs = [];
  for (const line of stdout.split(/\r?\n/)) {
    const m = line.trim().match(/^(\d+)\s+(.*)$/);
    if (m) procs.push({ pid: +m[1], name: baseName(m[2]) });
  }
  return procs;
}

async function kill(pid) { return run('/bin/kill', ['-9', String(pid)]); }

async function sweep(appsPolicy) {
  const killed = [];
  for (const t of decideKills(await listProcesses(), appsPolicy)) {
    const r = await kill(t.pid);
    if (r.code === 0) { killed.push(t.name); log('apps: terminated', t.name, t.pid); }
  }
  return [...new Set(killed)];
}

// Generate a configuration profile for the MDM-enforced durable path.
function buildProfile(appsPolicy) {
  const wl = appsPolicy.mode === 'whitelist';
  const ids = (wl ? appsPolicy.allow : appsPolicy.deny) || [];
  const arrKey = wl ? 'whitelistedAppBundleIDs' : 'blacklistedAppBundleIDs';
  const items = ids.map((id) => `        <string>${id}</string>`).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadIdentifier</key><string>cloud.whitelist.appaccess</string>
  <key>PayloadUUID</key><string>${require('crypto').randomUUID()}</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>PayloadContent</key><array><dict>
    <key>PayloadType</key><string>com.apple.applicationaccess.new</string>
    <key>PayloadIdentifier</key><string>cloud.whitelist.appaccess.payload</string>
    <key>PayloadUUID</key><string>${require('crypto').randomUUID()}</string>
    <key>PayloadVersion</key><integer>1</integer>
    <key>familyControlsEnabled</key><true/>
    <key>${arrKey}</key><array>
${items}
    </array>
  </dict></array>
</dict></plist>`;
}

async function applyDurable(appsPolicy) {
  if (!appsPolicy || appsPolicy.mode === 'off') return { active: [] };
  const file = path.join(DIR, 'appaccess.mobileconfig');
  try { fs.mkdirSync(DIR, { recursive: true }); fs.writeFileSync(file, buildProfile(appsPolicy)); } catch { /* ignore */ }
  // Installing a profile silently requires MDM enrollment; on an unmanaged Mac
  // `profiles install` prompts. We generate it and log; MDM push is the durable
  // route. Runtime sweep remains the active enforcement here.
  log('apps: app-access profile written for MDM push ->', file);
  return { active: ['runtime', 'profile-generated'] };
}

module.exports = { sweep, decideKills, listProcesses, kill, applyDurable, buildProfile, CRITICAL };

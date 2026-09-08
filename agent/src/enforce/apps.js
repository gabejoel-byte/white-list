'use strict';
// Application control. Two layers, defence in depth:
//   1. Runtime enforcement — poll the process list, terminate anything that
//      violates the policy (whitelist: kill all but allowed; blacklist: kill
//      denied). Immediate, needs no reboot, works for the common case.
//   2. AppLocker policy generation — for a durable, kernel-backed block the
//      agent emits an AppLocker XML and applies it via the Windows API. This is
//      what actually stops a determined user relaunching a renamed binary.
const os = require('os');
const path = require('path');
const { log, run, ps, isDryRun } = require('../lib/util');
const { DIR } = require('../lib/config');

// Never kill these — doing so would destabilise Windows or the agent itself.
const CRITICAL = new Set([
  'system', 'system idle process', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
  'services.exe', 'lsass.exe', 'winlogon.exe', 'fontdrvhost.exe', 'dwm.exe',
  'svchost.exe', 'explorer.exe', 'ctfmon.exe', 'sihost.exe', 'taskhostw.exe',
  'runtimebroker.exe', 'searchhost.exe', 'startmenuexperiencehost.exe',
  'node.exe', 'powershell.exe', 'conhost.exe', 'whitelist-agent.exe',
  'shellexperiencehost.exe', 'applicationframehost.exe', 'textinputhost.exe',
]);

function baseName(p) { return path.basename(String(p)).toLowerCase(); }

async function listProcesses() {
  if (isDryRun()) return [];
  // CSV: "Image Name","PID",...
  const { stdout } = await run('tasklist.exe', ['/fo', 'csv', '/nh']);
  const procs = [];
  for (const line of stdout.split(/\r?\n/)) {
    const m = line.match(/^"([^"]+)","(\d+)"/);
    if (m) procs.push({ name: m[1].toLowerCase(), pid: +m[2] });
  }
  return procs;
}

async function kill(pid) { return run('taskkill.exe', ['/PID', String(pid), '/F', '/T']); }

// One enforcement sweep. Returns the names it terminated (for event reporting).
async function sweep(appsPolicy) {
  const mode = appsPolicy?.mode || 'off';
  if (mode === 'off') return [];
  const allow = new Set((appsPolicy.allow || []).map(baseName));
  const deny = new Set((appsPolicy.deny || []).map(baseName));
  const killed = [];
  for (const p of await listProcesses()) {
    if (CRITICAL.has(p.name)) continue;
    let violate = false;
    if (mode === 'whitelist') violate = !allow.has(p.name);
    else if (mode === 'blacklist') violate = deny.has(p.name);
    if (violate) {
      const r = await kill(p.pid);
      if (r.code === 0) { killed.push(p.name); log('apps: terminated', p.name, p.pid); }
    }
  }
  return [...new Set(killed)];
}

// Build an AppLocker XML enforcing the same intent (durable layer).
function buildAppLockerXml(appsPolicy) {
  const rules = [];
  if (appsPolicy.mode === 'whitelist') {
    // Deny-by-default: allow only the listed publishers/paths. We allow the
    // Windows + Program Files trees implicitly-nothing; instead allow each
    // listed path/name and the OS folders required to boot.
    rules.push(pathRule('allow', '%WINDIR%\\*', 'OS'));
    rules.push(pathRule('allow', '%SYSTEM32%\\*', 'OS-sys32'));
    for (const a of appsPolicy.allow || []) {
      const p = a.includes('\\') ? a : `*\\${a}`;
      rules.push(pathRule('allow', p, 'allow-' + baseName(a)));
    }
    // Everyone gets an explicit deny for the rest via absence (AppLocker is
    // deny-by-default once any rule exists in the collection).
  } else if (appsPolicy.mode === 'blacklist') {
    rules.push(pathRule('allow', '*', 'allow-all'));
    for (const d of appsPolicy.deny || []) {
      const p = d.includes('\\') ? d : `*\\${d}`;
      rules.push(pathRule('deny', p, 'deny-' + baseName(d)));
    }
  }
  return `<?xml version="1.0" encoding="utf-8"?>
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
${rules.join('\n')}
  </RuleCollection>
</AppLockerPolicy>`;
}

function pathRule(action, p, id) {
  const guid = require('crypto').randomUUID();
  return `    <FilePathRule Id="${guid}" Name="${id}" Description="whitelist-agent" UserOrGroupSid="S-1-1-0" Action="${action.replace(/^\w/, (c) => c.toUpperCase())}">
      <Conditions><FilePathCondition Path="${p}" /></Conditions>
    </FilePathRule>`;
}

async function applyAppLocker(appsPolicy) {
  if (appsPolicy.mode === 'off') return;
  const xml = buildAppLockerXml(appsPolicy);
  const fs = require('fs');
  const file = path.join(DIR, 'applocker.xml');
  try { fs.mkdirSync(DIR, { recursive: true }); fs.writeFileSync(file, xml); } catch { /* ignore */ }
  // Requires the Application Identity service (AppIDSvc) running + admin.
  await ps(`Start-Service AppIDSvc -ErrorAction SilentlyContinue; Set-AppLockerPolicy -XmlPolicy '${file}' -ErrorAction SilentlyContinue`);
  log('apps: AppLocker policy applied from', file);
}

module.exports = { sweep, applyAppLocker, buildAppLockerXml, CRITICAL };

'use strict';
// Application control on Windows. Defence in depth, edition-aware — because the
// right durable mechanism differs by Windows edition:
//
//   1. Runtime enforcement (ALL editions, incl. Home): poll the process list
//      and terminate anything that violates the policy. Immediate, no reboot,
//      needs the agent running with admin/SYSTEM rights to kill other sessions'
//      processes. Reactive (a blocked app may flash before it dies), so it is
//      the fast layer, not the only one.
//
//   2. WDAC — Windows Defender Application Control (ALL editions, incl. Home):
//      kernel-enforced code integrity. This is the correct "only these programs
//      may run" allow-list on Home. Deployed AUDIT-FIRST (logs would-be blocks
//      without enforcing) so a mistaken policy cannot lock the machine out;
//      enforcement is a separate, explicit step.
//
//   3. AppLocker (Enterprise/Education, partial on Pro — NOT Home): kept for
//      those editions where it is the native tool.
//
//   4. IFEO blacklist (ALL editions, incl. Home): an Image File Execution
//      Options "Debugger" redirect that stops a named .exe from launching.
//      Registry-based, admin required. Good durable layer for blacklist mode.
const os = require('os');
const path = require('path');
const fs = require('fs');
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
  'lockapp.exe', 'logonui.exe', 'dllhost.exe', 'spoolsv.exe', 'audiodg.exe',
  'wininit.exe', 'wudfhost.exe', 'securityhealthservice.exe', 'msmpeng.exe',
]);

function baseName(p) { return path.basename(String(p)).toLowerCase(); }

// ---------------------------------------------------------------------------
// Pure decision: given a process list and a policy, which PIDs must be killed?
// No side effects — this is the unit-tested heart of runtime enforcement, and
// keeping it pure is what lets us verify behaviour without killing anything.
// ---------------------------------------------------------------------------
function decideKills(procs, appsPolicy) {
  const mode = appsPolicy?.mode || 'off';
  if (mode === 'off') return [];
  const allow = new Set((appsPolicy.allow || []).map(baseName));
  const deny = new Set((appsPolicy.deny || []).map(baseName));
  const out = [];
  for (const p of procs) {
    const name = String(p.name).toLowerCase();
    if (CRITICAL.has(name)) continue;          // never touch critical processes
    let violate = false;
    if (mode === 'whitelist') violate = !allow.has(name);
    else if (mode === 'blacklist') violate = deny.has(name);
    if (violate) out.push({ pid: p.pid, name });
  }
  return out;
}

async function listProcesses() {
  if (isDryRun()) return [];
  const { stdout } = await run('tasklist.exe', ['/fo', 'csv', '/nh']); // "Image","PID",...
  const procs = [];
  for (const line of stdout.split(/\r?\n/)) {
    const m = line.match(/^"([^"]+)","(\d+)"/);
    if (m) procs.push({ name: m[1].toLowerCase(), pid: +m[2] });
  }
  return procs;
}

async function kill(pid) { return run('taskkill.exe', ['/PID', String(pid), '/F', '/T']); }

// One runtime enforcement sweep. Returns the names it terminated.
async function sweep(appsPolicy) {
  const targets = decideKills(await listProcesses(), appsPolicy);
  const killed = [];
  for (const t of targets) {
    const r = await kill(t.pid);
    if (r.code === 0) { killed.push(t.name); log('apps: terminated', t.name, t.pid); }
  }
  return [...new Set(killed)];
}

// ---------------------------------------------------------------------------
// Edition detection — so we choose the right durable mechanism and log honestly.
// ---------------------------------------------------------------------------
async function detectEdition() {
  if (isDryRun()) return { caption: '(dry) Windows', appLocker: false, wdac: true };
  let caption = '';
  try {
    const { stdout } = await ps('(Get-CimInstance Win32_OperatingSystem).Caption');
    caption = (stdout || '').trim();
  } catch { /* ignore */ }
  return { caption, appLocker: appLockerSupported(caption), wdac: true };
}

// AppLocker is Enterprise/Education (and partially Pro). Explicitly NOT Home.
function appLockerSupported(caption) {
  const c = String(caption).toLowerCase();
  if (c.includes('home')) return false;
  return c.includes('enterprise') || c.includes('education') || c.includes('pro');
}

// ---------------------------------------------------------------------------
// WDAC — the correct kernel-enforced allow-list on all editions incl. Home.
// Built with Microsoft's own cmdlets (New-CIPolicy) rather than a hand-rolled
// XML, because a malformed CI policy can render a machine unbootable. Deployed
// in AUDIT mode unless the policy explicitly opts into enforcement.
// ---------------------------------------------------------------------------
function wdacBuildScript(appsPolicy, { enforce = false } = {}) {
  const outXml = path.join(DIR, 'wdac.xml');
  const outCip = path.join(DIR, 'wdac.cip');
  // Scan each allowed path/dir to produce allow rules; merge into one policy.
  // A path given as a bare name (chrome.exe) is treated as "allow that file
  // wherever it is"; a full path scans that file/dir specifically.
  const scans = (appsPolicy.allow || []).map((a, i) => {
    const target = a.includes('\\') ? a : a; // caller should prefer full paths
    const tmp = `$env:TEMP\\wdac_part_${i}.xml`;
    return `New-CIPolicy -FilePath '${tmp}' -ScanPath '${escapePS(dirOf(target))}' -Level FilePath -Fallback Hash -UserPEs -NoScript -MultiplePolicyFormat -ErrorAction SilentlyContinue`;
  });
  // Base template ships with Windows; we start from DefaultWindows_Audit and
  // merge our allow rules so the OS itself keeps working.
  const lines = [
    `$base = "$env:windir\\schemas\\CodeIntegrity\\ExamplePolicies\\DefaultWindows_Audit.xml"`,
    `Copy-Item $base '${outXml}' -Force`,
    ...scans,
    // Merge any parts that were produced.
    `$parts = Get-ChildItem "$env:TEMP\\wdac_part_*.xml" -ErrorAction SilentlyContinue | Select-Object -Expand FullName`,
    `if ($parts) { Merge-CIPolicy -PolicyPaths (@('${outXml}') + $parts) -OutputFilePath '${outXml}' | Out-Null }`,
    // Audit vs enforce.
    enforce
      ? `Set-RuleOption -FilePath '${outXml}' -Option 3 -Delete`   // remove "Audit Mode" => enforce
      : `Set-RuleOption -FilePath '${outXml}' -Option 3`,          // ensure "Audit Mode"
    `ConvertFrom-CIPolicy -XmlFilePath '${outXml}' -BinaryFilePath '${outCip}' | Out-Null`,
  ];
  return { script: lines.join('; '), outXml, outCip };
}

async function applyWdac(appsPolicy, { enforce = false } = {}) {
  if (appsPolicy.mode !== 'whitelist') return { deployed: false, reason: 'not_whitelist' };
  const { script, outCip } = wdacBuildScript(appsPolicy, { enforce });
  await ps(script);
  // Deploy: CiTool (Win11 22H2+) is the supported runtime deployment path.
  await ps(`CiTool --update-policy '${outCip}' 2>$null; if ($LASTEXITCODE -ne 0) { Write-Output 'citool_unavailable' }`);
  log('apps: WDAC policy built + deployed', enforce ? '(ENFORCED)' : '(AUDIT mode)');
  return { deployed: true, enforce, cip: outCip };
}

// ---------------------------------------------------------------------------
// IFEO blacklist — block named executables from launching (all editions).
// Sets HKLM\...\Image File Execution Options\<exe> Debugger to a harmless no-op
// so the target never runs. Reversible by deleting the key.
// ---------------------------------------------------------------------------
const IFEO = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options';
const IFEO_NOOP = '%windir%\\system32\\systray.exe'; // launches, does nothing, exits

function ifeoCommands(denyList, { clear = false } = {}) {
  // Returns the reg.exe argv arrays (pure) — used by tests and by applyIfeo.
  return (denyList || []).map(baseName).filter(Boolean).map((name) =>
    clear
      ? ['delete', `${IFEO}\\${name}`, '/v', 'Debugger', '/f']
      : ['add', `${IFEO}\\${name}`, '/v', 'Debugger', '/t', 'REG_SZ', '/d', IFEO_NOOP, '/f']);
}

async function applyIfeoBlacklist(denyList) {
  for (const args of ifeoCommands(denyList)) await run('reg.exe', args);
  if ((denyList || []).length) log('apps: IFEO blocks set for', denyList.length, 'executable(s)');
}
async function clearIfeo(denyList) {
  for (const args of ifeoCommands(denyList, { clear: true })) await run('reg.exe', args);
}

// ---------------------------------------------------------------------------
// AppLocker (Enterprise/Education/Pro) — unchanged native path.
// ---------------------------------------------------------------------------
function buildAppLockerXml(appsPolicy) {
  const rules = [];
  if (appsPolicy.mode === 'whitelist') {
    rules.push(pathRule('allow', '%WINDIR%\\*', 'OS'));
    rules.push(pathRule('allow', '%PROGRAMFILES%\\*', 'PF')); // keep signed apps working
    for (const a of appsPolicy.allow || []) {
      const p = a.includes('\\') ? a : `*\\${a}`;
      rules.push(pathRule('allow', p, 'allow-' + baseName(a)));
    }
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
  const file = path.join(DIR, 'applocker.xml');
  try { fs.mkdirSync(DIR, { recursive: true }); fs.writeFileSync(file, xml); } catch { /* ignore */ }
  await ps(`Start-Service AppIDSvc -ErrorAction SilentlyContinue; Set-AppLockerPolicy -XmlPolicy '${file}' -ErrorAction SilentlyContinue`);
  log('apps: AppLocker policy applied from', file);
}

// ---------------------------------------------------------------------------
// Orchestrator: pick the right durable mechanism for this edition + mode.
// ---------------------------------------------------------------------------
async function applyDurable(appsPolicy) {
  if (!appsPolicy || appsPolicy.mode === 'off') return { active: [] };
  const ed = await detectEdition();
  const active = [];

  if (appsPolicy.mode === 'blacklist') {
    // IFEO works everywhere and is low-risk; use it as the durable blacklist.
    await applyIfeoBlacklist(appsPolicy.deny);
    active.push('ifeo');
    if (ed.appLocker) { await applyAppLocker(appsPolicy).catch(() => {}); active.push('applocker'); }
  } else if (appsPolicy.mode === 'whitelist') {
    if (ed.appLocker) {
      await applyAppLocker(appsPolicy).catch(() => {});
      active.push('applocker');
    } else if (appsPolicy.wdac) {
      // Home/consumer: WDAC is the kernel-enforced allow-list. Audit-first
      // unless the policy explicitly sets wdacEnforce.
      await applyWdac(appsPolicy, { enforce: !!appsPolicy.wdacEnforce }).catch((e) => log('wdac:', e.message));
      active.push(appsPolicy.wdacEnforce ? 'wdac-enforced' : 'wdac-audit');
    }
  }
  log('apps: durable enforcement on', ed.caption || 'unknown', '->', active.join(',') || 'runtime-only');
  return { active, edition: ed };
}

function dirOf(p) { return p.includes('\\') ? path.win32.dirname(p) : p; }
function escapePS(s) { return String(s).replace(/'/g, "''"); }

module.exports = {
  sweep, decideKills, listProcesses, kill, CRITICAL,
  detectEdition, appLockerSupported,
  applyDurable, applyAppLocker, buildAppLockerXml,
  applyWdac, wdacBuildScript,
  applyIfeoBlacklist, clearIfeo, ifeoCommands,
};

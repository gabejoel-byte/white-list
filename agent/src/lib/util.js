'use strict';
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { DIR } = require('./config');

const LOG = path.join(DIR, 'agent.log');

// Execution mode is an explicit, deliberate choice — never a silent default.
//   'dry'   : system-mutating commands are logged, not executed (dev/testing).
//   'live'  : commands actually run (the real agent sets this at startup).
//   'unset' : neither was chosen -> run() THROWS. This is the guard that stops
//             an ad-hoc `node -e ...` or a test that forgot the flag from
//             quietly changing the machine (which is exactly how an earlier
//             proxy test once left a dead system proxy behind).
let MODE = process.env.WL_DRY_RUN === '1' ? 'dry'
  : process.env.WL_LIVE === '1' ? 'live'
    : 'unset';

function setDryRun(v) { if (v) MODE = 'dry'; }
function setLive() { if (MODE !== 'dry') MODE = 'live'; }
function setMode(m) { MODE = m; }         // tests use this to reset to 'unset'
function isDryRun() { return MODE === 'dry'; }
function getMode() { return MODE; }

function log(...args) {
  const line = `[${new Date().toISOString()}] ${args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')}`;
  console.log(line);
  try { fs.mkdirSync(DIR, { recursive: true }); fs.appendFileSync(LOG, line + '\n'); } catch { /* ignore */ }
}

// Throw unless an execution mode was explicitly chosen. Any code path that is
// about to mutate the system — whether via run() or by writing a file directly
// (e.g. the hosts file) — calls this first, so a forgotten flag fails loudly.
function requireMode(what = 'this operation') {
  if (MODE === 'unset') {
    throw new Error(
      `refusing ${what}: no execution mode set. ` +
      `Set WL_DRY_RUN=1 (log only) or WL_LIVE=1 (really run), ` +
      `or call setDryRun(true)/setLive() first. This guard prevents ad-hoc ` +
      `scripts and tests from mutating the system by accident.`
    );
  }
}

// Run a binary. Refuses unless an execution mode was explicitly chosen; in
// 'dry' mode logs the command instead of executing it.
function run(cmd, args = [], { ignoreError = true } = {}) {
  requireMode(`to execute "${cmd}"`);
  return new Promise((resolve) => {
    if (MODE === 'dry') { log('DRY run:', cmd, args.join(' ')); return resolve({ code: 0, stdout: '', stderr: '' }); }
    execFile(cmd, args, { windowsHide: true, timeout: 20000 }, (err, stdout, stderr) => {
      if (err && !ignoreError) log('cmd error:', cmd, String(err.message).slice(0, 200));
      resolve({ code: err ? (err.code || 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

// Run a PowerShell one-liner (Windows).
function ps(script) {
  return run('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script]);
}

module.exports = { log, run, ps, requireMode, setDryRun, setLive, setMode, isDryRun, getMode, LOG };

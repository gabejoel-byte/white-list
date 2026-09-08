'use strict';
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { DIR } = require('./config');

const LOG = path.join(DIR, 'agent.log');
let DRY = process.env.WL_DRY_RUN === '1';
function setDryRun(v) { DRY = !!v; }
function isDryRun() { return DRY; }

function log(...args) {
  const line = `[${new Date().toISOString()}] ${args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')}`;
  console.log(line);
  try { fs.mkdirSync(DIR, { recursive: true }); fs.appendFileSync(LOG, line + '\n'); } catch { /* ignore */ }
}

// Run a binary. In dry-run mode we log the command instead of executing it, so
// the whole agent can be exercised on a dev box without touching the system.
function run(cmd, args = [], { ignoreError = true } = {}) {
  return new Promise((resolve) => {
    if (DRY) { log('DRY run:', cmd, args.join(' ')); return resolve({ code: 0, stdout: '', stderr: '' }); }
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

module.exports = { log, run, ps, setDryRun, isDryRun, LOG };

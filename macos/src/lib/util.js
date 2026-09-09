'use strict';
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { DIR } = require('./config');

const LOG = path.join(DIR, 'agent.log');

// Same explicit-execution-mode guard as the Windows agent: nothing mutates the
// system unless WL_DRY_RUN=1 (log) or WL_LIVE=1 (run) was deliberately chosen.
let MODE = process.env.WL_DRY_RUN === '1' ? 'dry'
  : process.env.WL_LIVE === '1' ? 'live' : 'unset';
function setDryRun(v) { if (v) MODE = 'dry'; }
function setLive() { if (MODE !== 'dry') MODE = 'live'; }
function setMode(m) { MODE = m; }
function isDryRun() { return MODE === 'dry'; }
function getMode() { return MODE; }
function requireMode(what = 'this operation') {
  if (MODE === 'unset') {
    throw new Error(`refusing ${what}: no execution mode set (WL_DRY_RUN=1 or WL_LIVE=1).`);
  }
}

function log(...args) {
  const line = `[${new Date().toISOString()}] ${args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')}`;
  console.log(line);
  try { fs.mkdirSync(DIR, { recursive: true }); fs.appendFileSync(LOG, line + '\n'); } catch { /* ignore */ }
}

function run(cmd, args = [], { ignoreError = true } = {}) {
  requireMode(`to execute "${cmd}"`);
  return new Promise((resolve) => {
    if (MODE === 'dry') { log('DRY run:', cmd, args.join(' ')); return resolve({ code: 0, stdout: '', stderr: '' }); }
    execFile(cmd, args, { timeout: 20000 }, (err, stdout, stderr) => {
      if (err && !ignoreError) log('cmd error:', cmd, String(err.message).slice(0, 200));
      resolve({ code: err ? (err.code || 1) : 0, stdout: stdout || '', stderr: stderr || '' });
    });
  });
}

module.exports = { log, run, requireMode, setDryRun, setLive, setMode, isDryRun, getMode, LOG };

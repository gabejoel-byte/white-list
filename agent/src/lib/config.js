'use strict';
// Local agent state: server URL, enrollment key, issued device token, and the
// last policy it successfully applied (kept so enforcement survives reboots and
// offline periods — "fail closed": if the server is unreachable, the last known
// policy stays in force).
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execSync } = require('child_process');

// ProgramData is admin-writable but not user-writable by default — a standard
// user can't tamper with the stored token/policy without elevation.
const DIR = process.env.WL_DATA_DIR
  || path.join(process.env.ProgramData || path.join(os.homedir(), '.whitelist'), 'WhitelistAgent');
const CONFIG = path.join(DIR, 'config.json');
const POLICY = path.join(DIR, 'policy.json');

function ensureDir() { fs.mkdirSync(DIR, { recursive: true }); }

function load() {
  try { return JSON.parse(fs.readFileSync(CONFIG, 'utf8')); } catch { return {}; }
}
function save(cfg) { ensureDir(); fs.writeFileSync(CONFIG, JSON.stringify(cfg, null, 2)); }

function loadPolicy() {
  try { return JSON.parse(fs.readFileSync(POLICY, 'utf8')); } catch { return null; }
}
function savePolicy(p) { ensureDir(); fs.writeFileSync(POLICY, JSON.stringify(p, null, 2)); }

// Stable machine id derived from hardware so re-installs re-bind to the same
// device row on the server. Falls back to a persisted random id.
function machineId(cfg) {
  if (cfg.machineId) return cfg.machineId;
  let raw = os.hostname();
  try {
    if (process.platform === 'win32') {
      const out = execSync('reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid', { encoding: 'utf8' });
      const m = out.match(/MachineGuid\s+REG_SZ\s+([\w-]+)/i);
      if (m) raw = m[1];
    }
  } catch { /* fall back to hostname + random */ }
  const id = crypto.createHash('sha256').update(raw + '|' + os.arch()).digest('hex').slice(0, 24);
  cfg.machineId = id; save(cfg);
  return id;
}

module.exports = { DIR, load, save, loadPolicy, savePolicy, machineId };

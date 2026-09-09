'use strict';
// Local agent state for macOS. Lives under /Library/Application Support (root-
// writable, standard-user read-only) so a non-admin user can't tamper with the
// stored token/policy. Falls back to the home dir when not running as root.
const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const { execSync } = require('child_process');

const SYSTEM_DIR = '/Library/Application Support/WhitelistAgent';
const DIR = process.env.WL_DATA_DIR
  || (canWrite('/Library/Application Support') ? SYSTEM_DIR
    : path.join(os.homedir(), 'Library', 'Application Support', 'WhitelistAgent'));

function canWrite(p) { try { fs.accessSync(p, fs.constants.W_OK); return true; } catch { return false; } }
function ensureDir() { fs.mkdirSync(DIR, { recursive: true }); }

const CONFIG = path.join(DIR, 'config.json');
const POLICY = path.join(DIR, 'policy.json');

function load() { try { return JSON.parse(fs.readFileSync(CONFIG, 'utf8')); } catch { return {}; } }
function save(cfg) { ensureDir(); fs.writeFileSync(CONFIG, JSON.stringify(cfg, null, 2)); }
function loadPolicy() { try { return JSON.parse(fs.readFileSync(POLICY, 'utf8')); } catch { return null; } }
function savePolicy(p) { ensureDir(); fs.writeFileSync(POLICY, JSON.stringify(p, null, 2)); }

// Stable machine id from the macOS Hardware UUID so re-installs re-bind.
function machineId(cfg) {
  if (cfg.machineId) return cfg.machineId;
  let raw = os.hostname();
  try {
    const out = execSync('ioreg -rd1 -c IOPlatformExpertDevice', { encoding: 'utf8' });
    const m = out.match(/IOPlatformUUID"\s*=\s*"([^"]+)"/);
    if (m) raw = m[1];
  } catch { /* fall back */ }
  const id = crypto.createHash('sha256').update(raw + '|' + os.arch()).digest('hex').slice(0, 24);
  cfg.machineId = id; save(cfg);
  return id;
}

module.exports = { DIR, load, save, loadPolicy, savePolicy, machineId };

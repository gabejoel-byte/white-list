'use strict';
// Tamper resistance (user-mode). See SECURITY.md for the honest threat model:
// this stops a standard user and slows a determined one; it is not a substitute
// for a signed kernel driver or MDM for an adversary with local admin.
//
// Provided here:
//   * unlock gate — pausing/uninstalling locally requires the dashboard unlock
//     key (checked offline against its hash) OR a signed unlock command from the
//     server. An unlock is time-boxed.
//   * service hardening — configure the Windows service to auto-restart on
//     failure, so killing the process brings it straight back (paired with the
//     watchdog, which also relaunches the service if it is stopped outright).
const crypto = require('crypto');
const { log, run, ps } = require('../lib/util');
const { save, load } = require('../lib/config');

const SERVICE_NAME = 'WhitelistAgent';

function sha256(s) { return crypto.createHash('sha256').update(String(s)).digest('hex'); }

// Is enforcement currently paused by a valid, unexpired unlock?
function unlockActive(cfg = load()) {
  return cfg.unlockUntil && Date.now() < cfg.unlockUntil;
}

// Local unlock via the admin key (matches the hash carried in the policy).
function tryUnlockWithKey(key, policy, minutes = 15) {
  const hash = policy?.tamper?.unlockKeyHash;
  if (!hash) return { ok: false, reason: 'no_key_configured' };
  if (sha256(key) !== hash) return { ok: false, reason: 'bad_key' };
  const cfg = load();
  cfg.unlockUntil = Date.now() + minutes * 60000;
  save(cfg);
  log('tamper: unlocked locally for', minutes, 'min');
  return { ok: true, until: cfg.unlockUntil };
}

// Server-issued unlock command (already authenticated by the device token).
function unlockFromServer(minutes = 15) {
  const cfg = load();
  cfg.unlockUntil = Date.now() + minutes * 60000;
  save(cfg);
  log('tamper: unlocked by server command for', minutes, 'min');
  return cfg.unlockUntil;
}

function relock() {
  const cfg = load();
  delete cfg.unlockUntil;
  save(cfg);
  log('tamper: relocked');
}

// Configure Windows service recovery so a killed process restarts immediately.
async function hardenService() {
  await run('sc.exe', ['failure', SERVICE_NAME, 'reset=', '60', 'actions=', 'restart/2000/restart/2000/restart/2000']);
  await run('sc.exe', ['failureflag', SERVICE_NAME, '1']);
  log('tamper: service recovery configured');
}

// Mark whether uninstall is currently authorized (set by a server 'uninstall'
// command or a valid unlock). The uninstaller refuses to run otherwise.
function authorizeUninstall() {
  const cfg = load();
  cfg.uninstallAuthorizedUntil = Date.now() + 30 * 60000;
  save(cfg);
  log('tamper: uninstall authorized for 30 min');
}
function uninstallAuthorized(cfg = load()) {
  return cfg.uninstallAuthorizedUntil && Date.now() < cfg.uninstallAuthorizedUntil;
}

module.exports = {
  SERVICE_NAME, unlockActive, tryUnlockWithKey, unlockFromServer, relock,
  hardenService, authorizeUninstall, uninstallAuthorized, sha256,
};

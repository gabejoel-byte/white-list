#!/usr/bin/env node
'use strict';
// Local admin CLI. Run elevated on the endpoint.
//   node src/cli.js status
//   node src/cli.js unlock <adminUnlockKey> [minutes]
//   node src/cli.js check-uninstall        # exit 0 if uninstall is authorized
const cfgStore = require('./lib/config');
const tamper = require('./enforce/tamper');

const [, , cmd, arg1, arg2] = process.argv;
const cfg = cfgStore.load();
const policy = cfgStore.loadPolicy();

if (cmd === 'status') {
  console.log(JSON.stringify({
    deviceId: cfg.deviceId || null,
    serverUrl: cfg.serverUrl || null,
    policyVersion: policy?.version || 0,
    level: policy?.level || null,
    unlockActive: tamper.unlockActive(cfg),
    uninstallAuthorized: tamper.uninstallAuthorized(cfg),
  }, null, 2));
} else if (cmd === 'unlock') {
  if (!arg1) { console.error('usage: unlock <key> [minutes]'); process.exit(2); }
  const r = tamper.tryUnlockWithKey(arg1, policy, arg2 ? +arg2 : 15);
  if (r.ok) { tamper.authorizeUninstall(); console.log('unlocked until', new Date(r.until).toISOString()); }
  else { console.error('unlock failed:', r.reason); process.exit(1); }
} else if (cmd === 'check-uninstall') {
  process.exit(tamper.uninstallAuthorized(cfg) ? 0 : 1);
} else {
  console.error('usage: status | unlock <key> [minutes] | check-uninstall');
  process.exit(2);
}

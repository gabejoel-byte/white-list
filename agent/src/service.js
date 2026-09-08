'use strict';
// Install / remove the agent as a Windows service that starts at boot and
// auto-restarts on crash. Run elevated:
//   node src/service.js install
//   node src/service.js uninstall
const path = require('path');

function svc() {
  const { Service } = require('node-windows');
  return new Service({
    name: 'WhitelistAgent',
    description: 'Whitelist Cloud endpoint control agent (app/web/VPN policy enforcement).',
    script: path.join(__dirname, 'index.js'),
    // node-windows restarts the process on unexpected exit.
    wait: 2,
    grow: 0.5,
    maxRestarts: 999999,
    env: [
      { name: 'WL_DATA_DIR', value: process.env.WL_DATA_DIR || '' },
    ].filter((e) => e.value),
  });
}

const action = process.argv[2];
const s = svc();

if (action === 'install') {
  s.on('install', () => { console.log('service installed; starting…'); s.start(); });
  s.on('alreadyinstalled', () => { console.log('already installed; starting…'); s.start(); });
  s.on('start', () => console.log('WhitelistAgent started.'));
  s.install();
} else if (action === 'uninstall') {
  s.on('uninstall', () => console.log('service uninstalled.'));
  s.uninstall();
} else {
  console.error('usage: node service.js <install|uninstall>');
  process.exit(1);
}

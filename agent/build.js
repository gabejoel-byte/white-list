'use strict';
// Produce a self-contained, deployable agent package under ../installer/dist.
// Bundles the current Node runtime (node.exe) so target machines need nothing
// pre-installed. Optionally bakes in server URL + enrollment key so the package
// is turn-key for a given org/policy.
//
//   node build.js --server https://mdm.example.com --key ENR-xxxx [--zip]
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const args = parseArgs(process.argv.slice(2));
const ROOT = __dirname;
const OUT = path.resolve(ROOT, '..', 'installer', 'dist');
const PKG = path.join(OUT, 'WhitelistAgent');

function parseArgs(a) { const o = {}; for (let i = 0; i < a.length; i++) { if (a[i].startsWith('--')) { const k = a[i].slice(2); o[k] = (a[i + 1] && !a[i + 1].startsWith('--')) ? a[++i] : true; } } return o; }

function copyDir(src, dst, skip = () => false) {
  fs.mkdirSync(dst, { recursive: true });
  for (const e of fs.readdirSync(src, { withFileTypes: true })) {
    if (skip(e.name)) continue;
    const s = path.join(src, e.name), d = path.join(dst, e.name);
    if (e.isDirectory()) copyDir(s, d, skip); else fs.copyFileSync(s, d);
  }
}

console.log('cleaning', PKG);
fs.rmSync(PKG, { recursive: true, force: true });
fs.mkdirSync(PKG, { recursive: true });

// Layout MIRRORS the repo so the agent's `../../core` / `../../../core` requires
// resolve inside the package: PKG/agent/{src,node_modules,package.json} + PKG/core.
console.log('copying agent source + deps…');
const AGENT = path.join(PKG, 'agent');
copyDir(path.join(ROOT, 'src'), path.join(AGENT, 'src'));
copyDir(path.join(ROOT, 'node_modules'), path.join(AGENT, 'node_modules'));
fs.copyFileSync(path.join(ROOT, 'package.json'), path.join(AGENT, 'package.json'));

console.log('bundling shared core…');
copyDir(path.join(ROOT, '..', 'core'), path.join(PKG, 'core'));

console.log('bundling node runtime…');
fs.copyFileSync(process.execPath, path.join(PKG, 'node.exe'));

// Bake config if provided (next to agent/package.json — index.js reads ../baked-config.json).
const config = {};
if (args.server) config.serverUrl = args.server;
if (args.key) config.enrollmentKey = args.key;
if (Object.keys(config).length) {
  fs.writeFileSync(path.join(AGENT, 'baked-config.json'), JSON.stringify(config, null, 2));
  console.log('baked config:', JSON.stringify(config));
} else {
  console.log('no --server/--key baked; installer will prompt or take params');
}

// Copy installer scripts alongside the package.
for (const f of ['install.ps1', 'uninstall.ps1', 'watchdog.ps1']) {
  const src = path.join(ROOT, '..', 'installer', f);
  if (fs.existsSync(src)) fs.copyFileSync(src, path.join(PKG, f));
}

// Sanity check: fail loudly if the package is missing pieces the agent needs
// at runtime (this is the bug that shipped an unbootable agent once).
for (const must of ['core/filter.js', 'core/api.js', 'agent/src/index.js', 'agent/src/enforce/web.js', 'node.exe']) {
  if (!fs.existsSync(path.join(PKG, must))) { console.error('BUILD BROKEN — missing:', must); process.exit(1); }
}
console.log('sanity check OK (core + agent + runtime present)');

console.log('package built at', PKG);

if (args.zip) {
  const zip = path.join(OUT, 'WhitelistAgent.zip');
  fs.rmSync(zip, { force: true });
  execFileSync('powershell.exe', ['-NoProfile', '-Command',
    `Compress-Archive -Path '${PKG}\\*' -DestinationPath '${zip}' -Force`], { stdio: 'inherit' });
  console.log('zip:', zip);
}

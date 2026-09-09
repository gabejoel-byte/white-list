'use strict';
// macOS VPN / bypass prevention:
//   * a pf (packet filter) anchor blocking the common VPN protocols outbound;
//   * termination of known VPN client processes each sweep.
// As on Windows, this contains a standard user; a local admin can still adjust
// pf. See SECURITY.md for the honest threat model.
const fs = require('fs');
const path = require('path');
const { log, run } = require('../lib/util');
const { DIR } = require('../lib/config');
const { CRITICAL } = require('./apps');

const VPN_PROCS = [
  'openvpn', 'openvpn-connect', 'wireguard', 'wg', 'nordvpn', 'nordvpnd',
  'expressvpn', 'expressvpnd', 'surfshark', 'protonvpn', 'cyberghost',
  'privateinternetaccess', 'pia', 'mullvad', 'mullvad-daemon', 'tunnelblick',
  'openvpn_launchd', 'windscribe', 'hotspotshield', 'psiphon', 'tor',
];

const ANCHOR = path.join(DIR, 'whitelist-vpn.pf.conf');

// pf rules: block outbound to the common VPN ports/protocols.
function pfRules() {
  return [
    'block drop out proto udp to any port 1194',   // OpenVPN
    'block drop out proto tcp to any port 1194',
    'block drop out proto udp to any port 51820',  // WireGuard
    'block drop out proto udp to any port 500',    // IKE
    'block drop out proto udp to any port 4500',   // IPsec NAT-T
    'block drop out proto tcp to any port 1723',   // PPTP
    'block drop out proto gre',                     // PPTP GRE
  ].join('\n') + '\n';
}

async function applyFirewall(block) {
  if (!block) {
    await run('/sbin/pfctl', ['-a', 'whitelist.vpn', '-F', 'rules']);
    log('vpn: pf anchor flushed (block=off)');
    return;
  }
  try { fs.mkdirSync(DIR, { recursive: true }); fs.writeFileSync(ANCHOR, pfRules()); } catch { /* ignore */ }
  await run('/sbin/pfctl', ['-e']);                             // ensure pf enabled
  await run('/sbin/pfctl', ['-a', 'whitelist.vpn', '-f', ANCHOR]); // load our anchor
  log('vpn: pf block rules applied');
}

async function killVpnProcesses() {
  const { stdout } = await run('/bin/ps', ['-axo', 'pid=,comm=']);
  const killed = [];
  for (const line of stdout.split(/\r?\n/)) {
    const m = line.trim().match(/^(\d+)\s+(.*)$/);
    if (!m) continue;
    const name = path.basename(m[2]).toLowerCase();
    if (CRITICAL.has(name)) continue;
    if (VPN_PROCS.includes(name)) { await run('/bin/kill', ['-9', m[1]]); killed.push(name); log('vpn: terminated', name); }
  }
  return [...new Set(killed)];
}

async function apply(vpnPolicy) { await applyFirewall(!!vpnPolicy?.block); }

module.exports = { apply, killVpnProcesses, applyFirewall, pfRules, VPN_PROCS };

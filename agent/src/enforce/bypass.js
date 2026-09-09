'use strict';
// Extra bypass closures for Windows (network/registry only — never touches the
// logon path, so it cannot lock anyone out of Windows):
//   * Force browsers' built-in DNS-over-HTTPS OFF via policy registry keys, so
//     Chrome/Edge/Firefox can't tunnel DNS around the hosts filter.
//   * Firewall-block outbound 443 to well-known public DoH resolver IPs.
// All rules use the WhitelistAgent- prefix and the uninstaller reverts them.
const { log, run, ps } = require('../lib/util');

let BYPASS = {};
try { BYPASS = require('../data/bypass.json'); } catch { BYPASS = {}; }

// DoH-off policy values: Chrome/Edge "DnsOverHttpsMode"=off; Firefox
// "Enabled"=0 (and mode 5 = off) under the Mozilla policy key.
async function setBrowserDohOff() {
  const chromeLike = [
    'HKLM\\SOFTWARE\\Policies\\Google\\Chrome',
    'HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge',
    'HKLM\\SOFTWARE\\Policies\\Chromium',
    'HKLM\\SOFTWARE\\Policies\\BraveSoftware\\Brave',
  ];
  for (const k of chromeLike) {
    await run('reg.exe', ['add', k, '/v', 'DnsOverHttpsMode', '/t', 'REG_SZ', '/d', 'off', '/f']);
    await run('reg.exe', ['add', k, '/v', 'BuiltInDnsClientEnabled', '/t', 'REG_DWORD', '/d', '0', '/f']);
  }
  // Firefox.
  await run('reg.exe', ['add', 'HKLM\\SOFTWARE\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS', '/v', 'Enabled', '/t', 'REG_DWORD', '/d', '0', '/f']);
  await run('reg.exe', ['add', 'HKLM\\SOFTWARE\\Policies\\Mozilla\\Firefox\\DNSOverHTTPS', '/v', 'Locked', '/t', 'REG_DWORD', '/d', '1', '/f']);
  log('bypass: browser DoH disabled via policy registry');
}

async function blockDohIPs() {
  await ps(`Get-NetFirewallRule -DisplayName 'WhitelistAgent-DoH*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue`);
  const ips = (BYPASS.dohIPs || []).join(',');
  if (!ips) return;
  // Block only 443 to these resolver IPs — normal DNS (port 53) and general web
  // browsing are unaffected.
  await ps(`New-NetFirewallRule -DisplayName 'WhitelistAgent-DoH-block' -Direction Outbound -Action Block -Protocol TCP -RemotePort 443 -RemoteAddress '${ips}' -ErrorAction SilentlyContinue`);
  log('bypass: firewall block on DoH resolver IPs (:443) applied');
}

async function apply(web) {
  if (!web || !web.blockDoH) return;
  await setBrowserDohOff();
  await blockDohIPs();
}

// Reversal helpers (also mirrored in uninstall.ps1 for full teardown).
async function clear() {
  await ps(`Get-NetFirewallRule -DisplayName 'WhitelistAgent-DoH*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue`);
}

module.exports = { apply, setBrowserDohOff, blockDohIPs, clear };

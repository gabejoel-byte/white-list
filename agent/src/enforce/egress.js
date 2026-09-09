'use strict';
// Egress lockdown (Windows): the ONLY way to stop VPNs that ride TCP 443 /
// obfuscated TLS — you can't port-block 443 without killing HTTPS, so instead
// flip the firewall to default-deny OUTBOUND and allow only:
//   * the agent's own node.exe  (its cloud link for unlock/uninstall commands,
//     AND the local filtering proxy's outbound to whitelisted sites)
//   * DNS (53) and DHCP (67/68) so the machine stays on the network
// Everything else outbound is blocked, so a VPN client connecting directly to
// its server — on any port, 443 included — simply can't.
//
// SAFETY: only meaningful in WHITELIST (lockdown) web mode, where browsers go
// through the local proxy. It is OFF unless a policy sets vpn.egressLockdown.
// The agent rule is added BEFORE the default-deny flips, so remote control is
// never lost, and uninstall/`-Force` runs `netsh advfirewall reset`. Never
// touches the logon path.
const { log, run, ps } = require('../lib/util');

const AGENT_NODE = process.execPath; // the node.exe running this agent

// Pure: the ordered list of allow-rule specs (used by tests).
function egressRules() {
  return [
    { name: 'Agent', args: ['-Program', AGENT_NODE] },
    { name: 'DNS-UDP', args: ['-Protocol', 'UDP', '-RemotePort', '53'] },
    { name: 'DNS-TCP', args: ['-Protocol', 'TCP', '-RemotePort', '53'] },
    { name: 'DHCP', args: ['-Protocol', 'UDP', '-RemotePort', '67,68'] },
    { name: 'NTP', args: ['-Protocol', 'UDP', '-RemotePort', '123'] },
  ];
}

async function applyEgressLockdown() {
  // 1) Allow-rules FIRST — especially the agent, so we never lose the cloud
  //    link that can push an unlock/uninstall.
  await ps(`Get-NetFirewallRule -DisplayName 'WhitelistAgent-Egress-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue`);
  for (const r of egressRules()) {
    const extra = r.args.map((a) => (a.startsWith('-') ? a : `'${a}'`)).join(' ');
    await ps(`New-NetFirewallRule -DisplayName 'WhitelistAgent-Egress-${r.name}' -Direction Outbound -Action Allow ${extra} -ErrorAction SilentlyContinue`);
  }
  // 2) THEN default-deny outbound.
  await run('netsh.exe', ['advfirewall', 'set', 'allprofiles', 'firewallpolicy', 'blockinbound,blockoutbound']);
  log('egress: default-deny outbound ON — all direct tunnels (incl. 443) blocked; agent/DNS/DHCP allowed');
}

async function clearEgressLockdown() {
  // Restore normal outbound + drop our allow-rules.
  await run('netsh.exe', ['advfirewall', 'set', 'allprofiles', 'firewallpolicy', 'blockinbound,allowoutbound']);
  await ps(`Get-NetFirewallRule -DisplayName 'WhitelistAgent-Egress-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue`);
  log('egress: default-deny outbound cleared');
}

async function apply(policy) {
  const on = policy?.vpn?.egressLockdown && policy?.web?.mode === 'whitelist';
  if (on) await applyEgressLockdown();
  else await clearEgressLockdown();
}

module.exports = { apply, applyEgressLockdown, clearEgressLockdown, egressRules, AGENT_NODE };

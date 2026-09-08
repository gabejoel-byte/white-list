'use strict';
// VPN / bypass prevention. A user could otherwise tunnel around the web filter.
// Countermeasures, layered:
//   1. Firewall rules blocking the common VPN protocols outbound (OpenVPN,
//      WireGuard, IKEv2/IPsec, PPTP, L2TP).
//   2. Terminate known VPN/tunnel client processes each sweep.
//   3. Pin DNS to a fixed resolver and block outbound port 53 to anything else,
//      so DNS can't be redirected around the hosts sinkhole. Known DoH
//      endpoints are also sinkholed via the web layer's category "proxies".
// Note: a determined attacker with local admin can still defeat user-mode
// controls — see SECURITY.md. This raises the bar substantially for a standard
// (non-admin) user, which is the intended threat model.
const { log, run, ps } = require('../lib/util');
const { CRITICAL } = require('./apps');

const VPN_PROCS = [
  'openvpn.exe', 'openvpnserv.exe', 'wireguard.exe', 'wg.exe', 'tunnel.exe',
  'nordvpn.exe', 'nordvpn-service.exe', 'expressvpnd.exe', 'expressvpn.exe',
  'surfshark.exe', 'protonvpn.exe', 'protonvpnservice.exe', 'cyberghost.exe',
  'pia-client.exe', 'pia-service.exe', 'mullvad.exe', 'mullvadvpn.exe',
  'tunnelbear.exe', 'hotspotshield.exe', 'hsswd.exe', 'windscribe.exe',
  'wstunnel.exe', 'ovpnconnector.exe', 'vpnagent.exe', 'vpnui.exe',
  'psiphon3.exe', 'psiphon.exe', 'ultrasurf.exe', 'lantern.exe', 'tor.exe',
];

const RULE_PREFIX = 'WhitelistAgent-VPN';

async function applyFirewall(block) {
  // Idempotent: remove our rules first, then (re)add if blocking.
  await ps(`Get-NetFirewallRule -DisplayName '${RULE_PREFIX}*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue`);
  if (!block) { log('vpn: firewall rules cleared (block=off)'); return; }
  const rules = [
    ['OpenVPN-UDP', 'UDP', '1194'],
    ['OpenVPN-TCP', 'TCP', '1194'],
    ['WireGuard', 'UDP', '51820'],
    ['IPsec-IKE', 'UDP', '500'],
    ['IPsec-NAT', 'UDP', '4500'],
    ['PPTP', 'TCP', '1723'],
    ['SSTP', 'TCP', '1701'],
  ];
  for (const [name, proto, port] of rules) {
    await ps(`New-NetFirewallRule -DisplayName '${RULE_PREFIX}-${name}' -Direction Outbound -Action Block -Protocol ${proto} -RemotePort ${port} -ErrorAction SilentlyContinue`);
  }
  // GRE (protocol 47) used by PPTP — netsh handles the raw protocol number.
  await run('netsh.exe', ['advfirewall', 'firewall', 'add', 'rule', `name=${RULE_PREFIX}-GRE`, 'dir=out', 'action=block', 'protocol=47']);
  log('vpn: firewall block rules applied');
}

async function pinDns(resolver) {
  if (!resolver) return;
  // Set a fixed resolver on every active adapter, and block outbound :53 to
  // anything but it so DNS can't be redirected.
  await ps(`Get-DnsClientServerAddress -AddressFamily IPv4 | ForEach-Object { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ServerAddresses '${resolver}' -ErrorAction SilentlyContinue }`);
  await ps(`Get-NetFirewallRule -DisplayName '${RULE_PREFIX}-DNS*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue`);
  await ps(`New-NetFirewallRule -DisplayName '${RULE_PREFIX}-DNS-allow' -Direction Outbound -Action Allow -Protocol UDP -RemotePort 53 -RemoteAddress '${resolver}' -ErrorAction SilentlyContinue`);
  await ps(`New-NetFirewallRule -DisplayName '${RULE_PREFIX}-DNS-block' -Direction Outbound -Action Block -Protocol UDP -RemotePort 53 -ErrorAction SilentlyContinue`);
  log('vpn: DNS pinned to', resolver);
}

async function killVpnProcesses() {
  const { stdout } = await run('tasklist.exe', ['/fo', 'csv', '/nh']);
  const killed = [];
  for (const line of stdout.split(/\r?\n/)) {
    const m = line.match(/^"([^"]+)","(\d+)"/);
    if (!m) continue;
    const name = m[1].toLowerCase();
    if (CRITICAL.has(name)) continue;
    if (VPN_PROCS.includes(name)) {
      await run('taskkill.exe', ['/PID', m[2], '/F', '/T']);
      killed.push(name); log('vpn: terminated', name);
    }
  }
  return [...new Set(killed)];
}

async function apply(vpnPolicy, opts = {}) {
  const block = !!vpnPolicy?.block;
  await applyFirewall(block);
  if (block && opts.dnsResolver) await pinDns(opts.dnsResolver);
}

module.exports = { apply, killVpnProcesses, applyFirewall, VPN_PROCS };

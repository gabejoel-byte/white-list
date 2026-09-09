#!/bin/bash
# Whitelist Agent uninstaller for macOS. Authorisation-gated, like Windows:
# refuses unless the dashboard authorised uninstall for this device, an unlock
# key is supplied, or --force (admin recovery). Run with sudo.
#   sudo ./uninstall.sh [--force]
set -uo pipefail

if [[ $EUID -ne 0 ]]; then echo "Must run as root (use sudo)."; exit 1; fi

DEST="/usr/local/whitelist-agent"
DATA="/Library/Application Support/WhitelistAgent"
PLIST="/Library/LaunchDaemons/cloud.whitelist.agent.plist"
FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

if [[ $FORCE -ne 1 ]]; then
  # Check the local authorisation flag the agent writes when the server sends an
  # 'uninstall' command (or an unlock). Absent that, refuse.
  if ! python3 - "$DATA/config.json" <<'PY'
import json,sys,time,os
p=sys.argv[1]
try: cfg=json.load(open(p))
except Exception: sys.exit(1)
until=cfg.get('uninstallAuthorizedUntil') or cfg.get('unlockUntil') or 0
sys.exit(0 if until> time.time()*1000 else 1)
PY
  then
    echo "Uninstall not authorised. Authorise it from the dashboard, or re-run with --force for admin recovery."
    exit 1
  fi
fi

echo "Uninstalling..."
launchctl bootout system "$PLIST" 2>/dev/null || true
rm -f "$PLIST"

# Revert enforcement side-effects.
for svc in $(networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | sed 's/^\*//'); do
  networksetup -setwebproxystate "$svc" off 2>/dev/null || true
  networksetup -setsecurewebproxystate "$svc" off 2>/dev/null || true
done
pfctl -a whitelist.vpn -F rules 2>/dev/null || true
# Strip the managed hosts block.
if [[ -f /etc/hosts ]]; then
  perl -0pi -e 's/# >>> whitelist-agent \(managed\) >>>.*?# <<< whitelist-agent \(managed\) <<<//s' /etc/hosts
fi
dscacheutil -flushcache 2>/dev/null || true
killall -HUP mDNSResponder 2>/dev/null || true

rm -rf "$DEST" "$DATA"
echo "Whitelist Agent removed."

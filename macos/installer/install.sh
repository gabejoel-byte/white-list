#!/bin/bash
# Whitelist Agent installer for macOS. Run with sudo:
#   sudo ./install.sh [--server https://mdm.example.com] [--key ENR-xxxx]
# Installs to /usr/local/whitelist-agent, runs as a root LaunchDaemon that
# starts at boot and auto-restarts (KeepAlive), and locks its files down.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "Must run as root (use sudo)."; exit 1; fi

SRC="$(cd "$(dirname "$0")/.." && pwd)"
DEST="/usr/local/whitelist-agent"
DATA="/Library/Application Support/WhitelistAgent"
PLIST_DEST="/Library/LaunchDaemons/cloud.whitelist.agent.plist"

SERVER=""; KEY=""
while [[ $# -gt 0 ]]; do case "$1" in
  --server) SERVER="$2"; shift 2;;
  --key) KEY="$2"; shift 2;;
  *) echo "unknown arg $1"; exit 1;;
esac; done

echo "Installing to $DEST"
launchctl bootout system "$PLIST_DEST" 2>/dev/null || true
mkdir -p "$DEST" "$DATA"
cp -R "$SRC/src" "$DEST/"
[[ -f "$SRC/baked-config.json" ]] && cp "$SRC/baked-config.json" "$DEST/"

# Bundle a node runtime so the endpoint needs nothing pre-installed.
if [[ -x "$SRC/node" ]]; then cp "$SRC/node" "$DEST/node";
elif command -v node >/dev/null 2>&1; then cp "$(command -v node)" "$DEST/node";
else echo "No node runtime found to bundle."; exit 1; fi

# Write config (server + enrollment key).
CFG="$DATA/config.json"
python3 - "$CFG" "$SERVER" "$KEY" "$DEST/baked-config.json" <<'PY'
import json,sys,os
cfg_path,server,key,baked=sys.argv[1:5]
cfg={}
if os.path.exists(baked):
    cfg=json.load(open(baked))
if server: cfg['serverUrl']=server
if key: cfg['enrollmentKey']=key
if 'serverUrl' not in cfg: sys.exit("No server URL (pass --server or bake baked-config.json).")
json.dump(cfg,open(cfg_path,'w'),indent=2)
print("configured server:",cfg.get('serverUrl'))
PY

# Install the LaunchDaemon with the real install dir.
sed "s#__INSTALL_DIR__#$DEST#g" "$SRC/installer/cloud.whitelist.agent.plist" > "$PLIST_DEST"
chown root:wheel "$PLIST_DEST"; chmod 644 "$PLIST_DEST"

# Lock down install + data dirs against a standard user.
chown -R root:wheel "$DEST" "$DATA"
chmod -R go-w "$DEST" "$DATA"

launchctl bootstrap system "$PLIST_DEST"
launchctl enable system/cloud.whitelist.agent
echo "Whitelist Agent installed and started. It will enrol within ~30s."

# Panic recovery — never get locked out

Keep this handy. None of the enforcement touches the Windows/macOS **logon**
path (the agent never kills `winlogon`, `lsass`, `logonui`, `explorer`, etc.,
and never changes credentials), so **you can always log in**. These steps undo
enforcement if a policy is too aggressive or the agent misbehaves.

## The golden rule
Run the managed person as a **standard user**. Keep a **separate administrator
account** for yourself. Enforcement targets standard users; as an admin you can
always unlock or uninstall. This alone guarantees you can't lock *yourself* out.

## Windows

**Temporary unlock (pause enforcement, keep it installed)** — as admin:
```
cd "C:\Program Files\WhitelistAgent"
.\node.exe src\cli.js unlock <your-admin-unlock-key> 30
```
Pauses enforcement for 30 minutes (the key is the one set on the policy).
Or from the dashboard: Devices → your device → ⋯ → **Temporary unlock**.

**Full removal / hard recovery** — as admin:
```
cd "C:\Program Files\WhitelistAgent"
powershell -ExecutionPolicy Bypass -File uninstall.ps1 -Force
```
`-Force` removes the service + watchdog and **reverts everything**: system
proxy, hosts file, VPN/DoH firewall rules, browser DoH policies, and folder
ACLs.

**If the service won't stop (last resort):** boot into **Safe Mode** (the service
does not run there), then run the `uninstall.ps1 -Force` above.

**Internet broken but agent gone?** Clear a stuck proxy:
```
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /f
ipconfig /flushdns
```

## macOS

**Temporary unlock** — as admin:
```
sudo /usr/local/whitelist-agent/node /usr/local/whitelist-agent/src/cli.js unlock <key> 30
```
**Full removal:** `sudo /usr/local/whitelist-agent/uninstall.sh --force` — reverts
the proxy, hosts, and pf rules and removes the LaunchDaemon.

## Android (managed) / iOS (supervised)
- Android: unenroll from the dashboard, or factory-reset the device.
- iOS: remove the profile (supervised → do it in Apple Configurator; or erase).

## The unlock key IS your safety net
Every policy should have an **admin unlock key** set in the dashboard. It is
stored only as a hash, and it's what the CLI/uninstaller check. Do not lose it —
though `-Force` (Windows) / `--force` (macOS) is the fallback for a local admin
even without the key.

<#
  Whitelist Agent uninstaller. Refuses to run unless uninstall has been
  AUTHORISED, which is the whole point of the tamper protection. Authorisation
  comes from either:
    * the dashboard queuing an "Authorize uninstall" command for this device
      (delivered on the next heartbeat), or
    * the admin unlock key entered here (-UnlockKey), which matches the hash in
      the active policy.

  Run elevated:
    powershell -ExecutionPolicy Bypass -File uninstall.ps1 [-UnlockKey <key>] [-Force]

  -Force bypasses the authorisation check for legitimate admin recovery (e.g.
  the dashboard is gone). It still requires local Administrator rights.
#>
param(
  [string]$UnlockKey,
  [switch]$Force
)
$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) { Write-Error 'Uninstall must be run as Administrator.'; exit 1 }

$Dest = Join-Path $env:ProgramFiles 'WhitelistAgent'
$DataDir = Join-Path $env:ProgramData 'WhitelistAgent'
$Node = Join-Path $Dest 'node.exe'
$Cli  = Join-Path $Dest 'agent\src\cli.js'

# --- authorisation gate ---
$authorized = $false
if ($Force) {
  Write-Host 'Force flag set — proceeding with admin recovery uninstall.' -ForegroundColor Yellow
  $authorized = $true
} elseif ($UnlockKey) {
  & $Node $Cli unlock $UnlockKey 5 | Out-Null
  if ($LASTEXITCODE -eq 0) { $authorized = $true } else { Write-Error 'Unlock key rejected.'; exit 1 }
} else {
  & $Node $Cli check-uninstall
  if ($LASTEXITCODE -eq 0) { $authorized = $true }
}
if (-not $authorized) {
  Write-Error 'Uninstall is not authorised. Authorise it from the dashboard, or supply -UnlockKey, or -Force for admin recovery.'
  exit 1
}

Write-Host 'Uninstalling Whitelist Agent...'

# --- stop watchdog + service ---
Unregister-ScheduledTask -TaskName 'WhitelistAgentWatchdog' -Confirm:$false -ErrorAction SilentlyContinue
& sc.exe stop WhitelistAgent 2>$null | Out-Null
Start-Sleep -Seconds 2
if (Test-Path (Join-Path $Dest 'agent\src\service.js')) {
  Push-Location $Dest
  & $Node (Join-Path $Dest 'agent\src\service.js') uninstall
  Pop-Location
  Start-Sleep -Seconds 3
}
& sc.exe delete WhitelistAgent 2>$null | Out-Null

# --- undo enforcement side-effects ---
Write-Host 'Reverting system changes...'
# Remove our firewall rules (VPN + DoH blocks).
Get-NetFirewallRule -DisplayName 'WhitelistAgent-*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
# Revert the browser DoH-off policies we set.
foreach ($k in @(
  'HKLM:\SOFTWARE\Policies\Google\Chrome',
  'HKLM:\SOFTWARE\Policies\Microsoft\Edge',
  'HKLM:\SOFTWARE\Policies\Chromium',
  'HKLM:\SOFTWARE\Policies\BraveSoftware\Brave')) {
  Remove-ItemProperty -Path $k -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue
  Remove-ItemProperty -Path $k -Name 'BuiltInDnsClientEnabled' -ErrorAction SilentlyContinue
}
Remove-Item -Path 'HKLM:\SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS' -Recurse -Force -ErrorAction SilentlyContinue
# Reset the firewall to defaults — undoes any egress lockdown (default-deny out).
& netsh.exe advfirewall reset | Out-Null
# Remove Safe Mode persistence entries.
foreach ($sb in @('Minimal','Network')) {
  Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$sb\WhitelistAgent" -Recurse -Force -ErrorAction SilentlyContinue
}
# Clear the forced system proxy.
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Set-ItemProperty -Path $key -Name ProxyEnable -Value 0 -ErrorAction SilentlyContinue
Remove-ItemProperty -Path $key -Name ProxyServer -ErrorAction SilentlyContinue
# Strip the managed block from the hosts file.
$hosts = "$env:WINDIR\System32\drivers\etc\hosts"
if (Test-Path $hosts) {
  $content = Get-Content $hosts -Raw
  $content = [regex]::Replace($content, '# >>> whitelist-agent \(managed\) >>>[\s\S]*?# <<< whitelist-agent \(managed\) <<<', '')
  Set-Content -Path $hosts -Value $content.TrimEnd() -Encoding ascii
}
# Clear any AppLocker policy we set (reset to empty).
& powershell.exe -NoProfile -Command "Set-AppLockerPolicy -XmlPolicy '$env:TEMP\empty-applocker.xml' -ErrorAction SilentlyContinue" 2>$null | Out-Null
ipconfig /flushdns | Out-Null

# --- remove files (release ACL first) ---
foreach ($p in @($Dest, $DataDir)) {
  if (Test-Path $p) {
    & icacls.exe $p /reset /T /C | Out-Null
    Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
  }
}

Write-Host 'Whitelist Agent removed.' -ForegroundColor Green

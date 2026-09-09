<#
  Whitelist Agent installer. Run elevated (right-click > Run as administrator,
  or from an elevated prompt). Deploys the agent to Program Files, installs it
  as an auto-starting service, hardens it against a standard user, and enrols it
  with the cloud dashboard.

  Usage:
    powershell -ExecutionPolicy Bypass -File install.ps1 `
        [-Server https://mdm.example.com] [-Key ENR-xxxx]

  If -Server/-Key are omitted the values baked into baked-config.json are used.
#>
param(
  [string]$Server,
  [string]$Key
)
$ErrorActionPreference = 'Stop'

# --- require admin ---
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
if (-not $isAdmin) { Write-Error 'This installer must be run as Administrator.'; exit 1 }

$Src = $PSScriptRoot
$Dest = Join-Path $env:ProgramFiles 'WhitelistAgent'
$Node = Join-Path $Dest 'node.exe'
$DataDir = Join-Path $env:ProgramData 'WhitelistAgent'

Write-Host "Installing Whitelist Agent to $Dest"

# --- copy package ---
if (Test-Path $Dest) {
  # Stop an existing service before overwriting.
  & sc.exe stop WhitelistAgent 2>$null | Out-Null
  Start-Sleep -Seconds 2
}
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item -Path (Join-Path $Src '*') -Destination $Dest -Recurse -Force -Exclude 'install.ps1','uninstall.ps1'
# Keep the uninstaller available inside the install dir too.
Copy-Item -Path (Join-Path $Src 'uninstall.ps1') -Destination $Dest -Force
Copy-Item -Path (Join-Path $Src 'watchdog.ps1')  -Destination $Dest -Force -ErrorAction SilentlyContinue

New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

# --- write config (server + enrollment key) ---
# baked-config.json lives under agent\ in the packaged layout (older builds put
# it at the root) — check both.
$bakedPath = Join-Path $Dest 'agent\baked-config.json'
if (-not (Test-Path $bakedPath)) { $bakedPath = Join-Path $Dest 'baked-config.json' }
$cfg = @{}
if (Test-Path $bakedPath) { $cfg = Get-Content $bakedPath -Raw | ConvertFrom-Json }
if ($Server) { $cfg.serverUrl = $Server }
if ($Key)    { $cfg.enrollmentKey = $Key }
if (-not $cfg.serverUrl) { Write-Error 'No server URL (pass -Server or bake baked-config.json).'; exit 1 }
$cfg | ConvertTo-Json | Set-Content -Path (Join-Path $DataDir 'config.json') -Encoding utf8
Write-Host "Configured server: $($cfg.serverUrl)"

# --- install the Windows service using the bundled node runtime ---
Write-Host 'Installing service...'
Push-Location $Dest
& $Node (Join-Path $Dest 'agent\src\service.js') install
Pop-Location
Start-Sleep -Seconds 3

# --- harden service recovery: restart on failure ---
& sc.exe failure WhitelistAgent reset= 60 actions= restart/2000/restart/2000/restart/5000 | Out-Null
& sc.exe failureflag WhitelistAgent 1 | Out-Null
& sc.exe config WhitelistAgent start= auto | Out-Null

# --- watchdog scheduled task: relaunch the service if it is stopped, and run
#     at boot + every minute. Runs as SYSTEM so a standard user cannot disable
#     it without elevation. ---
Write-Host 'Registering watchdog task...'
$wd = Join-Path $Dest 'watchdog.ps1'
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$wd`""
$trigger1 = New-ScheduledTaskTrigger -AtStartup
$trigger2 = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 3650)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName 'WhitelistAgentWatchdog' -Action $action -Trigger @($trigger1,$trigger2) -Principal $principal -Force | Out-Null

# --- lock down install + data dirs so a standard user can't modify/delete them ---
Write-Host 'Applying ACLs...'
foreach ($p in @($Dest, $DataDir)) {
  & icacls.exe $p /inheritance:r | Out-Null
  & icacls.exe $p /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
  & icacls.exe $p /grant:r "Users:(OI)(CI)RX" | Out-Null   # read/execute, no modify/delete
}

# --- Safe Mode persistence: register the service so it also runs in Safe Mode
#     (closes the "boot Safe Mode to disable enforcement" bypass). This does NOT
#     disable Safe Mode itself, so admin recovery via Safe Mode still works. ---
Write-Host 'Registering Safe Mode persistence...'
foreach ($sb in @('Minimal','Network')) {
  $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$sb\WhitelistAgent"
  New-Item -Path $key -Force | Out-Null
  Set-ItemProperty -Path $key -Name '(Default)' -Value 'Service' -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host 'Whitelist Agent installed and started.' -ForegroundColor Green
Write-Host 'It will enrol and pull its policy from the dashboard within ~30s.'

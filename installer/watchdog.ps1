<#
  Watchdog: ensures the WhitelistAgent service is installed and running. Runs as
  SYSTEM from a scheduled task (at boot + every minute). If a user with local
  admin stops the service, this brings it straight back within a minute; the
  service's own recovery settings handle process crashes in ~2s. Together they
  make the agent hard to keep down without also removing this task (which needs
  elevation and is the documented, authorised uninstall path).
#>
$ErrorActionPreference = 'SilentlyContinue'
$Dest = Join-Path $env:ProgramFiles 'WhitelistAgent'
$Node = Join-Path $Dest 'node.exe'

$svc = Get-Service -Name 'WhitelistAgent' -ErrorAction SilentlyContinue
if ($null -eq $svc) {
  # Service missing entirely — reinstall it from the on-disk package.
  if (Test-Path $Node) {
    & $Node (Join-Path $Dest 'src\service.js') install | Out-Null
  }
} elseif ($svc.Status -ne 'Running') {
  Start-Service -Name 'WhitelistAgent'
}

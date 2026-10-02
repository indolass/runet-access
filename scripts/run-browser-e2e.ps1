# Runs tests\browser-e2e.mjs. Requires owner approval for the registry write (see AGENTS.md).
# Writes ONE HKCU value for the test, ALWAYS removes it in `finally`, and compares the Windows
# system proxy settings before/after.
param([string]$Script = 'tests\browser-e2e.mjs')
. "$PSScriptRoot\env.ps1"
$Dist   = Join-Path $RunetRoot 'dist\runet-access'
$RegKey  = 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.runet_access.host'
$Inet    = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
function Get-SysProxy { $p = Get-ItemProperty $Inet; [pscustomobject]@{ ProxyEnable = $p.ProxyEnable; ProxyServer = $p.ProxyServer; AutoConfigURL = $p.AutoConfigURL; AutoDetect = $p.AutoDetect } | ConvertTo-Json -Compress }

if (Test-Path $RegKey) { throw "Registry key already exists: $RegKey. Not touching it; investigate." }
$before = Get-SysProxy
Write-Host "system proxy before: $before"
$code = 1
try {
  & (Join-Path $Dist 'register.ps1') -Apply
  # stderr lines are stringified so PowerShell 5.1 does not wrap them in NativeCommandError records
  node (Join-Path $RunetRoot $Script) 2>&1 | ForEach-Object { "$_" }
  $code = $LASTEXITCODE
} finally {
  & (Join-Path $Dist 'register.ps1') -Uninstall -Apply
  $gone = -not (Test-Path $RegKey)
  Write-Host "registry key removed: $gone"
  $after = Get-SysProxy
  Write-Host "system proxy after:  $after"
  Write-Host ("system proxy unchanged: " + ($before -eq $after))
  if (-not $gone) { $code = 2 }
}
exit $code

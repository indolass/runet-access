# Runs a PowerShell test script on a private INVISIBLE Windows desktop, so the real windows it opens
# (dialogs, Chrome) never appear on the screen of the person at the computer.
#
#   . .\scripts\env.ps1; .\tests\run-hidden.ps1 tests\chrome-install-check.ps1 [args...]
#
# The script's output is captured in .local\logs\<name>.hidden.txt and echoed here.
param([Parameter(Mandatory = $true)][string]$Script, [Parameter(ValueFromRemainingArguments = $true)][string[]]$Rest)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\hidden-desktop.ps1"
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$script = (Resolve-Path $Script).Path
$log = Join-Path $root ('.local\logs\' + [IO.Path]::GetFileNameWithoutExtension($script) + '.hidden.txt')
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log -Force }
[HD]::Create('RunetAccessTest-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$inner = "& '$script' $($Rest -join ' ') *> '$log'; exit `$LASTEXITCODE"
$cmd = '"' + $ps + '" -NoProfile -ExecutionPolicy Bypass -Command "' + $inner.Replace('"', '\"') + '"'
$id = [HD]::Start($cmd)
$p = Get-Process -Id $id
while (-not $p.HasExited) { Start-Sleep -Milliseconds 500 }
Start-Sleep -Milliseconds 300
if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Encoding utf8 }
exit $p.ExitCode

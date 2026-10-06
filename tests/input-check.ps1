# Runs tests\input-check.mjs (real typing / real Ctrl+V / Shift+Insert into the key field of the control page,
# in the real Chrome started by RunetAccess.exe) on a PRIVATE window station: it has its own clipboard, so the
# test can fill a system clipboard and paste from it without ever touching the clipboard of the person at the
# computer, and nothing it opens is visible. The output lands in .local\logs\input-check.txt and is echoed.
#
#   . .\scripts\env.ps1; .\tests\input-check.ps1 [-Exe path\to\RunetAccess.exe]
param([string]$Exe = '')
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\scripts\env.ps1"
. "$PSScriptRoot\window-station.ps1"
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$log = Join-Path $root '.local\logs\input-check.txt'
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log -Force }
if ($Exe) { $env:RUNET_EXE = (Resolve-Path $Exe).Path }

[WS]::Create('RunetAccessInput-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'

# Isolation self-test first: a Set-Clipboard on the private window station must leave the sequence number of
# the WinSta0 (owner's) clipboard untouched. Repeated up to three times, as the person at the computer may be
# copying something at the same moment.
$isolated = $false
for ($i = 0; $i -lt 3 -and -not $isolated; $i++) {
  $s0 = [WS]::OwnerClipboardSeq()
  $probe = [Diagnostics.Process]::GetProcessById([WS]::Start('"' + $ps + '" -NoProfile -Command "Set-Clipboard -Value runet-isolation-probe"'))
  $probe.WaitForExit()
  if ([WS]::OwnerClipboardSeq() -eq $s0) { $isolated = $true }
}
if (-not $isolated) { [WS]::Close(); throw 'the private window station does not have its own clipboard: refusing to run the clipboard steps' }
Write-Host "isolation: Set-Clipboard on $([WS]::Name) did not change the owner's clipboard sequence number"

$seqBefore = [WS]::OwnerClipboardSeq()
$env:RUNET_PRIVATE_WINSTA = [WS]::Name          # the test refuses to touch any clipboard without this
$node = (Get-Command node.exe).Source
$cmd = '"' + $node + '" "' + (Join-Path $root 'tests\input-check.mjs') + '"'
$inner = "& $cmd *> '$log'; exit `$LASTEXITCODE"
$line = '"' + $ps + '" -NoProfile -ExecutionPolicy Bypass -Command "' + $inner.Replace('"', '\"') + '"'
$exitFile = Join-Path $root '.local\logs\input-check.exit'
if (Test-Path -LiteralPath $exitFile) { Remove-Item -LiteralPath $exitFile -Force }
$id = [WS]::Start($line)
$p = [Diagnostics.Process]::GetProcessById($id)
$p.WaitForExit()
# the exit code of a process started with CreateProcess is not reliably visible here: the test writes it to a file
$code = 2
if (Test-Path -LiteralPath $exitFile) { $code = [int](Get-Content -LiteralPath $exitFile -Raw).Trim() }
Start-Sleep -Milliseconds 300
[WS]::Close()
if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Encoding utf8 }
$seqAfter = [WS]::OwnerClipboardSeq()
if ($seqAfter -eq $seqBefore) { Write-Host "OWNER CLIPBOARD: unchanged (sequence number $seqBefore)" }
else { Write-Host "OWNER CLIPBOARD: sequence number changed $seqBefore -> $seqAfter (something on WinSta0 wrote to it during the run)" }
Write-Host "input-check exit code: $code"
exit $code

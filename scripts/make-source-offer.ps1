# Builds the COMPLETE corresponding source of the bundled sing-box (GPLv3): the pinned tag archive
# plus all Go dependencies vendored, packed into dist\source-offer\. About 1.6 GB unpacked, ~440 MB packed,
# so it is NOT put into the installer; the installer carries the tag archive and a written offer
# (installer\SOURCE-OFFER.txt). Keep this archive to answer requests.
#
#   .\scripts\make-source-offer.ps1
#
# Everything happens inside the project (.local\tmp\sbsrc, .local\cache\go-mod). Network access is used
# only to fetch the Go modules listed in sing-box's own go.sum (the go tool verifies every hash).
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\env.ps1"
$lock = Get-Content (Join-Path $PSScriptRoot 'tools.lock.json') -Raw | ConvertFrom-Json
$tar = Join-Path $L 'cache\downloads\sing-box-1.13.16-source.tar.gz'
if (-not (Test-Path $tar)) { throw 'download the pinned source archive first (scripts\make-installer.ps1 does it)' }
if ((Get-FileHash $tar -Algorithm SHA256).Hash.ToLower() -ne $lock.'sing-box-source'.sha256) { throw 'source archive does not match tools.lock.json' }

$work = Join-Path $L 'tmp\sbsrc'
if (Test-Path -LiteralPath $work) {
  if ((Split-Path $work -Leaf) -ne 'sbsrc' -or -not $work.StartsWith($L)) { throw "unexpected path $work" }
  Remove-Item -LiteralPath $work -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $work | Out-Null
tar -xzf $tar -C $work
if ($LASTEXITCODE) { throw 'tar extract failed' }
$src = Get-ChildItem $work -Directory | Select-Object -First 1
Push-Location $src.FullName
try {
  $env:GOFLAGS = ''; $env:GOPROXY = 'https://proxy.golang.org,direct'; $env:GONOSUMDB = ''
  $log = Join-Path $L 'logs\sb-vendor.log'
  cmd /c "go mod vendor > `"$log`" 2>&1"          # go prints progress on stderr; keep it out of PowerShell's error stream
  if ($LASTEXITCODE) { throw "go mod vendor failed, see $log" }
} finally { Pop-Location }

$outDir = Join-Path $RunetRoot 'dist\source-offer'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$out = Join-Path $outDir 'sing-box-v1.13.16-source-with-vendored-dependencies.tar.gz'
if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force }
tar -czf $out -C $work $src.Name
if ($LASTEXITCODE) { throw 'tar pack failed' }
$h = (Get-FileHash $out -Algorithm SHA256).Hash.ToLower()
[IO.File]::WriteAllText((Join-Path $outDir 'SHA256SUMS.txt'), "$h  $(Split-Path $out -Leaf)`n", (New-Object Text.UTF8Encoding($false)))
Remove-Item -LiteralPath $work -Recurse -Force      # our own temp folder (no links inside: it was just extracted)
Write-Host "done: $out ($([math]::Round((Get-Item $out).Length/1MB)) MB) sha256 $h"

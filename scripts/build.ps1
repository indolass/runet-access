# Builds dist\runet-access\ : RunetAccess.exe (launcher) + pinned sing-box + licences + docs.
# Everything stays inside the repo root (see scripts\env.ps1). Run:  .\scripts\build.ps1
. "$PSScriptRoot\env.ps1"
$Version = '0.2.0'
$Dist    = Join-Path $RunetRoot 'dist\runet-access'

# 1. tools (idempotent, hash-verified)
if (-not (Test-Path (Join-Path $L 'tools\go\bin\go.exe')) -or -not (Test-Path (Join-Path $L 'tools\sing-box\sing-box.exe'))) {
  & (Join-Path $PSScriptRoot 'fetch-tools.ps1'); . "$PSScriptRoot\env.ps1"
}

# 2. checks before building
Push-Location (Join-Path $RunetRoot 'src\app')
try {
  $fmt = gofmt -l .
  if ($fmt) { throw "gofmt: $fmt" }
  go vet ./...;  if ($LASTEXITCODE) { throw 'go vet failed' }
  go test ./...; if ($LASTEXITCODE) { throw 'go test failed' }
} finally { Pop-Location }
node --test (Join-Path $RunetRoot 'tests\check.test.mjs') (Join-Path $RunetRoot 'tests\page-verdict.test.mjs')
if ($LASTEXITCODE) { throw 'node tests failed' }

# 3. fresh dist (only our own output folder)
if (Test-Path $Dist) { Remove-Item -LiteralPath $Dist -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Dist | Out-Null

Push-Location (Join-Path $RunetRoot 'src\app')
try {
  # windowsgui: no console window; errors are shown in a message box
  go build -trimpath -ldflags "-H=windowsgui -X main.version=$Version" -o (Join-Path $Dist 'RunetAccess.exe') ./cmd/launcher
  if ($LASTEXITCODE) { throw 'go build failed' }
} finally { Pop-Location }
Copy-Item (Join-Path $L 'tools\sing-box\sing-box.exe') (Join-Path $Dist 'sing-box.exe')

# 4. licences, docs, hashes
Copy-Item (Join-Path $RunetRoot 'third_party') (Join-Path $Dist 'third_party') -Recurse
Copy-Item (Join-Path $RunetRoot 'LICENSE') (Join-Path $Dist 'LICENSE.txt')
foreach ($d in 'INSTALL.md', 'MANUAL-CHECK.md', 'LIMITATIONS.md', 'UX.md') {
  $src = Join-Path $RunetRoot ('docs\' + $d)
  if (Test-Path $src) { Copy-Item $src $Dist }
}
$sums = Get-ChildItem $Dist -Recurse -File | Sort-Object FullName | ForEach-Object {
  '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.FullName.Substring($Dist.Length + 1).Replace('\', '/')
}
[IO.File]::WriteAllText((Join-Path $Dist 'SHA256SUMS.txt'), (($sums -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))

Write-Host "built: $Dist"

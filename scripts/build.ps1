# Builds dist\runet-access\ : RunetAccess.exe (launcher) + pinned sing-box + licences + docs.
# Everything stays inside the repo root (see scripts\env.ps1). Run:  .\scripts\build.ps1
. "$PSScriptRoot\env.ps1"
$Version = (Get-Content (Join-Path $RunetRoot 'VERSION') -Raw).Trim()
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "bad VERSION: $Version" }
$Dist    = Join-Path $RunetRoot 'dist\runet-access'

# 1. tools (idempotent, hash-verified)
if (-not (Test-Path (Join-Path $L 'tools\go\bin\go.exe')) -or -not (Test-Path (Join-Path $L 'tools\sing-box\sing-box.exe'))) {
  & (Join-Path $PSScriptRoot 'fetch-tools.ps1'); . "$PSScriptRoot\env.ps1"
}

# 2. checks before building
Push-Location (Join-Path $RunetRoot 'src\app')
try {
  # the third-party Go code linked into the program is exactly the pinned set (scripts\tools.lock.json), with the pinned hashes
  $pins = (Get-Content (Join-Path $PSScriptRoot 'tools.lock.json') -Raw | ConvertFrom-Json).'go-modules'
  $sumLines = Get-Content go.sum
  $pinned = @()
  foreach ($m in $pins.PSObject.Properties) {
    if ($m.Name -eq 'note') { continue }
    $pinned += $m.Name
    if ($sumLines -notcontains "$($m.Name) $($m.Value.version) h1:$($m.Value.h1)") { throw "go.sum does not hold the pinned hash of $($m.Name) $($m.Value.version)" }
  }
  $linked = @(go list -deps -f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}}{{end}}{{end}}' ./cmd/launcher | Sort-Object -Unique)
  $want = @($pins.PSObject.Properties | Where-Object { $_.Name -ne 'note' } | ForEach-Object { "$($_.Name)@$($_.Value.version)" } | Sort-Object)
  if (($linked -join '|') -ne ($want -join '|')) { throw "linked Go modules differ from the pinned set.`nlinked: $($linked -join ', ')`npinned: $($want -join ', ')" }
  go mod verify; if ($LASTEXITCODE) { throw 'go mod verify failed (module cache differs from go.sum)' }
  # application manifest (asInvoker, common controls v6, DPI) -> embedded by the linker
  go run ./cmd/genrsrc cmd/launcher/rsrc_windows_amd64.syso; if ($LASTEXITCODE) { throw 'genrsrc failed' }
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

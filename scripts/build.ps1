# Builds dist\runet-access\ : host + pinned sing-box + extension + native-messaging manifest.
# Everything stays inside the repo root (see scripts\env.ps1). Run:  .\scripts\build.ps1
. "$PSScriptRoot\env.ps1"
$Version = '0.1.0'
$Dist    = Join-Path $RunetRoot 'dist\runet-access'
$HostName = 'com.runet_access.host'

# 1. tools (idempotent, hash-verified)
if (-not (Test-Path (Join-Path $L 'tools\go\bin\go.exe')) -or -not (Test-Path (Join-Path $L 'tools\sing-box\sing-box.exe'))) {
  & (Join-Path $PSScriptRoot 'fetch-tools.ps1'); . "$PSScriptRoot\env.ps1"
}

# 2. checks before building
Push-Location (Join-Path $RunetRoot 'src\native-host')
try {
  $fmt = gofmt -l .
  if ($fmt) { throw "gofmt: $fmt" }
  go vet ./...;  if ($LASTEXITCODE) { throw 'go vet failed' }
  go test ./...; if ($LASTEXITCODE) { throw 'go test failed' }
} finally { Pop-Location }
node --test (Join-Path $RunetRoot 'tests\gov.test.mjs') (Join-Path $RunetRoot 'tests\pac.test.mjs')
if ($LASTEXITCODE) { throw 'node tests failed' }

# 3. fresh dist (only our own output folder; never recursive-delete anything else)
if (Test-Path $Dist) { Remove-Item -LiteralPath $Dist -Recurse -Force }
$bin = Join-Path $Dist 'bin'
New-Item -ItemType Directory -Force -Path $bin | Out-Null

Push-Location (Join-Path $RunetRoot 'src\native-host')
try {
  go build -trimpath -ldflags "-X main.hostVersion=$Version" -o (Join-Path $bin 'runet-access-host.exe') ./cmd/host
  if ($LASTEXITCODE) { throw 'go build failed' }
} finally { Pop-Location }
Copy-Item (Join-Path $L 'tools\sing-box\sing-box.exe') (Join-Path $bin 'sing-box.exe')

# 4. extension (copied, so the loaded folder is exactly what was tested)
Copy-Item (Join-Path $RunetRoot 'src\extension') (Join-Path $Dist 'extension') -Recurse

# 5. native messaging manifest next to the host (relative path => the folder is relocatable)
$extId = (node (Join-Path $PSScriptRoot 'ext-id.mjs')).Trim()
$nm = [ordered]@{
  name = $HostName; description = 'Runet Access native messaging host'
  path = 'runet-access-host.exe'; type = 'stdio'
  allowed_origins = @("chrome-extension://$extId/")
} | ConvertTo-Json
[IO.File]::WriteAllText((Join-Path $bin "$HostName.json"), $nm, (New-Object Text.UTF8Encoding($false)))

# 5b. user-facing scripts: .cmd stays ASCII-only, .ps1 gets a UTF-8 BOM (Windows PowerShell 5.1 reads Cyrillic correctly)
$pkg = Join-Path $RunetRoot 'scripts\package'
Copy-Item (Join-Path $pkg "Install.cmd") $Dist
Copy-Item (Join-Path $pkg "Uninstall.cmd") $Dist
$reg = [IO.File]::ReadAllText((Join-Path $pkg "register.ps1"))
[IO.File]::WriteAllText((Join-Path $Dist "register.ps1"), $reg, (New-Object Text.UTF8Encoding($true)))
foreach ($d in "INSTALL.md", "MANUAL-CHECK.md", "LIMITATIONS.md") {
  $src = Join-Path $RunetRoot ("docs\" + $d)
  if (Test-Path $src) { Copy-Item $src $Dist }
}

# 6. licences + hashes
Copy-Item (Join-Path $RunetRoot 'third_party') (Join-Path $Dist 'third_party') -Recurse
Copy-Item (Join-Path $RunetRoot 'LICENSE') (Join-Path $Dist 'LICENSE.txt')
$sums = Get-ChildItem $Dist -Recurse -File | Sort-Object FullName | ForEach-Object {
  '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.FullName.Substring($Dist.Length + 1).Replace('\', '/')
}
[IO.File]::WriteAllText((Join-Path $Dist 'SHA256SUMS.txt'), (($sums -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))

Write-Host "built: $Dist"
Write-Host "extension id: $extId"

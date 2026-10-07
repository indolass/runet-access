# Builds the ONE-FILE portable version: dist\portable\RunetAccess-Portable-<version>.exe
#
#   .\scripts\make-portable.ps1 [-SkipBuild]
#
# The exe is the launcher built with -tags portable: the pinned sing-box core and the licence texts are embedded in it
# as a zip (payload.zip with a MANIFEST.sha256) and the hashes of that zip and of the core are baked into the program
# (-X main.payloadSHA256 / main.coreSHA256). At run time the program unpacks the components into its own data folder and
# verifies them before use (see src\app\cmd\launcher\portable_windows.go). Nothing is installed or registered.
#
# What this script does, and refuses to continue when any step fails:
#   1. runs the normal build (scripts\build.ps1: gofmt, vet, tests, linked-module check, go build) unless -SkipBuild
#   2. verifies sing-box.exe really is the pinned release and the source archive matches its pinned hash
#   3. stages ONLY an explicit list of files (the core and the licences) and zips them with a manifest
#   4. scans the payload and the final exe for key material / personal paths (values are never printed)
#   5. builds the portable exe, then writes <name>.sha256.txt and the short instruction for the friend next to it
param(
  [switch]$SkipBuild,
  [string]$OutDir
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\env.ps1"
$started = Get-Date
$lock = Get-Content (Join-Path $PSScriptRoot 'tools.lock.json') -Raw | ConvertFrom-Json
$Version = (Get-Content (Join-Path $RunetRoot 'VERSION') -Raw).Trim()
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "bad VERSION: $Version" }
if (-not $OutDir) { $OutDir = Join-Path $RunetRoot 'dist\portable' }
$dl = Join-Path $L 'cache\downloads'
$DistApp = Join-Path $RunetRoot 'dist\runet-access'
$Payload = Join-Path $L 'tmp\portable-payload'
$GoDir = Join-Path $RunetRoot 'src\app'
$EmbedDir = Join-Path $GoDir 'cmd\launcher\payload'
$exeName = "RunetAccess-Portable-$Version.exe"
$exePath = Join-Path $OutDir $exeName

function Get-Sha256($path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() }
function Under($child, $parent) { [IO.Path]::GetFullPath($child).StartsWith([IO.Path]::GetFullPath($parent).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) }

# ---------------------------------------------------------------- 1. build + checks
if (-not $SkipBuild) {
  & (Join-Path $PSScriptRoot 'build.ps1')
  . "$PSScriptRoot\env.ps1"
} elseif (-not (Test-Path (Join-Path $DistApp 'sing-box.exe'))) { throw 'SkipBuild: dist\runet-access does not exist' }

# ---------------------------------------------------------------- 2. provenance of the core
$sbSource = Join-Path $dl 'sing-box-1.13.16-source.tar.gz'
if (-not (Test-Path $sbSource) -or (Get-Sha256 $sbSource) -ne $lock.'sing-box-source'.sha256) { throw 'sing-box source archive missing or SHA256 mismatch with tools.lock.json' }
$zip = Join-Path $dl ([IO.Path]::GetFileName($lock.'sing-box'.url))
if (-not (Test-Path $zip) -or (Get-Sha256 $zip) -ne $lock.'sing-box'.sha256) { throw 'pinned sing-box zip missing or SHA256 mismatch (run scripts\fetch-tools.ps1)' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$tmpSb = Join-Path $L 'tmp\sb-verify-portable.exe'
$za = [IO.Compression.ZipFile]::OpenRead($zip)
try {
  $entry = $za.Entries | Where-Object { $_.Name -eq 'sing-box.exe' } | Select-Object -First 1
  if (-not $entry) { throw 'sing-box.exe not found in the pinned zip' }
  [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $tmpSb, $true)
} finally { $za.Dispose() }
$sbHash = Get-Sha256 $tmpSb
Remove-Item -LiteralPath $tmpSb
if ((Get-Sha256 (Join-Path $DistApp 'sing-box.exe')) -ne $sbHash) { throw 'dist sing-box.exe is not the pinned release' }
$sbVer = ((& (Join-Path $DistApp 'sing-box.exe') version) | Select-Object -First 1)
if ($sbVer -notlike "*$($lock.'sing-box'.version)*") { throw "sing-box reports '$sbVer', pinned $($lock.'sing-box'.version)" }
Write-Host "sing-box $($lock.'sing-box'.version) matches the pinned release (sha256 $($sbHash.Substring(0,12))...)"

# ---------------------------------------------------------------- 3. payload from an explicit list
if (Test-Path -LiteralPath $Payload) {
  if (-not (Under $Payload $L) -or (Split-Path $Payload -Leaf) -ne 'portable-payload') { throw "unexpected path $Payload" }
  Remove-Item -LiteralPath $Payload -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $Payload | Out-Null
$gitCommit = (git -C $RunetRoot rev-parse HEAD).Trim()
$gitDirty = [bool](git -C $RunetRoot status --porcelain)
$goVer = (& go version)
$buildDate = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
$goMods = @($lock.'go-modules'.PSObject.Properties | Where-Object { $_.Name -ne 'note' } | ForEach-Object { '{0} {1}  ({2})  h1:{3}' -f $_.Name, $_.Value.version, $_.Value.license, $_.Value.h1 })
$goModsText = "Third-party Go code compiled into the program (pinned in scripts/tools.lock.json, hashes as in go.sum):`r`n" + ($goMods -join "`r`n") + "`r`nThe licence texts are in the folders next to this file. The Outline SDK is used unmodified.`r`n"
$buildInfo = @"
Runet Access $Version (portable, one file)
Git commit: $gitCommit$(if ($gitDirty) { ' (build made from a tree with uncommitted changes)' })
Built: $buildDate
Go: $goVer
sing-box: $sbVer, unmodified official release, sing-box.exe SHA-256 $sbHash (embedded in the exe, unpacked and verified at run time)
Go libraries (compiled in): $($goMods -join '; ')
Signature: NONE (the program is not code-signed)
"@
$sbSrcHash = Get-Sha256 $sbSource
$plan = @(
  @{ Src = (Join-Path $DistApp 'sing-box.exe'); Dst = 'sing-box.exe' },
  @{ Text = $buildInfo; Dst = 'licenses/BUILD-INFO.txt'; Bom = $true },
  @{ Src = (Join-Path $RunetRoot 'LICENSE'); Dst = 'licenses/LICENSE.txt' },
  @{ Src = (Join-Path $RunetRoot 'THIRD_PARTY.md'); Dst = 'licenses/THIRD_PARTY.txt' },
  @{ Src = (Join-Path $RunetRoot 'third_party\MagicProxy\LICENSE'); Dst = 'licenses/MagicProxy/LICENSE.txt' },
  @{ Src = (Join-Path $L 'tools\go\LICENSE'); Dst = 'licenses/Go/LICENSE.txt' },
  @{ Text = $goModsText; Dst = 'licenses/go-modules.txt'; Bom = $true },
  @{ Src = (Join-Path $RunetRoot 'third_party\outline-sdk\LICENSE'); Dst = 'licenses/OutlineSDK/LICENSE.txt' },
  @{ Src = (Join-Path $RunetRoot 'third_party\go-shadowsocks2\LICENSE'); Dst = 'licenses/go-shadowsocks2/LICENSE.txt' },
  @{ Src = (Join-Path $RunetRoot 'third_party\golang-x\LICENSE'); Dst = 'licenses/golang-x/LICENSE.txt' },
  @{ Src = (Join-Path $RunetRoot 'third_party\golang-x\PATENTS'); Dst = 'licenses/golang-x/PATENTS.txt' },
  @{ Src = (Join-Path $RunetRoot 'third_party\sing-box\GPL-3.0.txt'); Dst = 'licenses/sing-box/GPL-3.0.txt' },
  @{ Src = (Join-Path $RunetRoot 'third_party\sing-box\LICENSE'); Dst = 'licenses/sing-box/LICENSE.txt' },
  @{ Src = (Join-Path $RunetRoot 'installer\SOURCE-OFFER.txt'); Dst = 'licenses/sing-box/SOURCE-OFFER.txt'; Bom = $true },
  @{ Text = "sing-box $($lock.'sing-box'.version) source archive`r`nFile: sing-box-1.13.16-source.tar.gz`r`nSHA-256: $sbSrcHash`r`nFrom: $($lock.'sing-box-source'.url)`r`nBinary: sing-box.exe SHA-256 $sbHash (official release zip SHA-256 $($lock.'sing-box'.sha256))`r`n"; Dst = 'licenses/sing-box/SOURCE-INFO.txt'; Bom = $true },
  @{ Src = $sbSource; Dst = 'licenses/sing-box/sing-box-1.13.16-source.tar.gz' }
)
$utf8Bom = New-Object Text.UTF8Encoding($true)
$manifest = New-Object System.Collections.Generic.List[string]
foreach ($e in $plan) {
  $dst = Join-Path $Payload ($e.Dst.Replace('/', '\'))
  New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
  if ($e.ContainsKey('Text')) { [IO.File]::WriteAllText($dst, $e.Text, $utf8Bom) }
  else {
    if (-not (Test-Path -LiteralPath $e.Src)) { throw "missing component: $($e.Src)" }
    if ($e.Bom) { [IO.File]::WriteAllText($dst, ([IO.File]::ReadAllText($e.Src, [Text.Encoding]::UTF8)), $utf8Bom) }
    else { Copy-Item -LiteralPath $e.Src -Destination $dst }
  }
  $manifest.Add(('{0}  {1}' -f (Get-Sha256 $dst), $e.Dst))
}
$expected = ($plan | ForEach-Object { $_.Dst.ToLowerInvariant() } | Sort-Object) -join '|'
$actualFiles = Get-ChildItem -LiteralPath $Payload -Recurse -File
$actual = ($actualFiles | ForEach-Object { $_.FullName.Substring($Payload.Length + 1).Replace('\', '/').ToLowerInvariant() } | Sort-Object) -join '|'
if ($expected -ne $actual) { throw "payload differs from the explicit list.`nexpected: $expected`nactual:   $actual" }
$coreHash = ($manifest | Where-Object { $_ -like '*  sing-box.exe' }) -replace '  .*$', ''
if ($coreHash -ne $sbHash) { throw 'payload core differs from the verified one' }
Write-Host "payload: $($actualFiles.Count) files, exactly the explicit list"

# ---------------------------------------------------------------- 4. secret scan of the payload (values never printed)
$needles = @()
foreach ($kf in '.local\secrets\test-key.txt', '.local\secrets\ssconf-key.txt') {
  $p = Join-Path $RunetRoot $kf
  if (-not (Test-Path $p)) { continue }
  $kt = [IO.File]::ReadAllText($p).Trim()
  foreach ($m in [regex]::Matches($kt, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')) { $needles += $m.Value.ToLowerInvariant() }
  $hm = [regex]::Match($kt, '(?:@|://)([^:/?#\s@]+)'); if ($hm.Success -and $hm.Groups[1].Value.Length -ge 6) { $needles += $hm.Groups[1].Value.ToLowerInvariant() }
  $core = ($kt -split '#')[0]; if ($core.Length -ge 20) { $needles += $core.ToLowerInvariant() }
}
$latin1 = [Text.Encoding]::GetEncoding(28591)
function Scan-Bytes($label, [byte[]]$bytes, [bool]$text) {
  $t = $latin1.GetString($bytes).ToLowerInvariant(); $n = 0
  foreach ($needle in $needles) { if ($t.Contains($needle)) { Write-Host "OWNER KEY MATERIAL in $label"; $n++ } }
  if ($text -and $t -match '(vless|trojan)://[^\s]*@|vmess://[a-z0-9+/=]{20,}|ss://[a-z0-9+/=]{16,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@') { Write-Host "SECRET-LIKE URI in $label"; $n++ }
  return $n
}
$hits = 0
foreach ($f in $actualFiles) {
  if ($f.Extension -eq '.gz' -or $f.Name -eq 'sing-box.exe') { continue }   # fixed by hash, not scanned
  $hits += Scan-Bytes $f.Name ([IO.File]::ReadAllBytes($f.FullName)) $true
}
if ($hits) { throw "secret scan failed ($hits findings); nothing was packaged" }

# ---------------------------------------------------------------- 5. payload zip (forward-slash names, manifest last)
if (-not (Under $EmbedDir $RunetRoot)) { throw 'bad embed path' }
New-Item -ItemType Directory -Force -Path $EmbedDir | Out-Null
$payloadZip = Join-Path $EmbedDir 'payload.zip'
if (Test-Path -LiteralPath $payloadZip) { Remove-Item -LiteralPath $payloadZip -Force }
$fs = [IO.File]::Open($payloadZip, 'CreateNew')
try {
  $zw = New-Object IO.Compression.ZipArchive($fs, [IO.Compression.ZipArchiveMode]::Create, $false)
  try {
    foreach ($e in $plan) {
      $src = Join-Path $Payload ($e.Dst.Replace('/', '\'))
      $ze = $zw.CreateEntry($e.Dst, [IO.Compression.CompressionLevel]::Optimal)
      $zs = $ze.Open(); $in = [IO.File]::OpenRead($src)
      try { $in.CopyTo($zs) } finally { $in.Dispose(); $zs.Dispose() }
    }
    $ze = $zw.CreateEntry('MANIFEST.sha256', [IO.Compression.CompressionLevel]::Optimal)
    $zs = $ze.Open()
    try { $b = (New-Object Text.UTF8Encoding($false)).GetBytes(($manifest -join "`n") + "`n"); $zs.Write($b, 0, $b.Length) } finally { $zs.Dispose() }
  } finally { $zw.Dispose() }
} finally { $fs.Dispose() }
$payloadHash = Get-Sha256 $payloadZip
Write-Host "payload.zip: $([math]::Round((Get-Item $payloadZip).Length/1MB,1)) MB, sha256 $($payloadHash.Substring(0,16))..."

# ---------------------------------------------------------------- 6. the portable exe
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if (Test-Path -LiteralPath $exePath) { Remove-Item -LiteralPath $exePath -Force }   # a failed build must not leave an old file
Push-Location $GoDir
try {
  go run ./cmd/genrsrc cmd/launcher/rsrc_windows_amd64.syso; if ($LASTEXITCODE) { throw 'genrsrc failed' }
  go build -tags portable -trimpath -ldflags "-H=windowsgui -X main.version=$Version -X main.payloadSHA256=$payloadHash -X main.coreSHA256=$sbHash" -o $exePath ./cmd/launcher
  if ($LASTEXITCODE) { throw 'go build -tags portable failed' }
} finally {
  Pop-Location
  if (Test-Path -LiteralPath $payloadZip) { Remove-Item -LiteralPath $payloadZip -Force }   # generated file: not left in the source tree
}
if (-not (Test-Path -LiteralPath $exePath)) { throw 'build reported success but no exe exists' }
if ((Get-Item -LiteralPath $exePath).LastWriteTime -lt $started) { throw 'exe is older than this run' }
$exeBytes = [IO.File]::ReadAllBytes($exePath)
$n = Scan-Bytes $exeName $exeBytes $false
$t = $latin1.GetString($exeBytes)
foreach ($bad in 'D:\AI-workspaces', 'Aleksandr', '\.local\') { if ($t.Contains($bad)) { Write-Host "personal/dev path '$bad' found in the exe"; $n++ } }
if ($n) { Remove-Item -LiteralPath $exePath -Force; throw "exe scan failed ($n findings); the exe was deleted" }
$exeHash = Get-Sha256 $exePath
Write-Host "exe scan: clean ($($needles.Count) key fingerprints checked, no personal paths)"

# ---------------------------------------------------------------- 7. next to the exe: SHA-256 and the instruction
$sumPath = Join-Path $OutDir "RunetAccess-Portable-$Version.sha256.txt"
[IO.File]::WriteAllText($sumPath, "$exeHash  $exeName`n", (New-Object Text.UTF8Encoding($false)))
$instrName = [string]::new([char[]](0x418, 0x43d, 0x441, 0x442, 0x440, 0x443, 0x43a, 0x446, 0x438, 0x44f)) + '-Portable.txt'   # "Instruction-Portable.txt" in Russian
$instrText = [IO.File]::ReadAllText((Join-Path $RunetRoot 'portable\Instruction-RU.txt'), [Text.Encoding]::UTF8).Replace('@VERSION@', $Version).Replace("`r`n", "`n").Replace("`n", "`r`n")
[IO.File]::WriteAllText((Join-Path $OutDir $instrName), $instrText, $utf8Bom)
$size = (Get-Item -LiteralPath $exePath).Length
Write-Host "portable: $exePath"
Write-Host "  size $size bytes, sha256 $exeHash"
Write-Host "  commit $gitCommit$(if ($gitDirty) { ' (DIRTY tree)' })"
Write-Host "  next to it: $(Split-Path $sumPath -Leaf), $instrName"

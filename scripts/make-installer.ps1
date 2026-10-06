# Builds the Windows installer: dist\installer\RunetAccess-Setup-<version>.exe
#
#   .\scripts\make-installer.ps1
#
# What it does, and refuses to continue when any step fails:
#   1. makes sure the pinned Inno Setup compiler is present (hash + Authenticode checked) inside .local\tools
#   2. runs the normal build (scripts\build.ps1: gofmt, vet, tests, go build) and checks the exe is NEW
#   3. verifies sing-box.exe really is the pinned release (extracted again from the pinned zip, compared)
#   4. stages ONLY an explicit list of files into dist\installer-staging\app and compares the result with that list
#   5. scans the staging for key material / secrets (without printing values)
#   6. compiles installer\RunetAccess.iss, then writes SHA256SUMS, the file list and BUILD-INFO
#
# Test-only switches (used by tests\installer-check.ps1): -VersionOverride, -DataDir, -OutDir, -OutName,
# -SkipBuild (reuse the dist\runet-access built by the previous full run), -Test.
param(
  [string]$OutDir,
  [string]$VersionOverride,
  [string]$DataDir,
  [string]$OutName,
  [switch]$SkipBuild,
  [switch]$Test
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\env.ps1"
$started = Get-Date
$lock = Get-Content (Join-Path $PSScriptRoot 'tools.lock.json') -Raw | ConvertFrom-Json
$Version = (Get-Content (Join-Path $RunetRoot 'VERSION') -Raw).Trim()
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "bad VERSION: $Version" }
$AppVersion = if ($VersionOverride) { $VersionOverride } else { $Version }
if ($AppVersion -notmatch '^\d+\.\d+\.\d+$') { throw "bad version: $AppVersion" }
if (-not $OutDir) { $OutDir = Join-Path $RunetRoot 'dist\installer' }
if (-not $OutName) { $OutName = "RunetAccess-Setup-$AppVersion" }
$dl = Join-Path $L 'cache\downloads'
$DistApp = Join-Path $RunetRoot 'dist\runet-access'
$Stage = Join-Path $RunetRoot 'dist\installer-staging'

function Get-Sha256($path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() }
function Invoke-Checked($exe, [string[]]$arguments) {
  & $exe @arguments
  if ($LASTEXITCODE -ne 0) { throw "$exe failed with exit code $LASTEXITCODE" }
}
function Under($child, $parent) { [IO.Path]::GetFullPath($child).StartsWith([IO.Path]::GetFullPath($parent).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) }

# ---------------------------------------------------------------- 1. Inno Setup
$innoLock = $lock.innosetup
$innoDir = Join-Path $L 'tools\innosetup'
$iscc = Join-Path $innoDir 'ISCC.exe'
if (-not (Test-Path $iscc)) {
  $setup = Join-Path $dl ([IO.Path]::GetFileName($innoLock.url))
  if (-not (Test-Path $setup)) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host "downloading Inno Setup $($innoLock.version) ..."
    Invoke-WebRequest -Uri $innoLock.url -OutFile $setup -UseBasicParsing -Headers @{ 'User-Agent' = 'runet-access' }
  }
  if ((Get-Sha256 $setup) -ne $innoLock.sha256) { throw 'Inno Setup installer: SHA256 mismatch' }
  $sig = Get-AuthenticodeSignature $setup
  if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike "*$($innoLock.signer)*") { throw "Inno Setup installer: bad signature ($($sig.Status))" }
  Write-Host 'installing Inno Setup into .local\tools (current user, no admin)'
  $p = Start-Process -FilePath $setup -ArgumentList @('/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/CURRENTUSER', '/NOICONS', "/DIR=$innoDir") -Wait -PassThru
  if ($p.ExitCode -ne 0 -or -not (Test-Path $iscc)) { throw "Inno Setup install failed ($($p.ExitCode))" }
}
# the installed compiler must be byte-identical to the one verified at pinning time
foreach ($prop in $innoLock.installed_files_sha256.PSObject.Properties) {
  $f = Join-Path $innoDir $prop.Name
  if (-not (Test-Path $f) -or (Get-Sha256 $f) -ne $prop.Value) { throw "Inno Setup file $($prop.Name) differs from the pinned installation" }
}
$innoVersion = $innoLock.version
Write-Host "Inno Setup $innoVersion OK (compiler files match the pinned hashes)"

# ---------------------------------------------------------------- 2. build
$sbSource = Join-Path $dl ([IO.Path]::GetFileName('sing-box-1.13.16-source.tar.gz'))
if (-not (Test-Path $sbSource)) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Write-Host 'downloading the sing-box source archive ...'
  Invoke-WebRequest -Uri $lock.'sing-box-source'.url -OutFile $sbSource -UseBasicParsing -Headers @{ 'User-Agent' = 'runet-access' }
}
if ((Get-Sha256 $sbSource) -ne $lock.'sing-box-source'.sha256) { throw 'sing-box source archive: SHA256 mismatch with tools.lock.json' }

$exe = Join-Path $DistApp 'RunetAccess.exe'
if (-not $SkipBuild) {
  & (Join-Path $PSScriptRoot 'build.ps1')   # throws on any failure; removes the old dist first
  . "$PSScriptRoot\env.ps1"
  if ((Get-Item $exe).LastWriteTime -lt $started) { throw 'RunetAccess.exe is older than this run: refusing to package a stale build' }
} elseif (-not (Test-Path $exe)) { throw 'SkipBuild: dist\runet-access\RunetAccess.exe does not exist' }

# ---------------------------------------------------------------- 3. sing-box provenance
$zip = Join-Path $dl ([IO.Path]::GetFileName($lock.'sing-box'.url))
if (-not (Test-Path $zip) -or (Get-Sha256 $zip) -ne $lock.'sing-box'.sha256) { throw 'pinned sing-box zip missing or SHA256 mismatch (run scripts\fetch-tools.ps1)' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
$tmpSb = Join-Path $L 'tmp\sb-verify.exe'
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

# ---------------------------------------------------------------- 4. staging from an explicit list
$instr = @(Get-ChildItem (Join-Path $RunetRoot 'installer') -Filter '*.txt' | Where-Object { $_.Name -ne 'info-before.txt' -and $_.Name -ne 'SOURCE-OFFER.txt' })
if ($instr.Count -ne 1) { throw 'expected exactly one instruction .txt in installer\' }
$instrName = [string]::new([char[]](0x418, 0x43d, 0x441, 0x442, 0x440, 0x443, 0x43a, 0x446, 0x438, 0x44f)) + '.txt'   # the Russian word for "Instruction"
if ($instr[0].Name -ne $instrName) { throw "instruction file must be named $instrName (the .iss refers to it)" }

if (Test-Path -LiteralPath $Stage) {
  if (-not (Under $Stage (Join-Path $RunetRoot 'dist')) -or (Split-Path $Stage -Leaf) -ne 'installer-staging') { throw "unexpected staging path $Stage" }
  Remove-Item -LiteralPath $Stage -Recurse -Force
}
$app = Join-Path $Stage 'app'
New-Item -ItemType Directory -Force -Path $app | Out-Null

# git state
$gitCommit = (git -C $RunetRoot rev-parse HEAD).Trim()
$gitDirty = [bool](git -C $RunetRoot status --porcelain)
$goVer = (& go version)
$buildDate = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + ' UTC'
$sbSrcHash = Get-Sha256 $sbSource
$buildInfo = @"
Runet Access $AppVersion
Git commit: $gitCommit$(if ($gitDirty) { ' (build made from a tree with uncommitted changes)' })
Built: $buildDate
Go: $goVer
sing-box: $sbVer, unmodified official release, sing-box.exe SHA-256 $sbHash
Installer compiler: Inno Setup $innoVersion
Signature: NONE (the installer and the programs are not code-signed)
"@

# every entry: source file (or text), relative destination, whether to add a UTF-8 BOM
$plan = @(
  @{ Src = $exe; Dst = 'RunetAccess.exe' },
  @{ Src = (Join-Path $DistApp 'sing-box.exe'); Dst = 'sing-box.exe' },
  @{ Src = $instr[0].FullName; Dst = $instrName; Bom = $true },
  @{ Text = $buildInfo; Dst = 'BUILD-INFO.txt'; Bom = $true },
  @{ Src = (Join-Path $RunetRoot 'LICENSE'); Dst = 'licenses\LICENSE.txt' },
  @{ Src = (Join-Path $RunetRoot 'THIRD_PARTY.md'); Dst = 'licenses\THIRD_PARTY.txt' },
  @{ Src = (Join-Path $RunetRoot 'third_party\MagicProxy\LICENSE'); Dst = 'licenses\MagicProxy\LICENSE.txt' },
  @{ Src = (Join-Path $L 'tools\go\LICENSE'); Dst = 'licenses\Go\LICENSE.txt' },
  @{ Src = (Join-Path $RunetRoot 'third_party\sing-box\GPL-3.0.txt'); Dst = 'licenses\sing-box\GPL-3.0.txt' },
  @{ Src = (Join-Path $RunetRoot 'third_party\sing-box\LICENSE'); Dst = 'licenses\sing-box\LICENSE.txt' },
  @{ Src = (Join-Path $RunetRoot 'installer\SOURCE-OFFER.txt'); Dst = 'licenses\sing-box\SOURCE-OFFER.txt'; Bom = $true },
  @{ Text = "sing-box $($lock.'sing-box'.version) source archive`r`nFile: sing-box-1.13.16-source.tar.gz`r`nSHA-256: $sbSrcHash`r`nFrom: $($lock.'sing-box-source'.url)`r`nBinary: sing-box.exe SHA-256 $sbHash (official release zip SHA-256 $($lock.'sing-box'.sha256))`r`n"; Dst = 'licenses\sing-box\SOURCE-INFO.txt'; Bom = $true },
  @{ Src = $sbSource; Dst = 'licenses\sing-box\sing-box-1.13.16-source.tar.gz' }
)
$utf8Bom = New-Object Text.UTF8Encoding($true)
foreach ($e in $plan) {
  $dst = Join-Path $app $e.Dst
  New-Item -ItemType Directory -Force -Path (Split-Path $dst) | Out-Null
  if ($e.ContainsKey('Text')) { [IO.File]::WriteAllText($dst, $e.Text, $utf8Bom) }
  else {
    if (-not (Test-Path -LiteralPath $e.Src)) { throw "missing component: $($e.Src)" }
    if ($e.Bom) { [IO.File]::WriteAllText($dst, ([IO.File]::ReadAllText($e.Src, [Text.Encoding]::UTF8)), $utf8Bom) }
    else { Copy-Item -LiteralPath $e.Src -Destination $dst }
  }
}
$expected = ($plan | ForEach-Object { $_.Dst.ToLowerInvariant() } | Sort-Object) -join '|'
$actualFiles = Get-ChildItem -LiteralPath $app -Recurse -File
$actual = ($actualFiles | ForEach-Object { $_.FullName.Substring($app.Length + 1).ToLowerInvariant() } | Sort-Object) -join '|'
if ($expected -ne $actual) { throw "staging differs from the explicit list.`nexpected: $expected`nactual:   $actual" }
$allowedExt = '.exe', '.txt', '.gz', ''
foreach ($f in $actualFiles) { if ($allowedExt -notcontains $f.Extension.ToLowerInvariant()) { throw "unexpected file type in staging: $($f.Name)" } }
Write-Host "staging: $($actualFiles.Count) files, exactly the explicit list"

# ---------------------------------------------------------------- 5. secret / personal data scan (values never printed)
$needles = @()
$ownerKey = Join-Path $RunetRoot '.local\secrets\test-key.txt'
if (Test-Path $ownerKey) {
  $kt = [IO.File]::ReadAllText($ownerKey)
  foreach ($m in [regex]::Matches($kt, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')) { $needles += $m.Value.ToLowerInvariant() }
  $hm = [regex]::Match($kt, '@([^:/?#\s]+)'); if ($hm.Success) { $needles += $hm.Groups[1].Value.ToLowerInvariant() }
}
$latin1 = [Text.Encoding]::GetEncoding(28591)
$hits = 0
foreach ($f in $actualFiles) {
  if ($f.Extension -eq '.gz') { continue }   # compressed upstream source: fixed by hash, not scanned
  $bytes = [IO.File]::ReadAllBytes($f.FullName)
  $text = $latin1.GetString($bytes).ToLowerInvariant()
  if ($f.Extension -eq '.txt' -or $f.Extension -eq '') {
    if ($text -match '(vless|trojan)://[^\s]*@|vmess://[a-z0-9+/=]{20,}|ss://[a-z0-9+/=]{16,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}@') { Write-Host "SECRET-LIKE URI in $($f.Name)"; $hits++ }
  }
  foreach ($n in $needles) { if ($text.Contains($n)) { Write-Host "OWNER KEY MATERIAL found in $($f.Name)"; $hits++ } }
  if ($f.Name -match '\.(dpapi|key|pem|pfx|p12|json|log|db)$') { Write-Host "forbidden file $($f.Name)"; $hits++ }
}
if ($hits) { throw "secret scan failed ($hits findings); nothing was packaged" }
Write-Host "secret scan: clean ($($needles.Count) owner key fingerprints checked, none found)"

# ---------------------------------------------------------------- 6. compile
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$setupExe = Join-Path $OutDir ($OutName + '.exe')
if (Test-Path -LiteralPath $setupExe) { Remove-Item -LiteralPath $setupExe -Force }   # a failed compile must not leave an old installer
$isccArgs = @('/Q', "/DAppVersion=$AppVersion", "/DStagingDir=$Stage", "/DOutDir=$OutDir", "/DOutName=$OutName")
if ($DataDir) { $isccArgs += "/DDataDir=$DataDir" }
$isccArgs += (Join-Path $RunetRoot 'installer\RunetAccess.iss')
Invoke-Checked $iscc $isccArgs
if (-not (Test-Path -LiteralPath $setupExe)) { throw 'ISCC reported success but no installer exists' }
if ((Get-Item -LiteralPath $setupExe).LastWriteTime -lt $started) { throw 'installer is older than this run' }
$setupHash = Get-Sha256 $setupExe
$setupSize = (Get-Item -LiteralPath $setupExe).Length
Write-Host "installer: $setupExe ($([math]::Round($setupSize/1MB,1)) MB) sha256 $setupHash"
if ($Test) { return }

# ---------------------------------------------------------------- 7. release files
$sigState = (Get-AuthenticodeSignature $setupExe).Status
$lines = $actualFiles | Sort-Object FullName | ForEach-Object { '{0}  {1,12}  {2}' -f (Get-Sha256 $_.FullName), $_.Length, $_.FullName.Substring($app.Length + 1).Replace('\', '/') }
[IO.File]::WriteAllText((Join-Path $OutDir "$OutName.contents.txt"), ("# Files installed into the application folder (sha256, bytes, path)`n" + ($lines -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))
$info = [ordered]@{
  product = 'Runet Access'; version = $AppVersion; installer = ($OutName + '.exe'); installerBytes = $setupSize; installerSha256 = $setupHash
  authenticode = [string]$sigState; gitCommit = $gitCommit; gitDirty = $gitDirty; builtUtc = $buildDate
  go = $goVer; singBox = $sbVer; singBoxSha256 = $sbHash; singBoxSourceSha256 = $sbSrcHash; innoSetup = $innoVersion
}
[IO.File]::WriteAllText((Join-Path $OutDir "$OutName.build-info.json"), (($info | ConvertTo-Json) + "`n"), (New-Object Text.UTF8Encoding($false)))
$sums = @($setupExe, (Join-Path $OutDir "$OutName.contents.txt"), (Join-Path $OutDir "$OutName.build-info.json")) | ForEach-Object { '{0}  {1}' -f (Get-Sha256 $_), (Split-Path $_ -Leaf) }
[IO.File]::WriteAllText((Join-Path $OutDir 'SHA256SUMS.txt'), (($sums -join "`n") + "`n"), (New-Object Text.UTF8Encoding($false)))
Write-Host "done: $setupExe"

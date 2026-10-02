# Downloads portable build tools into .local/tools, verifying pinned SHA256.
. "$PSScriptRoot\env.ps1"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$lock = Get-Content (Join-Path $PSScriptRoot 'tools.lock.json') -Raw | ConvertFrom-Json
$dl = Join-Path $L 'cache\downloads'
function Get-Verified($name, $entry) {
  $zip = Join-Path $dl ([IO.Path]::GetFileName($entry.url))
  if (-not (Test-Path $zip)) {
    Write-Host "downloading $name $($entry.version) ..."
    Invoke-WebRequest -Uri $entry.url -OutFile $zip -UseBasicParsing -Headers @{ 'User-Agent' = 'runet-access' }
  }
  $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($actual -ne $entry.sha256) { Remove-Item $zip; throw "$name SHA256 mismatch: got $actual, pinned $($entry.sha256)" }
  Write-Host "$name sha256 OK"
  return $zip
}
$goZip = Get-Verified 'go' $lock.go
$goDir = Join-Path $L 'tools\go'
if (-not (Test-Path (Join-Path $goDir 'bin\go.exe'))) {
  $tmp = Join-Path $L 'tmp\go-extract'
  if (Test-Path $tmp) { throw "stale $tmp, inspect manually" }
  Expand-Archive $goZip $tmp
  Move-Item (Join-Path $tmp 'go') $goDir
  [IO.Directory]::Delete($tmp, $false)
}
$sbZip = Get-Verified 'sing-box' $lock.'sing-box'
$sbDir = Join-Path $L 'tools\sing-box'
if (-not (Test-Path (Join-Path $sbDir 'sing-box.exe'))) {
  $tmp = Join-Path $L 'tmp\sb-extract'
  if (Test-Path $tmp) { throw "stale $tmp, inspect manually" }
  Expand-Archive $sbZip $tmp
  New-Item -ItemType Directory -Force $sbDir | Out-Null
  $exe = Get-ChildItem $tmp -Recurse -Filter sing-box.exe | Select-Object -First 1
  Copy-Item $exe.FullName (Join-Path $sbDir 'sing-box.exe')
  Remove-Item $tmp -Recurse -Force
}
Write-Host "tools ready under $L\tools"

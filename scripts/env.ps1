# Dot-source this file before any build/test step:  . .\scripts\env.ps1
# Redirects every tool cache/temp path used by this project into the repo root.
# Does NOT touch HOME / USERPROFILE / global PATH of the machine (session only).
$ErrorActionPreference = 'Stop'
$script:RunetRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$L = Join-Path $RunetRoot '.local'
foreach ($d in 'tools','cache','tmp','logs','browser-profile','cache\go-build','cache\go-mod','cache\go-path','cache\downloads','cache\npm') {
  New-Item -ItemType Directory -Force -Path (Join-Path $L $d) | Out-Null
}
$env:TEMP        = Join-Path $L 'tmp'
$env:TMP         = $env:TEMP
$env:GOTMPDIR    = $env:TEMP
$env:GOPATH      = Join-Path $L 'cache\go-path'
$env:GOCACHE     = Join-Path $L 'cache\go-build'
$env:GOMODCACHE  = Join-Path $L 'cache\go-mod'
$env:APPDATA      = Join-Path $L 'cache\appdata'    # Go telemetry etc. (session only)
New-Item -ItemType Directory -Force $env:APPDATA | Out-Null
$env:GOENV       = Join-Path $L 'cache\go-env'      # keeps %APPDATA%\go out of play
$env:GOTOOLCHAIN = 'local'                           # never auto-download another toolchain
$env:GOFLAGS     = '-mod=mod'
$env:GOPROXY     = 'off'                             # host has no third-party deps
$env:GONOSUMDB   = '*'
$env:npm_config_cache = Join-Path $L 'cache\npm'
$env:NODE_OPTIONS = ''
$GoRoot = Join-Path $L 'tools\go'
if (Test-Path (Join-Path $GoRoot 'bin\go.exe')) {
  $env:GOROOT = $GoRoot
  $env:PATH = (Join-Path $GoRoot 'bin') + ';' + $env:PATH   # this session only
}
Write-Host "runet-access env: root=$RunetRoot"

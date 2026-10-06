# Runs the general end-to-end test (tests\launcher-e2e.mjs). Start it through tests\run-hidden.ps1 to keep the windows off the screen.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\scripts\env.ps1"
& node (Join-Path $RunetRoot 'tests\launcher-e2e.mjs')
exit $LASTEXITCODE

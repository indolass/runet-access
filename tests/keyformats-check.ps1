# Runs tests\keyformats-e2e.mjs (key formats in a real Chrome). Start it through tests\run-hidden.ps1 to keep the windows off the screen.
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\scripts\env.ps1"
$env:RUNET_TEST_MODE = $null   # the node script sets the variables for the program itself
& node (Join-Path $RunetRoot 'tests\keyformats-e2e.mjs')
exit $LASTEXITCODE

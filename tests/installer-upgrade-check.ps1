# Update check: the REAL previous installer (0.3.0) -> the REAL new one, data kept. Silent installs, no windows of the installer.
#
#   . .\scripts\env.ps1; .\tests\run-hidden.ps1 tests\installer-upgrade-check.ps1
#
# Where things happen (be exact about it):
#   - the program is installed into the project: .local\upgrade-test\<Cyrillic> s probelami\Runet Access;
#   - the REAL user-data folder %LOCALAPPDATA%\RunetAccess receives a few clearly named SYNTHETIC files (a fake key.dpapi, a fake
#     profile file, a note) to prove that an update and an uninstall keep user data. The script refuses to run if that folder
#     already exists (it would be somebody's real data) and removes exactly the files it created;
#   - the REAL Start-menu / desktop shortcuts and the HKCU uninstall entry are created and removed by the installer itself.
# NOT a clean Windows: developer tools are on this machine; see docs\LIMITATIONS.md.
param([string]$Old, [string]$New)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\scripts\env.ps1"
$Ver = (Get-Content (Join-Path $RunetRoot 'VERSION') -Raw).Trim()
if (-not $New) { $New = Join-Path $RunetRoot "dist\installer\RunetAccess-Setup-$Ver.exe" }
if (-not $Old) { $Old = Join-Path $RunetRoot 'dist\installer\RunetAccess-Setup-0.3.0.exe' }
foreach ($f in $Old, $New) { if (-not (Test-Path $f)) { throw "missing installer: $f" } }
$OldVersion = [regex]::Match([IO.Path]::GetFileName($Old), '\d+\.\d+\.\d+').Value   # the version the old installer must report
$Work = Join-Path $RunetRoot '.local\upgrade-test'
$data = Join-Path $env:LOCALAPPDATA 'RunetAccess'
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{B7E2C1A4-5D3F-4E8B-9A16-0C4D7F2E6A31}_is1'
function Cyr([int[]]$c) { [string]::new([char[]]$c) }
$InstallDir = Join-Path $Work ((Cyr 0x41f, 0x443, 0x442, 0x44c) + ' s probelami\Runet Access')
$AppExe = Join-Path $InstallDir 'RunetAccess.exe'
if (Test-Path $key) { throw 'a Runet Access installation already exists: refusing to touch it' }
if (Test-Path $data) { throw "$data exists (real user data): refusing to run" }
if (Test-Path $Work) { if ((Split-Path $Work -Leaf) -ne 'upgrade-test') { throw 'bad path' }; Remove-Item -LiteralPath $Work -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Work | Out-Null

Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class UG {
  delegate bool CB(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] static extern bool EnumWindows(CB cb, IntPtr l);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
  public static IntPtr Dialog(int pid) { IntPtr f = IntPtr.Zero;
    EnumWindows((h, l) => { uint p; GetWindowThreadProcessId(h, out p); if (p != pid || !IsWindowVisible(h)) return true;
      var c = new StringBuilder(64); GetClassName(h, c, 64); if (c.ToString() == "#32770") { f = h; return false; } return true; }, IntPtr.Zero);
    return f; }
}
'@
$script:pass = 0; $script:fail = 0
function Check($name, [scriptblock]$body) {
  try { $r = @(& $body); if ($r.Count -eq 0 -or $r[-1] -eq $false) { throw 'condition is false' }; $script:pass++; Write-Host "PASS  $name" }
  catch { $script:fail++; Write-Host "FAIL  $name`n      $($_.Exception.Message)" }
}
function Sha($p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower() }
function Run-Setup($exe) { (Start-Process -FilePath $exe -ArgumentList ('/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /NOCANCEL /TASKS=desktopicon /DIR="' + $InstallDir + '"') -Wait -PassThru).ExitCode }
function Lnks($dir) { @(Get-ChildItem -LiteralPath $dir -Filter 'Runet Access*.lnk' -ErrorAction SilentlyContinue) }
$programs = [Environment]::GetFolderPath('Programs'); $desktop = [Environment]::GetFolderPath('Desktop')
function ProxyState() { (reg query 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Where-Object { $_ -match 'Proxy|AutoConfig|AutoDetect' } | Sort-Object) -join '|' }
$proxy0 = ProxyState; $lnk0 = (Lnks $programs).Count + (Lnks $desktop).Count
$sentinels = @{ 'key.dpapi' = [byte[]](1..220); 'profile\Default\Preferences' = [Text.Encoding]::UTF8.GetBytes('synthetic profile (update test)'); 'upgrade-test-note.txt' = [Text.Encoding]::UTF8.GetBytes('created by installer-upgrade-check.ps1; safe to delete') }

try {
  Check 'old version installs (silent, ordinary user, path with spaces and Cyrillic)' {
    if ((Run-Setup $Old) -ne 0) { throw 'setup failed' }
    $k = Get-ItemProperty $key; if ($k.DisplayVersion -ne $OldVersion) { throw "version $($k.DisplayVersion)" }
    Test-Path $AppExe
  }
  $oldExeHash = Sha $AppExe; $oldInfo = Sha (Join-Path $InstallDir 'BUILD-INFO.txt')
  foreach ($rel in $sentinels.Keys) { $f = Join-Path $data $rel; New-Item -ItemType Directory -Force -Path (Split-Path $f) | Out-Null; [IO.File]::WriteAllBytes($f, $sentinels[$rel]) }
  $before = @{}; foreach ($rel in $sentinels.Keys) { $before[$rel] = Sha (Join-Path $data $rel) }

  Check "update $Ver installs over the old one in the same folder (shortcut choice kept)" {
    if ((Run-Setup $New) -ne 0) { throw 'setup failed' }
    $k = Get-ItemProperty $key; if ($k.DisplayVersion -ne $Ver) { throw "version after update: $($k.DisplayVersion)" }
    if ((Sha (Join-Path $InstallDir 'BUILD-INFO.txt')) -eq $oldInfo) { throw 'BUILD-INFO.txt was not replaced' }
    $true
  }
  Check 'the program file is the new build and the installed list matches the package exactly' {
    $dist = Join-Path $RunetRoot 'dist\runet-access\RunetAccess.exe'
    if ((Sha $AppExe) -ne (Sha $dist)) { throw 'installed exe differs from dist' }
    if ((Sha $AppExe) -eq $oldExeHash) { throw 'the exe was not replaced' }
    $contents = Get-Content (Join-Path $RunetRoot "dist\installer\RunetAccess-Setup-$Ver.contents.txt") -Encoding utf8 | Where-Object { $_ -notlike '#*' }
    $bad = @(); foreach ($l in $contents) { $m = [regex]::Match($l, '^([0-9a-f]{64})\s+(\d+)\s+(.+)$'); $f = Join-Path $InstallDir $m.Groups[3].Value.Replace('/', '\'); if (-not (Test-Path -LiteralPath $f) -or (Sha $f) -ne $m.Groups[1].Value) { $bad += $m.Groups[3].Value } }
    if ($bad) { throw "mismatch: $($bad -join ', ')" }
    $extra = @(Get-ChildItem -LiteralPath $InstallDir -Recurse -File | Where-Object { $_.Name -notlike 'unins000.*' }).Count
    if ($extra -ne @($contents).Count) { throw "installed $extra files, package has $(@($contents).Count)" }
    $true
  }
  Check 'still ONE entry in Apps and no duplicate shortcuts' {
    $n = @(Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall' | Where-Object { (Get-ItemProperty $_.PSPath).DisplayName -like 'Runet Access*' }).Count
    if ($n -ne 1) { throw "Apps entries: $n" }
    ((Lnks $programs).Count + (Lnks $desktop).Count) - $lnk0 -eq 3
  }
  Check 'user data (key, profile, note) is untouched by the update, byte for byte' {
    foreach ($rel in $sentinels.Keys) { if ((Sha (Join-Path $data $rel)) -ne $before[$rel]) { throw "changed: $rel" } }
    $true
  }
  Check 'ORDINARY launch of the updated program (no test variables): Chrome found, no window asks for it, our Chrome starts' {
    $saved = @{}; foreach ($v in 'RUNET_TEST_MODE', 'RUNET_CHROME_PATH', 'RUNET_NO_DIALOG') { $saved[$v] = (Get-Item "Env:\$v" -ErrorAction SilentlyContinue).Value; Set-Item "Env:\$v" $null }
    $home2 = Join-Path $Work 'run-home'; $env:RUNET_ACCESS_HOME = $home2
    try {
      $p = Start-Process -FilePath $AppExe -PassThru; Start-Sleep 8; $p.Refresh()
      if ($p.HasExited) { throw "the launcher exited (code $($p.ExitCode))" }
      if ([UG]::Dialog($p.Id) -ne [IntPtr]::Zero) { throw 'a dialog appeared' }
      $ours = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'chrome.exe' -and $_.CommandLine -and $_.CommandLine.IndexOf($home2, [StringComparison]::OrdinalIgnoreCase) -ge 0 })
      if ($ours.Count -lt 1) { throw 'our Chrome did not start' }
      Write-Host "      Chrome used: $(($ours | Select-Object -First 1).ExecutablePath)"
      $p.Kill(); Start-Sleep 3
      $true
    } finally { Remove-Item Env:\RUNET_ACCESS_HOME -ErrorAction SilentlyContinue; foreach ($v in $saved.Keys) { Set-Item "Env:\$v" $saved[$v] } }
  }
  Check 'the UPDATED program takes the new key formats end to end (key-formats e2e against the installed copy)' {
    $log = Join-Path $RunetRoot '.local\logs\upgrade-keyformats.txt'
    $env:RUNET_EXE = $AppExe
    try { & (Get-Command node).Source (Join-Path $RunetRoot 'tests\keyformats-e2e.mjs') *> $log } finally { Remove-Item Env:\RUNET_EXE }
    $last = Get-Content $log -Encoding utf8 | Where-Object { $_ -match 'passed,' } | Select-Object -Last 1
    if ($last -notmatch '^(\d+) passed, 0 failed') { throw "result: $last (see .local\logs\upgrade-keyformats.txt)" }
    $Matches[1] -ge 26
  }
  Check 'the UPDATED program carries Outline-prefix keys end to end (prefix e2e against the installed copy)' {
    $log = Join-Path $RunetRoot '.local\logs\upgrade-prefix.txt'
    $env:RUNET_EXE = $AppExe
    try { & (Get-Command node).Source (Join-Path $RunetRoot 'tests\prefix-e2e.mjs') *> $log } finally { Remove-Item Env:\RUNET_EXE }
    $last = Get-Content $log -Encoding utf8 | Where-Object { $_ -match 'passed,' } | Select-Object -Last 1
    if ($last -notmatch '^(\d+) passed, 0 failed') { throw "result: $last (see .local\logs\upgrade-prefix.txt)" }
    $Matches[1] -ge 16
  }
  Check 'uninstall (default answer): program, shortcuts and the Apps entry are gone; user data is KEPT' {
    $u = Join-Path $InstallDir 'unins000.exe'
    $p = Start-Process -FilePath $u -ArgumentList '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART' -Wait -PassThru; Start-Sleep -Milliseconds 2500
    if (Test-Path $key) { throw 'Apps entry remains' }
    if (Test-Path -LiteralPath $AppExe) { throw 'exe remains' }
    if (((Lnks $programs).Count + (Lnks $desktop).Count) -ne $lnk0) { throw 'shortcuts remain' }
    foreach ($rel in $sentinels.Keys) { if ((Sha (Join-Path $data $rel)) -ne $before[$rel]) { throw "data lost or changed: $rel" } }
    $true
  }
  Check 'system proxy unchanged' { (ProxyState) -eq $proxy0 }
} finally {
  # remove exactly what this script created in the real data folder, then the folder if it is empty again
  foreach ($rel in $sentinels.Keys) { $f = Join-Path $data $rel; if (Test-Path -LiteralPath $f) { [IO.File]::Delete($f) } }
  foreach ($d in (Join-Path $data 'profile\Default'), (Join-Path $data 'profile'), $data) { if ((Test-Path $d) -and @(Get-ChildItem $d -Force).Count -eq 0) { [IO.Directory]::Delete($d, $false) } }
  if (Test-Path $key) { # a failed run: take the installation away again with its own uninstaller
    $u = Join-Path $InstallDir 'unins000.exe'; if (Test-Path $u) { Start-Process -FilePath $u -ArgumentList '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART' -Wait }
  }
}
Write-Host "`n$script:pass passed, $script:fail failed"
if ($script:fail) { exit 1 }

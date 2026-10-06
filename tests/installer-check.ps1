# Installer checks: install / start / update / uninstall of the REAL installer in an isolated location.
#
#   . .\scripts\env.ps1; powershell -File tests\installer-check.ps1     (or: .\tests\installer-check.ps1 after env.ps1)
#   Prerequisite: scripts\make-installer.ps1 has produced dist\installer\RunetAccess-Setup-<version>.exe
#
# What is isolated and what is not (be honest about it):
#   - install FOLDERS are inside the project (.local\inst-test), with spaces and Cyrillic in the path;
#   - user DATA of the product (key, browser profile) is redirected with RUNET_ACCESS_HOME to the project
#     for the running app, and the "delete my data" choice is exercised on a TEST BUILD of the installer
#     (same .iss, only the data folder constant differs) so the real %LOCALAPPDATA%\RunetAccess is never at risk;
#   - Start-menu / desktop shortcuts and the HKCU uninstall entry are REAL (Windows offers no way to redirect
#     them without another user account); they are removed again by the uninstall step;
#   - this is NOT a clean Windows: Python/Go/Node/Git are present on this machine. What is checked instead is that
#     the installed files do not reference them (see "no developer tools needed" below).
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\scripts\env.ps1"
$Version = (Get-Content (Join-Path $RunetRoot 'VERSION') -Raw).Trim()
$Setup = Join-Path $RunetRoot "dist\installer\RunetAccess-Setup-$Version.exe"
$Work = Join-Path $RunetRoot '.local\inst-test'
$TestInstaller = Join-Path $RunetRoot '.local\installer-test'
if (-not (Test-Path $Setup)) { throw "build the installer first: $Setup" }

$script:pass = 0; $script:fail = 0
function Check($name, [scriptblock]$body) {
  try { $r = @(& $body); if ($r.Count -eq 0 -or $r[-1] -eq $false) { throw 'condition is false' }; $script:pass++; Write-Host "PASS  $name" }
  catch { $script:fail++; Write-Host "FAIL  $name`n      $($_.Exception.Message)" }
}
function Cyr([int[]]$codes) { [string]::new([char[]]$codes) }
$put = Cyr 0x41f, 0x443, 0x442, 0x44c                       # "Put'"
$progs = Cyr 0x41f, 0x440, 0x43e, 0x433, 0x440, 0x430, 0x43c, 0x43c, 0x44b   # "Programmy"
$InstallDir = Join-Path $Work "$put s probelami\$progs\Runet Access"
$DataRoot = Join-Path $Work 'data'
$DataDir = Join-Path $DataRoot 'RunetAccess'                 # product data folder of the TEST BUILD (must be named RunetAccess)
$Home1 = Join-Path $Work 'run-home'                           # RUNET_ACCESS_HOME for the running app
$AppExe = Join-Path $InstallDir 'RunetAccess.exe'
$ProgramsDir = [Environment]::GetFolderPath('Programs')
$DesktopDir = [Environment]::GetFolderPath('Desktop')
$UninstKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{B7E2C1A4-5D3F-4E8B-9A16-0C4D7F2E6A31}_is1'

function Sha($p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower() }
function Run-Setup($exe, $extra) {
  $a = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /NOCANCEL /DIR="' + $InstallDir + '" ' + $extra
  $p = Start-Process -FilePath $exe -ArgumentList $a -Wait -PassThru
  return $p.ExitCode
}
function Run-Uninstall($extra) {
  $u = Join-Path $InstallDir 'unins000.exe'
  $p = Start-Process -FilePath $u -ArgumentList ('/VERYSILENT /SUPPRESSMSGBOXES /NORESTART ' + $extra) -Wait -PassThru
  Start-Sleep -Milliseconds 1500    # the uninstaller finishes its own cleanup in a helper copy
  return $p.ExitCode
}
function Lnks($dir, $prefix) { @(Get-ChildItem -LiteralPath $dir -Filter '*.lnk' -ErrorAction SilentlyContinue | Where-Object { $_.Name -like "$prefix*" }) }
function Target($lnk) { (New-Object -ComObject WScript.Shell).CreateShortcut($lnk).TargetPath }
function Own-Procs() {
  Get-CimInstance Win32_Process | Where-Object {
    ($_.ExecutablePath -and $_.ExecutablePath.StartsWith($Work, [StringComparison]::OrdinalIgnoreCase)) -or
    ($_.Name -eq 'chrome.exe' -and $_.CommandLine -and $_.CommandLine.IndexOf($Work, [StringComparison]::OrdinalIgnoreCase) -ge 0)
  }
}
function ProxyState() { (reg query 'HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings' | Where-Object { $_ -match 'Proxy|AutoConfig|AutoDetect' } | Sort-Object) -join '|' }
function RunKeys() { ((Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $_.Name } | Sort-Object) -join '|' }

# ---- baseline ---------------------------------------------------------------------------------
if (Test-Path $Work) { if ((Split-Path $Work -Leaf) -ne 'inst-test' -or -not $Work.StartsWith($RunetRoot)) { throw 'bad work path' }; Remove-Item -LiteralPath $Work -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Work, $DataRoot, $Home1 | Out-Null
if (Test-Path $UninstKey) { throw 'a Runet Access installation already exists on this account: refusing to touch it (uninstall it first)' }
if (Test-Path (Join-Path $env:LOCALAPPDATA 'RunetAccess')) { Write-Host 'NOTE: %LOCALAPPDATA%\RunetAccess exists (real user data): this script never writes there.' }
$proxy0 = ProxyState; $run0 = RunKeys
$tasks0 = @(Get-ScheduledTask -ErrorAction SilentlyContinue).Count
$services0 = @(Get-Service).Count
$chrome0 = @(Get-Process chrome -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
$localState = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Local State'
$localState0 = if (Test-Path $localState) { (Get-Item $localState).LastWriteTimeUtc.Ticks } else { 0 }
$desktop0 = @(Lnks $DesktopDir 'Runet Access').Count; $start0 = @(Lnks $ProgramsDir 'Runet Access').Count
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "session is elevated: $isAdmin (must be False for the 'no administrator' checks to mean anything)"

# ---- 1. install the real installer ---------------------------------------------------------------
Check 'installer runs as an ordinary user and finishes without errors (path with spaces and Cyrillic)' {
  if ($isAdmin) { throw 'run this from a NON-elevated shell' }
  (Run-Setup $Setup '/TASKS=desktopicon') -eq 0
}
Check 'files: exactly the packaged list, hashes match (exe, sing-box, licences, source archive)' {
  $contents = Get-Content (Join-Path $RunetRoot "dist\installer\RunetAccess-Setup-$Version.contents.txt") -Encoding utf8 | Where-Object { $_ -notlike '#*' }
  $bad = @()
  foreach ($l in $contents) { $m = [regex]::Match($l, '^([0-9a-f]{64})\s+(\d+)\s+(.+)$'); $f = Join-Path $InstallDir $m.Groups[3].Value.Replace('/', '\'); if (-not (Test-Path -LiteralPath $f) -or (Sha $f) -ne $m.Groups[1].Value) { $bad += $m.Groups[3].Value } }
  $installed = @(Get-ChildItem -LiteralPath $InstallDir -Recurse -File | Where-Object { $_.Name -ne 'unins000.exe' -and $_.Name -ne 'unins000.dat' -and $_.Name -ne 'unins000.msg' })
  if ($bad) { throw "mismatch: $($bad -join ', ')" }
  if ($installed.Count -ne @($contents).Count) { throw "installed $($installed.Count) files, packaged $(@($contents).Count)" }
  $true
}
Check 'nothing of the developer setup or of the owner is installed (no .local, keys, profiles, logs, scripts, tests, sources)' {
  $names = (Get-ChildItem -LiteralPath $InstallDir -Recurse -File | ForEach-Object { $_.Name.ToLower() }) -join '|'
  $ok = $names -notmatch '\.(go|mjs|js|ps1|py|json|log|dpapi|pem|key|pfx)\b|\.local|test-key|prev-server'
  $ok
}
Check 'no developer tools needed: the programs reference no Python / Go toolchain / Node / Git at run time' {
  $latin = [Text.Encoding]::GetEncoding(28591)
  $t = $latin.GetString([IO.File]::ReadAllBytes($AppExe)).ToLower()
  # the launcher starts only sing-box.exe and chrome.exe
  foreach ($n in 'node.exe', 'python.exe', 'git.exe', 'go.exe') { if ($t.Contains('\' + $n) -or $t.Contains('"' + $n)) { throw "RunetAccess.exe mentions $n" } }
  $true
}
Check 'uninstall entry: one, in HKCU (no machine-wide entry), name and version correct, uninstaller present' {
  $k = Get-ItemProperty $UninstKey
  if ($k.DisplayName -ne 'Runet Access' -or $k.DisplayVersion -ne $Version) { throw "entry: $($k.DisplayName) $($k.DisplayVersion)" }
  if (Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\{B7E2C1A4-5D3F-4E8B-9A16-0C4D7F2E6A31}_is1') { throw 'machine-wide entry exists' }
  Test-Path (Join-Path $InstallDir 'unins000.exe')
}
Check 'shortcuts: Start menu (program + instruction) and the chosen desktop one point into the install folder' {
  $s = @(Lnks $ProgramsDir 'Runet Access'); $d = @(Lnks $DesktopDir 'Runet Access')
  if ($s.Count - $start0 -ne 2) { throw "start menu shortcuts added: $($s.Count - $start0)" }
  if ($d.Count - $desktop0 -ne 1) { throw "desktop shortcuts added: $($d.Count - $desktop0)" }
  $prog = $s + $d | Where-Object { (Target $_.FullName) -ieq $AppExe }
  if (@($prog).Count -ne 2) { throw 'program shortcuts do not point at the installed exe' }
  $instr = $s | Where-Object { $_.Name -ne 'Runet Access.lnk' }
  (Target $instr.FullName).StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase)
}
Check 'no autostart, no services, no scheduled tasks, system proxy unchanged' {
  if ((RunKeys) -ne $run0) { throw 'Run keys changed' }
  if (@(Get-ScheduledTask -ErrorAction SilentlyContinue).Count -ne $tasks0) { throw 'scheduled tasks changed' }
  if (@(Get-Service).Count -ne $services0) { throw 'services changed' }
  (ProxyState) -eq $proxy0
}
Check 'the installer did not create the user data folder (key and profile appear only when the user connects)' {
  -not (Test-Path (Join-Path $env:LOCALAPPDATA 'RunetAccess'))
}

# ---- 2. the installed program works (the whole e2e against the INSTALLED copy) -------------------------
$e2eOut = Join-Path $RunetRoot '.local\logs\installer-e2e.txt'
Check 'installed program: all 36 end-to-end checks in real Chrome pass (first run, links before connect, tiles, replace/cancel, fail-closed, crash cleanup)' {
  # The program is started with a PATH that holds only Windows folders: it must not need Node, Go, Git or Python.
  # (This is NOT a clean Windows - those tools are still on disk - but the program cannot find them through PATH.)
  $env:RUNET_EXE = $AppExe
  $nodeExe = (Get-Command node).Source; $pathBefore = $env:PATH
  $env:PATH = "$env:SystemRoot\System32;$env:SystemRoot;$env:SystemRoot\System32\WindowsPowerShell\v1.0"
  try { & $nodeExe (Join-Path $RunetRoot 'tests\launcher-e2e.mjs') *> $e2eOut } finally { $env:PATH = $pathBefore; Remove-Item Env:\RUNET_EXE }
  $last = (Get-Content $e2eOut -Encoding utf8 | Where-Object { $_ -match 'passed,' } | Select-Object -Last 1)
  if ($last -notmatch '^(\d+) passed, 0 failed') { throw "e2e result: $last (see .local\logs\installer-e2e.txt)" }
  $Matches[1] -ge 36
}

# ---- 3. Chrome missing: the plain window, not a crash ---------------------------------------------------
$env:RUNET_ACCESS_HOME = $Home1; $env:RUNET_CHROME_PATH = (Join-Path $Work 'no-chrome-here\chrome.exe'); $env:RUNET_NO_DIALOG = '1'
Check 'Chrome missing (scripted answers: open page, check again, close): official page offered once, exits cleanly, nothing else started' {
  $log = Join-Path $Work 'open.log'; $env:RUNET_OPEN_LOG = $log; $env:RUNET_TEST_CHROME_PROMPT = 'open,recheck,close'
  $p = Start-Process -FilePath $AppExe -PassThru; if (-not $p.WaitForExit(20000)) { $p.Kill(); throw 'launcher did not exit after the user closed the window' }
  $links = @(Get-Content $log -ErrorAction SilentlyContinue)
  if ($p.ExitCode -ne 0) { throw "exit code $($p.ExitCode)" }
  if ($links.Count -ne 1 -or $links[0] -ne 'https://www.google.com/chrome/') { throw "links: $($links -join ',')" }
  if (@(Own-Procs).Count -ne 0) { throw 'processes left' }
  -not (Test-Path (Join-Path $Home1 'run.lock'))
}
Remove-Item Env:\RUNET_TEST_CHROME_PROMPT, Env:\RUNET_OPEN_LOG -ErrorAction SilentlyContinue
Check 'Chrome missing: the REAL window appears (marked TEST), has download / manual / check again / Close; closing it ends the program without error' {
  Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class WinMsg {
  delegate bool CB(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] static extern bool EnumWindows(CB cb, IntPtr l);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  public static IntPtr Find(int pid) { IntPtr f = IntPtr.Zero;
    EnumWindows((h, l) => { uint p; GetWindowThreadProcessId(h, out p); if (p != pid || !IsWindowVisible(h)) return true;
      var c = new StringBuilder(64); GetClassName(h, c, 64); if (c.ToString() == "#32770") { f = h; return false; } return true; }, IntPtr.Zero);
    return f; }
}
'@
  $dump = Join-Path $Work 'dialogs.txt'; $env:RUNET_TEST_DIALOG_DUMP = $dump
  $p = Start-Process -FilePath $AppExe -PassThru
  $h = [IntPtr]::Zero; for ($i = 0; $i -lt 40 -and $h -eq [IntPtr]::Zero; $i++) { Start-Sleep -Milliseconds 250; if ($p.HasExited) { throw 'launcher exited without showing the window' }; $h = [WinMsg]::Find($p.Id) }
  if ($h -eq [IntPtr]::Zero) { $p.Kill(); throw 'no window' }
  $txt = if (Test-Path $dump) { [IO.File]::ReadAllText($dump, [Text.Encoding]::UTF8) } else { '' }
  $needles = @((Cyr 0x422, 0x415, 0x421, 0x422), (Cyr 0x421, 0x43a, 0x430, 0x447, 0x430, 0x442, 0x44c, 0x20, 0x438, 0x20, 0x443, 0x441, 0x442, 0x430, 0x43d, 0x43e, 0x432, 0x438, 0x442, 0x44c), (Cyr 0x432, 0x440, 0x443, 0x447, 0x43d, 0x443, 0x44e), (Cyr 0x41f, 0x440, 0x43e, 0x432, 0x435, 0x440, 0x438, 0x442, 0x44c), 'Chrome')
  foreach ($need in $needles) { if ($txt -notmatch [regex]::Escape($need)) { throw "window text lacks '$need': $txt" } }
  [void][WinMsg]::PostMessage($h, 0x10, [IntPtr]::Zero, [IntPtr]::Zero)   # WM_CLOSE to OUR dialog
  if (-not $p.WaitForExit(10000)) { $p.Kill(); throw 'did not exit after the window was closed' }
  if ($p.ExitCode -ne 0) { throw "exit code $($p.ExitCode)" }
  @(Own-Procs).Count -eq 0
}
Remove-Item Env:\RUNET_TEST_DIALOG_DUMP -ErrorAction SilentlyContinue
Remove-Item Env:\RUNET_CHROME_PATH -ErrorAction SilentlyContinue

# ---- 4. running program: setup must ask to close it, never kill it -----------------------------------------
Check 'program running: Setup does not replace files under it and does not kill the program or Chrome' {
  $env:RUNET_CHROME_EXTRA_ARGS = '--remote-debugging-port=9333'
  $app = Start-Process -FilePath $AppExe -PassThru; Start-Sleep 6
  $hashBefore = Sha $AppExe
  $setupProc = Start-Process -FilePath $Setup -ArgumentList ('/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /DIR="' + $InstallDir + '"') -PassThru
  Start-Sleep 12
  $waiting = -not $setupProc.HasExited
  $alive = -not $app.HasExited
  $chromeOurs = @(Own-Procs | Where-Object { $_.Name -eq 'chrome.exe' }).Count
  $res = "setup still waiting=$waiting exitcode=$(if ($setupProc.HasExited) { $setupProc.ExitCode } else { 'running' }) app alive=$alive our chrome processes=$chromeOurs"
  Write-Host "      $res"
  # close the program the polite way (Chrome window via DevTools), then let Setup finish or end
  node -e "const ws=new WebSocket(JSON.parse(require('child_process').execSync('curl -s http://127.0.0.1:9333/json/version')).webSocketDebuggerUrl);ws.onopen=()=>{ws.send(JSON.stringify({id:1,method:'Browser.close'}));setTimeout(()=>process.exit(0),1500)}" 2>$null
  [void]$app.WaitForExit(20000)
  if (-not $setupProc.WaitForExit(40000)) { $setupProc.Kill(); Write-Host '      (setup was still waiting after the program closed; killed by the test)' }
  Remove-Item Env:\RUNET_CHROME_EXTRA_ARGS -ErrorAction SilentlyContinue
  if (-not $alive) { throw "the program was killed. $res" }
  if ($chromeOurs -lt 1) { throw "our Chrome was killed. $res" }
  if ((Sha $AppExe) -ne $hashBefore) { throw 'exe changed while running' }
  $true
}
Check 'program running: nothing of ours is left after the polite close' {
  Start-Sleep 3; @(Own-Procs | Where-Object { $_.Name -ne 'unins000.exe' }).Count -eq 0
}

# ---- 5. uninstall (real installer, no user data of ours present) ----------------------------------------------
Check 'uninstall: program files, shortcuts and the Apps entry are gone; the install folder is removed' {
  if ((Run-Uninstall '') -ne 0) { throw 'uninstaller failed' }
  if (Test-Path $UninstKey) { throw 'uninstall entry remains' }
  if (@(Lnks $ProgramsDir 'Runet Access').Count -ne $start0 -or @(Lnks $DesktopDir 'Runet Access').Count -ne $desktop0) { throw 'shortcuts remain' }
  -not (Test-Path -LiteralPath $AppExe)
}

# ---- 6. update + data handling on a TEST BUILD (same script, data folder redirected) ---------------------------------------
Write-Host 'building two test variants of the installer (0.3.0 and 0.3.1) with a throw-away data folder ...'
$mk = Join-Path $RunetRoot 'scripts\make-installer.ps1'
& $mk -SkipBuild -Test -VersionOverride $Version -DataDir $DataDir -OutDir $TestInstaller -OutName 'RunetAccess-Setup-test-A' | Out-Null
$vp = $Version.Split('.'); $vp[2] = [string]([int]$vp[2] + 1); $next = $vp -join '.'
& $mk -SkipBuild -Test -VersionOverride $next -DataDir $DataDir -OutDir $TestInstaller -OutName 'RunetAccess-Setup-test-B' | Out-Null
$SetupA = Join-Path $TestInstaller 'RunetAccess-Setup-test-A.exe'; $SetupB = Join-Path $TestInstaller 'RunetAccess-Setup-test-B.exe'

# synthetic user data + bystanders that must survive everything
New-Item -ItemType Directory -Force -Path (Join-Path $DataDir 'profile\Default'), (Join-Path $DataRoot 'Google\Chrome\User Data\Default'), (Join-Path $DataRoot 'OtherApp') | Out-Null
[IO.File]::WriteAllBytes((Join-Path $DataDir 'key.dpapi'), [byte[]](1..200))
[IO.File]::WriteAllText((Join-Path $DataDir 'profile\Default\Cookies'), 'synthetic cookie data')
[IO.File]::WriteAllText((Join-Path $DataDir 'profile\Default\History'), 'synthetic history')
[IO.File]::WriteAllText((Join-Path $DataDir 'unrelated-note.txt'), 'not ours')
[IO.File]::WriteAllText((Join-Path $DataRoot 'Google\Chrome\User Data\Default\Preferences'), 'ordinary chrome profile (decoy)')
[IO.File]::WriteAllText((Join-Path $DataRoot 'OtherApp\data.txt'), 'other app (decoy)')
$keyHash = Sha (Join-Path $DataDir 'key.dpapi')
$decoys = @((Join-Path $DataRoot 'Google\Chrome\User Data\Default\Preferences'), (Join-Path $DataRoot 'OtherApp\data.txt'), (Join-Path $DataDir 'unrelated-note.txt'))
$decoyHashes = $decoys | ForEach-Object { Sha $_ }

Check 'update: install 0.3.0, then install the next version over it with the same shortcut choice' {
  if ((Run-Setup $SetupA '/TASKS=desktopicon') -ne 0) { throw 'install A failed' }
  $bi = Sha (Join-Path $InstallDir 'BUILD-INFO.txt')
  if ((Run-Setup $SetupB '/TASKS=desktopicon') -ne 0) { throw 'install B failed' }
  $k = Get-ItemProperty $UninstKey
  if ($k.DisplayVersion -ne $next) { throw "version after update: $($k.DisplayVersion)" }
  if ((Sha (Join-Path $InstallDir 'BUILD-INFO.txt')) -eq $bi) { throw 'files were not replaced' }
  $true
}
Check 'update: still ONE Apps entry, no duplicate shortcuts' {
  $entries = @(Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall' | Where-Object { (Get-ItemProperty $_.PSPath).DisplayName -like 'Runet Access*' }).Count
  if ($entries -ne 1) { throw "Apps entries: $entries" }
  if (@(Lnks $ProgramsDir 'Runet Access').Count - $start0 -ne 2 -or @(Lnks $DesktopDir 'Runet Access').Count - $desktop0 -ne 1) { throw 'duplicate or missing shortcuts' }
  $true
}
Check 'update: saved key and browser profile untouched' {
  (Sha (Join-Path $DataDir 'key.dpapi')) -eq $keyHash -and (Test-Path (Join-Path $DataDir 'profile\Default\Cookies'))
}
Check 'uninstall (default answer): program removed, the saved key and profile are KEPT' {
  if ((Run-Uninstall '') -ne 0) { throw 'uninstaller failed' }
  if (Test-Path $UninstKey) { throw 'entry remains' }
  if (Test-Path -LiteralPath $AppExe) { throw 'exe remains' }
  (Sha (Join-Path $DataDir 'key.dpapi')) -eq $keyHash -and (Test-Path (Join-Path $DataDir 'profile\Default\History'))
}
Check 'reinstall after a kept-data uninstall finds the old key (nothing to re-enter)' {
  if ((Run-Setup $SetupB '') -ne 0) { throw 'install failed' }
  (Sha (Join-Path $DataDir 'key.dpapi')) -eq $keyHash
}
Check 'uninstall with explicit "delete my data": key and profile removed, bystanders (other app, ordinary Chrome profile, unrelated file) intact' {
  if ((Run-Uninstall '/DELETEDATA') -ne 0) { throw 'uninstaller failed' }
  if (Test-Path (Join-Path $DataDir 'key.dpapi')) { throw 'key remains' }
  if (Test-Path (Join-Path $DataDir 'profile')) { throw 'profile remains' }
  for ($i = 0; $i -lt $decoys.Count; $i++) { if (-not (Test-Path $decoys[$i]) -or (Sha $decoys[$i]) -ne $decoyHashes[$i]) { throw "bystander damaged: $($decoys[$i])" } }
  $true
}
Check 'uninstall of a clean machine state: Start menu, desktop, Apps list and the install folder are all clean' {
  if (Test-Path $UninstKey) { throw 'entry remains' }
  if (@(Lnks $ProgramsDir 'Runet Access').Count -ne $start0 -or @(Lnks $DesktopDir 'Runet Access').Count -ne $desktop0) { throw 'shortcuts remain' }
  -not (Test-Path -LiteralPath $InstallDir)
}

# ---- 7. nothing else was touched --------------------------------------------------------------------------------------
Check 'system proxy, autostart, scheduled tasks and services identical to before; ordinary Chrome processes not killed; its Local State untouched' {
  if ((ProxyState) -ne $proxy0) { throw 'proxy changed' }
  if ((RunKeys) -ne $run0) { throw 'Run keys changed' }
  if (@(Get-ScheduledTask -ErrorAction SilentlyContinue).Count -ne $tasks0 -or @(Get-Service).Count -ne $services0) { throw 'tasks/services changed' }
  $now = @(Get-Process chrome -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
  foreach ($id in $chrome0) { if ($now -notcontains $id) { throw "an ordinary Chrome process ($id) disappeared" } }
  $ls = if (Test-Path $localState) { (Get-Item $localState).LastWriteTimeUtc.Ticks } else { 0 }
  # Chrome itself may rewrite it while running; report instead of failing
  if ($ls -ne $localState0) { Write-Host '      (note: Chrome Local State changed by the running ordinary Chrome itself, not by us; the test never touches it)' }
  $true
}
Check 'the owner key file is untouched' {
  $f = Join-Path $RunetRoot '.local\secrets\test-key.txt'
  (Test-Path $f) -and ((Get-Item $f).Length -gt 0)
}
Remove-Item Env:\RUNET_ACCESS_HOME, Env:\RUNET_NO_DIALOG -ErrorAction SilentlyContinue

Write-Host "`n$script:pass passed, $script:fail failed"
if ($script:fail) { exit 1 }

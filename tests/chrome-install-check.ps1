# The "download and install Google Chrome" window, driven in the REAL program against a LOCAL stand-in for
# Google's host. Nothing is downloaded from the internet and no browser is installed or touched.
#
#   . .\scripts\env.ps1; .\tests\chrome-install-check.ps1 [-Exe path\to\RunetAccess.exe]
#
# What is real: the launcher binary, its Windows dialogs (TaskDialog), the download code, the signature check,
# the cleanup. What is stood in: Google's host (a loopback server, honoured only for loopback addresses).
# Test windows are marked with the word TEST in the title and text, and run on an invisible desktop when started
# through tests/run-hidden.ps1.
# What is NOT covered here: a real Google installer actually installing Chrome (needs a clean machine; see
# docs\LIMITATIONS.md). The "install succeeded" logic is covered by the Go tests with fakes.
param([string]$Exe)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\scripts\env.ps1"
if (-not $Exe) { $Exe = Join-Path $RunetRoot 'dist\runet-access\RunetAccess.exe' }
if (-not (Test-Path $Exe)) { throw "no program at $Exe" }
$Work = Join-Path $RunetRoot '.local\chrome-install-test'
if (Test-Path $Work) { if ((Split-Path $Work -Leaf) -ne 'chrome-install-test') { throw 'bad path' }; Remove-Item -LiteralPath $Work -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Work | Out-Null
$shots = Join-Path $RunetRoot '.local\logs\shots'; New-Item -ItemType Directory -Force -Path $shots | Out-Null

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName System.Drawing
Add-Type @'
using System; using System.Runtime.InteropServices;
public class CI {
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr dc, uint f);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, uint m, IntPtr w, IntPtr l);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; } }
'@
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
public static class WD {
  delegate bool CB(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] static extern bool EnumWindows(CB cb, IntPtr l);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
  // the visible dialog (#32770) of a process on THIS desktop; .NET's MainWindowHandle may pick an unrelated window
  public static IntPtr Find(int pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => { uint p; GetWindowThreadProcessId(h, out p); if (p != pid || !IsWindowVisible(h)) return true;
      var c = new StringBuilder(64); GetClassName(h, c, 64); if (c.ToString() == "#32770") { found = h; return false; } return true; }, IntPtr.Zero);
    return found;
  }
  public static string Title(IntPtr h) { var t = new StringBuilder(256); GetWindowText(h, t, 256); return t.ToString(); }
}
'@
function Dialog($p) { [WD]::Find($p.Id) }
[void][CI]::SetProcessDPIAware()
$script:pass = 0; $script:fail = 0
function Check($name, [scriptblock]$body) {
  try { $r = @(& $body); if ($r.Count -eq 0 -or $r[-1] -eq $false) { throw 'condition is false' }; $script:pass++; Write-Host "PASS  $name" }
  catch { $script:fail++; Write-Host "FAIL  $name`n      $($_.Exception.Message)" }
}
function Cyr([int[]]$c) { [string]::new([char[]]$c) }
$W_head   = Cyr 0x41d, 0x443, 0x436, 0x435, 0x43d, 0x20, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65                          # "Nuzhen Google"
$W_sign   = Cyr 0x43f, 0x43e, 0x434, 0x43f, 0x438, 0x441, 0x430, 0x43d                                    # "podpisan"
$W_test   = Cyr 0x422, 0x415, 0x421, 0x422                                                                 # "TEST"
$W_download = Cyr 0x441, 0x43a, 0x430, 0x447, 0x430, 0x442, 0x44c                                         # "skachat'"
$W_cancelled = Cyr 0x43e, 0x442, 0x43c, 0x435, 0x43d, 0x435, 0x43d, 0x430                                  # "otmenena"
$W_busy   = Cyr 0x423, 0x441, 0x442, 0x430, 0x43d, 0x43e, 0x432, 0x43a, 0x430, 0x20, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65     # "Ustanovka Google" (heading of the progress window)
$W_install = Cyr 0x421, 0x43a, 0x430, 0x447, 0x430, 0x442, 0x44c, 0x20, 0x438, 0x20, 0x443, 0x441, 0x442, 0x430, 0x43d, 0x43e, 0x432, 0x438, 0x442, 0x44c   # "Skachat' i ustanovit'"
$W_pick   = Cyr 0x443, 0x43a, 0x430, 0x437, 0x430, 0x442, 0x44c, 0x20, 0x63, 0x68, 0x72, 0x6f, 0x6d, 0x65, 0x2e, 0x65, 0x78, 0x65   # "ukazat' chrome.exe"
$W_manual = Cyr 0x432, 0x440, 0x443, 0x447, 0x43d, 0x443, 0x44e                                           # "vruchnuyu"

# ---- fixtures: a harmless unsigned "installer" that leaves a marker if it is ever started ----------------------------
$fixture = Join-Path $Work 'fake-installer.exe'
Push-Location (Join-Path $RunetRoot 'src\app')
& go build -o $fixture ./cmd/launcher/testdata/exitcode
if ($LASTEXITCODE) { throw 'cannot build the fixture' }
Pop-Location
$marker = Join-Path $Work 'installer-was-started.txt'
$env:FIXTURE_MARKER = $marker
$port = Get-Random -Minimum 20000 -Maximum 40000
$srv = Start-Process node -ArgumentList @((Join-Path $RunetRoot 'tests\chrome-fake-server.mjs'), $port, $fixture) -PassThru -WindowStyle Hidden
Start-Sleep 1
function Hits() { (Invoke-RestMethod "http://127.0.0.1:$port/__hits") }
$tmpRoot = Join-Path $env:TEMP 'runet-access'
function SetupDirs() { @(Get-ChildItem $tmpRoot -Directory -Filter 'chrome-setup-*' -ErrorAction SilentlyContinue).Count }

$env:RUNET_TEST_MODE = '1'   # every override below is ignored by the program without this
$env:RUNET_ACCESS_HOME = Join-Path $Work 'home'; $env:RUNET_NO_DIALOG = '1'
$env:RUNET_CHROME_PATH = Join-Path $Work 'no-chrome-here\chrome.exe'      # "Chrome is not installed" (nothing is uninstalled)
$env:RUNET_OPEN_LOG = Join-Path $Work 'open.log'

$dump = Join-Path $Work 'dialogs.txt'; $env:RUNET_TEST_DIALOG_DUMP = $dump
# what the program itself says it shows in its latest dialog (title, heading, text, details, buttons)
function Texts($h) {
  if (-not (Test-Path $dump)) { return '' }
  $t = [IO.File]::ReadAllText($dump, [Text.Encoding]::UTF8); $i = $t.LastIndexOf('=== DIALOG')
  if ($i -lt 0) { return '' } else { return $t.Substring($i) }
}
function Wait-Window($p, $needle, $sec = 20) {
  $end = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $end) {
    $p.Refresh()
    if ($p.HasExited) { return [IntPtr]::Zero }
    $h = Dialog $p
    if ($h -ne [IntPtr]::Zero) { try { if ((Texts $h) -match [regex]::Escape($needle)) { return $h } } catch {} }
    Start-Sleep -Milliseconds 300
  }
  return [IntPtr]::Zero
}
function Press($h, $id) { [void][CI]::SendMessage($h, 0x466, [IntPtr]$id, [IntPtr]::Zero) }   # TDM_CLICK_BUTTON on OUR dialog
function Shot($h, $name) {
  $r = New-Object CI+RECT; [void][CI]::GetWindowRect($h, [ref]$r)
  $bmp = New-Object Drawing.Bitmap ($r.R - $r.L), ($r.B - $r.T); $g = [Drawing.Graphics]::FromImage($bmp)
  $dc = $g.GetHdc(); [void][CI]::PrintWindow($h, $dc, 2); $g.ReleaseHdc($dc); $bmp.Save((Join-Path $shots $name)); $bmp.Dispose()
}
function Start-App() { Start-Process -FilePath $Exe -PassThru }
function Close-App($p) { $p.Refresh(); if (-not $p.HasExited) { $h = Dialog $p; if ($h -ne [IntPtr]::Zero) { [void][CI]::PostMessage($h, 0x10, [IntPtr]::Zero, [IntPtr]::Zero) } }; [void]$p.WaitForExit(10000); if (-not $p.HasExited) { $p.Kill(); throw 'the program did not end after closing the window' } }

# ---- 1. unsigned file: downloaded, REFUSED, deleted, never started ------------------------------------------------------
$env:RUNET_TEST_CHROME_URL = "http://127.0.0.1:$port/ok.exe"
Check 'main window offers: download and install / open the page by hand / check again / close' {
  $p = Start-App; $h = Wait-Window $p $W_head; if ($h -eq [IntPtr]::Zero) { throw 'no window' }
  $t = Texts $h
  foreach ($need in @($W_install, $W_manual, 'Chrome', $W_test)) { if ($t -notmatch [regex]::Escape($need)) { throw "window text lacks '$need': $t" } }
  $title = [WD]::Title($h); if ($title -notmatch [regex]::Escape($W_test)) { throw "the window title is not marked as a test: '$title'" }
  Shot $h 'chrome-missing-dialog.png'
  Close-App $p; $p.ExitCode -eq 0
}
Check 'a file NOT signed by Google is downloaded, refused with a clear message, deleted and never started' {
  $p = Start-App; $h = Wait-Window $p $W_head; if ($h -eq [IntPtr]::Zero) { throw 'no window' }
  Press $h 103
  $h2 = Wait-Window $p $W_sign 30                                    # the main window comes back with the reason on top
  if ($h2 -eq [IntPtr]::Zero) { throw "no refusal message. window: $(try { Texts (Dialog $p) } catch { 'none' }); alive=$(-not $p.HasExited); hits=$((Hits | ConvertTo-Json -Compress))" }
  Shot $h2 'chrome-install-refused.png'
  $tt = Texts $h2; if ($tt -notmatch '127\.0\.0\.1' -or $tt -notmatch 'SHA-256') { throw "no technical details in the window: $tt" }
  if (Test-Path $marker) { throw 'THE UNVERIFIED FILE WAS STARTED' }
  if ((Hits).'/ok.exe' -ne 1) { throw 'the file was not requested exactly once' }
  if ((SetupDirs) -ne 0) { throw 'the refused file is still on disk' }
  Close-App $p; $true
}
# ---- 2. the working window and cancelling ------------------------------------------------------------------------------------
$env:RUNET_TEST_CHROME_URL = "http://127.0.0.1:$port/slow.exe"
Check 'progress window while downloading; Cancel returns to the main window with "cancelled"; nothing left on disk' {
  $p = Start-App; $h = Wait-Window $p $W_head; if ($h -eq [IntPtr]::Zero) { throw 'no window' }
  Press $h 103
  $hb = Wait-Window $p $W_busy 20; if ($hb -eq [IntPtr]::Zero) { throw 'no progress window' }
  Start-Sleep 2; Shot $hb 'chrome-install-progress.png'
  Press $hb 2                                                          # the user presses Cancel
  $h2 = Wait-Window $p $W_cancelled 20; if ($h2 -eq [IntPtr]::Zero) { throw 'no "cancelled" message' }
  if (Test-Path $marker) { throw 'something was started' }
  Start-Sleep 1; if ((SetupDirs) -ne 0) { throw 'the partial download is still on disk' }
  Close-App $p; $true
}
$env:RUNET_TEST_CHROME_URL = "http://127.0.0.1:$port/404"
Check 'download failure (404): a clear message, a way to retry, nothing started' {
  $p = Start-App; $h = Wait-Window $p $W_head; Press $h 103
  $h2 = Wait-Window $p $W_download 20; if ($h2 -eq [IntPtr]::Zero) { throw 'no failure message' }
  $t = Texts $h2; if ($t -notmatch [regex]::Escape($W_install)) { throw 'no way to retry' }
  if (Test-Path $marker) { throw 'something was started' }
  Close-App $p; $true
}
$env:RUNET_TEST_CHROME_URL = "http://127.0.0.1:$port/html"
Check 'a web page instead of a program is refused' {
  $p = Start-App; $h = Wait-Window $p $W_head; Press $h 103
  $h2 = Wait-Window $p $W_download 20; if ($h2 -eq [IntPtr]::Zero) { throw 'no failure message' }
  if (Test-Path $marker) { throw 'something was started' }
  Close-App $p; $true
}
$env:RUNET_TEST_CHROME_URL = "http://127.0.0.1:$port/redirect-away"
Check 'a redirect to another host is refused (only the official host is followed)' {
  $p = Start-App; $h = Wait-Window $p $W_head; Press $h 103
  $h2 = Wait-Window $p $W_download 20; if ($h2 -eq [IntPtr]::Zero) { throw 'no failure message' }
  if (Test-Path $marker) { throw 'something was started' }
  if ((Hits).'/ok.exe' -gt 1) { throw 'the foreign host was contacted' }
  Close-App $p; $true
}
# ---- 3. an existing Chrome, ORDINARY launch: no test mode, no overrides at all (only a private data folder) ----------------
$env:RUNET_TEST_MODE = $null; $env:RUNET_CHROME_PATH = $null; $env:RUNET_TEST_CHROME_URL = $null; $env:RUNET_CHROME_EXTRA_ARGS = $null
$env:RUNET_TEST_DIALOG_DUMP = $null; $env:RUNET_OPEN_LOG = $null; $env:RUNET_ACCESS_HOME = Join-Path $Work 'home-plain'
Check 'ORDINARY launch (no test variables): the installed Chrome is found, no window asks for it, our own Chrome window starts' {
  $p = Start-App; Start-Sleep 8
  $p.Refresh(); if ($p.HasExited) { throw "the launcher exited (code $($p.ExitCode))" }
  if ((Dialog $p) -ne [IntPtr]::Zero) { throw 'a dialog appeared although Chrome is installed' }
  $ours = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'chrome.exe' -and $_.CommandLine -match 'chrome-install-test' })
  if ($ours.Count -lt 1) { throw 'our Chrome did not start' }
  $exe = ($ours | Select-Object -First 1).ExecutablePath
  if ((SetupDirs) -ne 0) { throw 'an installer download was started' }
  $p.Kill(); Start-Sleep 3                                                # the Job Object takes our core and Chrome with it
  if (@(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'chrome.exe' -and $_.CommandLine -match 'chrome-install-test' }).Count) { throw 'our Chrome outlived the launcher' }
  Write-Host "      Chrome used: $exe"
  $true
}
# ---- 4. "specify chrome.exe": automatic search pretended to fail (test mode), the user points at the real Chrome ----
$env:RUNET_TEST_MODE = '1'; $env:RUNET_TEST_DIALOG_DUMP = $dump; $env:RUNET_TEST_NO_AUTODETECT = '1'
$env:RUNET_ACCESS_HOME = Join-Path $Work 'home-pick'
$realChrome = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe').'(default)'
Check 'the main window offers "specify chrome.exe"' {
  $p = Start-App; $h = Wait-Window $p $W_head; if ($h -eq [IntPtr]::Zero) { throw 'no window' }
  if ((Texts $h) -notmatch [regex]::Escape($W_pick)) { throw "no pick button: $(Texts $h)" }
  Close-App $p; $true
}
Check 'a file that is NOT Google Chrome is refused with the reason (publisher shown) and nothing is remembered' {
  $fake = Join-Path $Work 'fake\chrome.exe'; New-Item -ItemType Directory -Force -Path (Split-Path $fake) | Out-Null
  Copy-Item (Join-Path $RunetRoot '.local\cache\downloads\innosetup-6.7.3.exe') $fake    # validly signed, but by someone else
  $env:RUNET_TEST_CHROME_PICK = $fake
  $p = Start-App; $h = Wait-Window $p $W_head; Press $h 104
  $h2 = Wait-Window $p 'Pyrsys' 20; if ($h2 -eq [IntPtr]::Zero) { throw "no refusal with the publisher: $(Texts (Dialog $p))" }
  $t = Texts $h2; if ($t -notmatch 'Google LLC|Google') { throw $t }
  if (Test-Path (Join-Path $env:RUNET_ACCESS_HOME 'chrome-path.txt')) { throw 'a refused file was remembered' }
  Close-App $p; $true
}
Check 'the real chrome.exe chosen by the user is accepted, remembered, and used on the next start without any question' {
  $env:RUNET_TEST_CHROME_PICK = $realChrome
  $p = Start-App; $h = Wait-Window $p $W_head; Press $h 104
  $end = (Get-Date).AddSeconds(25); $ok = $false
  while ((Get-Date) -lt $end -and -not $ok) { Start-Sleep -Milliseconds 500; $ok = @(Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'chrome.exe' -and $_.CommandLine -match 'chrome-install-test' }).Count -ge 1 }
  if (-not $ok) { throw 'the program did not continue after the file was accepted' }
  $saved = (Get-Content (Join-Path $env:RUNET_ACCESS_HOME 'chrome-path.txt') -Encoding utf8 | Select-Object -First 1).Trim()
  if ($saved -ne $realChrome) { throw "remembered: $saved" }
  $p.Kill(); Start-Sleep 3
  $env:RUNET_TEST_CHROME_PICK = $null
  $p = Start-App; Start-Sleep 8; $p.Refresh()
  if ($p.HasExited) { throw 'second start: launcher exited' }
  if ((Dialog $p) -ne [IntPtr]::Zero) { throw 'second start: the window asked again' }
  $p.Kill(); Start-Sleep 3; $true
}
$env:RUNET_TEST_NO_AUTODETECT = $null
Check 'the fake host was only ever asked for the expected paths; no installer ran; no leftovers' {
  if (Test-Path $marker) { throw 'the marker exists' }
  (SetupDirs) -eq 0
}
Check 'every window was shown by the modern Windows dialog (hr=0x0), never by the plain fallback box; the user closing it is the only "closed" result' {
  $all = [IO.File]::ReadAllText($dump, [Text.Encoding]::UTF8)
  $bad = [regex]::Matches($all, 'result: hr=0x([0-9a-f]+)') | Where-Object { $_.Groups[1].Value -ne '0' }
  if (@($bad).Count) { throw "TaskDialog failed: $($bad[0].Value)" }
  ([regex]::Matches($all, 'result: hr=0x0 ')).Count -ge 8
}
Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue
foreach ($v in 'RUNET_TEST_MODE', 'RUNET_TEST_CHROME_URL', 'RUNET_CHROME_EXTRA_ARGS', 'RUNET_ACCESS_HOME', 'RUNET_NO_DIALOG', 'RUNET_OPEN_LOG', 'FIXTURE_MARKER', 'RUNET_TEST_DIALOG_DUMP', 'RUNET_TEST_CHROME_PICK', 'RUNET_TEST_NO_AUTODETECT') { Set-Item -Path "Env:\$v" -Value $null -ErrorAction SilentlyContinue }
Write-Host "`n$script:pass passed, $script:fail failed"
if ($script:fail) { exit 1 }

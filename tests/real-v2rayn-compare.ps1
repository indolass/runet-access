# Control comparison: the SAME key through a ready client (v2rayN + Xray), independent of our parser.
# - works on a COPY of the portable v2rayN inside .local\tools (the owner's installation and profiles are not touched);
# - the copy is configured with SysProxyType=2 (Unchanged: never touches the Windows proxy) and TUN off;
# - import is v2rayN's own "Import Share Links from clipboard", INVOKED through UI Automation. This script sends NO
#   keystrokes and NO mouse input at all (an earlier version did, see docs\INCIDENT-2026-10-02-global-paste.md);
# - the server is made ACTIVE without any input: its id is read from v2rayN's closed database (tests\dbget.mjs,
#   ids only) and written into the copy's own config, then the copy is restarted and starts the core itself;
# - CLIPBOARD EXPOSURE: the key IS placed on the system clipboard for the few seconds of the import call (a
#   clipboard history/manager or cloud clipboard could capture it); the previous text is restored afterwards.
#   Do not run this script without the owner's approval for that exposure;
# - the probe request goes EXPLICITLY through the local v2rayN proxy (curl -x socks5h://127.0.0.1:PORT);
# - only processes started here are stopped; the copy (its DB and generated config contain the key) is deleted;
# - it never writes outside the project root, never touches the registry or the owner's v2rayN folder (read-only source).
# Output is redacted (host, IP, UUID, keys; any IPv4 -> first octet).
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Src  = 'D:\soft\v2rayN-windows-64\v2rayN-windows-64'
$Dst  = Join-Path $Root '.local\tools\v2rayN-test'
$Key  = Join-Path $Root '.local\secrets\test-key.txt'
$Port = 17808
$Inet = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Add-Type -AssemblyName System.Web, System.Windows.Forms, UIAutomationClient, UIAutomationTypes

function SysProxy { $p = Get-ItemProperty $Inet; ($p.ProxyEnable, $p.ProxyServer, $p.AutoConfigURL, $p.AutoDetect) -join '|' }
$script:secrets = @()
function Redact([string]$s) {
  foreach ($x in $script:secrets) { if ($x -and $x.Length -ge 4) { $s = $s.Replace($x, '<скрыто>') } }
  $s = [regex]::Replace($s, '\b(\d{1,3})(\.\d{1,3}){3}\b', '$1.x.x.x')
  [regex]::Replace($s, '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b', '<uuid>')
}
function Say([string]$s) { Write-Output (Redact $s) }
# the clipboard can be held by another process for a moment: retry (SetDataObject has built-in retries)
function SetClip([string]$text) {
  for ($i = 0; $i -lt 8; $i++) {
    try { [System.Windows.Forms.Clipboard]::SetDataObject($text, $true, 10, 200); return } catch { Start-Sleep -Milliseconds 400 }
  }
  throw 'clipboard is busy'
}
function El($root, [string]$name, $type) {
  $c = New-Object System.Windows.Automation.AndCondition(
    (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::NameProperty, $name)),
    (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, $type)))
  $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $c)
}

# ---- preconditions ------------------------------------------------------------------------
if (-not (Test-Path "$Src\v2rayN.exe")) { throw 'v2rayN not found' }
if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) { throw "port $Port is busy" }
$raw = (Get-Content $Key -Raw -Encoding UTF8).Trim()
$u = [Uri]($raw.Split('#')[0])
$q = [System.Web.HttpUtility]::ParseQueryString($u.Query)
$script:secrets = @($u.Host, [Uri]::UnescapeDataString($u.UserInfo), $q['pbk'], $q['sid'])
try { $script:secrets += ([Net.Dns]::GetHostAddresses($u.Host) | % { $_.IPAddressToString }) } catch {}
$sysBefore = SysProxy
Say "Системный прокси Windows до: [$sysBefore]"

# ---- copy of v2rayN (no user profiles, no heavy unused cores) ------------------------------
if (-not (Test-Path "$Dst\v2rayN.exe")) {
  robocopy $Src $Dst /E /XD guiConfigs guiLogs guiTemps binConfigs mihomo sing_box srss /NFL /NDL /NJH /NJS /NP | Out-Null
}
foreach ($d in 'guiConfigs', 'guiLogs', 'guiTemps', 'binConfigs') { New-Item -ItemType Directory -Force (Join-Path $Dst $d) | Out-Null }
$cfg = [ordered]@{
  SystemProxyItem = [ordered]@{ SysProxyType = 2 }
  TunModeItem     = [ordered]@{ EnableTun = $false }
  Inbound         = [ordered]@{ LocalPort = $Port; Protocol = 'socks'; UdpEnabled = $true; SniffingEnabled = $true; AllowLANConn = $false }
  CoreBasicItem   = [ordered]@{ LogEnabled = $true; Loglevel = 'warning' }
  CheckUpdateItem = [ordered]@{ CheckPreReleaseUpdate = $false }
}
[IO.File]::WriteAllText((Join-Path $Dst 'guiConfigs\guiNConfig.json'), ($cfg | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))

$started = New-Object System.Collections.Generic.List[int]
$clipBackup = $null; $clipHadText = $false
$result = [ordered]@{}
try {
  try { $clipBackup = Get-Clipboard -Raw -ErrorAction Stop; $clipHadText = $true } catch { $clipHadText = $false }
  $p = Start-Process -FilePath (Join-Path $Dst 'v2rayN.exe') -WorkingDirectory $Dst -PassThru -RedirectStandardOutput (Join-Path $Dst 'stdout.txt') -RedirectStandardError (Join-Path $Dst 'stderr.txt')
  $started.Add($p.Id)
  $h = [IntPtr]::Zero
  for ($i = 0; $i -lt 60; $i++) { Start-Sleep -Milliseconds 500; $p.Refresh(); if ($p.MainWindowHandle -ne [IntPtr]::Zero) { $h = $p.MainWindowHandle; break } }
  if ($h -eq [IntPtr]::Zero) { throw 'v2rayN window did not appear' }
  Start-Sleep -Seconds 2
  Say ("Системный прокси сразу после запуска v2rayN: [" + (SysProxy) + "] (изменился: " + ((SysProxy) -ne $sysBefore) + ")")
  $win = [System.Windows.Automation.AutomationElement]::FromHandle($h)

  # ---- import through v2rayN's own menu, invoked by UI Automation ------------------------------
  $menu = El $win 'Configuration' ([System.Windows.Automation.ControlType]::MenuItem)
  if (-not $menu) { throw 'menu "Configuration" not found' }
  $menu.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern).Expand()
  Start-Sleep -Milliseconds 700
  $items = $menu.FindAll([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::MenuItem)))
  $names = @($items | % { $_.Current.Name } | ? { $_ })
  Say ("Пункты меню Configuration: " + ($names -join ' | '))
  $imp = $items | ? { $_.Current.Name -match 'clipboard' -and $_.Current.Name -match 'Import|URL' } | select -First 1
  if (-not $imp) { throw 'import-from-clipboard menu item not found' }
  Say ("Использую штатный пункт: " + $imp.Current.Name)
  SetClip $raw
  $raw = $null
  $imp.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
  Start-Sleep -Seconds 3
  if ($clipHadText) { SetClip $clipBackup } else { SetClip ' ' }   # the key leaves the clipboard
  Say 'Буфер обмена возвращён к прежнему содержимому'

  # ---- how many servers v2rayN now has (no names printed) ---------------------------------------
  $grid = $win.FindFirst([System.Windows.Automation.TreeScope]::Descendants, (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::AutomationIdProperty, 'lstProfiles')))
  $rows = @($grid.FindAll([System.Windows.Automation.TreeScope]::Children, (New-Object System.Windows.Automation.PropertyCondition([System.Windows.Automation.AutomationElement]::ControlTypeProperty, [System.Windows.Automation.ControlType]::DataItem))))
  Say ("Серверов в списке v2rayN после импорта: " + $rows.Count)
  $result.import = [ordered]@{ servers_after_import = $rows.Count }
  if ($rows.Count -ge 1) {
    # NO keystrokes at all: stop this instance, write the imported server's id as the ACTIVE server into
    # v2rayN's own config (plus: system proxy "Unchanged", our local port), restart; v2rayN starts the core
    # for the active server by itself.
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $idsJson = & node (Join-Path $Root 'tests\dbget.mjs') (Join-Path $Dst 'guiConfigs\guiNDB.db') 2>$null
    $ErrorActionPreference = $prev
    $ids = @($idsJson | ConvertFrom-Json)
    Say ("Серверов в базе v2rayN: " + $ids.Count + "; тип профиля (5 = VLESS): " + (($ids | % { $_.type }) -join ','))
    $result.import.db_servers = $ids.Count
    if ($ids.Count -ge 1) {
      $cp = Join-Path $Dst 'guiConfigs\guiNConfig.json'
      $txt = [IO.File]::ReadAllText($cp)
      $reId = [regex]'"IndexId"\s*:\s*"[^"]*"'; $reSp = [regex]'"SysProxyType"\s*:\s*\d+'; $rePort = [regex]'"LocalPort"\s*:\s*\d+'
      Say ("Поля конфига найдены: IndexId=" + $reId.IsMatch($txt) + ", SysProxyType=" + $reSp.IsMatch($txt) + ", LocalPort=" + $rePort.IsMatch($txt) + " (число LocalPort: " + $rePort.Matches($txt).Count + ")")
      $txt = $reId.Replace($txt, ('"IndexId": "' + $ids[0].id + '"'), 1)
      $txt = $reSp.Replace($txt, '"SysProxyType": 2', 1)
      $txt = $rePort.Replace($txt, ('"LocalPort": ' + $Port), 1)
      [IO.File]::WriteAllText($cp, $txt, (New-Object Text.UTF8Encoding($false)))
      $p = Start-Process -FilePath (Join-Path $Dst 'v2rayN.exe') -WorkingDirectory $Dst -PassThru -RedirectStandardOutput (Join-Path $Dst 'stdout2.txt') -RedirectStandardError (Join-Path $Dst 'stderr2.txt')
      $started.Add($p.Id)
      Say 'v2rayN перезапущен с активным импортированным сервером'
      Start-Sleep -Seconds 4
      Say ("Системный прокси после перезапуска: [" + (SysProxy) + "] (изменился: " + ((SysProxy) -ne $sysBefore) + ")")
    }
  }

  $listening = $false
  # whichever port OUR xray.exe listens on (v2rayN may ignore the configured port); only a listener owned by xray from the copy counts
  for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 750
    $xr = @(Get-CimInstance Win32_Process | ? { $_.Name -eq 'xray.exe' -and $_.ExecutablePath -like "$Dst*" } | % { [int]$_.ProcessId })
    if ($xr.Count) { $hit = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ? { $xr -contains $_.OwningProcess } | select -First 1; if ($hit) { $Port = $hit.LocalPort; $listening = $true; break } }
  }
  Say ("Порт локального прокси Xray: " + $(if ($listening) { $Port } else { 'не найден' }))
  $kids = @(Get-CimInstance Win32_Process | ? { $_.ParentProcessId -eq $p.Id -or ($_.Name -eq 'xray.exe' -and $_.ExecutablePath -like "$Dst*") })
  foreach ($k in $kids) { if (-not $started.Contains([int]$k.ProcessId)) { $started.Add([int]$k.ProcessId) } }
  $xrayUp = [bool]($kids | ? { $_.Name -eq 'xray.exe' })
  $result.core = [ordered]@{ xray_started = $xrayUp; local_proxy_listening = $listening }
  Say "v2rayN: ядро Xray запущено = $xrayUp; локальный прокси :$Port слушает = $listening"

  # ---- what v2rayN generated for Xray (structure only, values redacted) ---------------------------
  $gen = Join-Path $Dst 'binConfigs\config.json'
  if (Test-Path $gen) {
    $g = Get-Content $gen -Raw -Encoding UTF8 | ConvertFrom-Json
    $ob = $g.outbounds | ? { $_.protocol -eq 'vless' } | select -First 1
    if ($ob) {
      try {
        # Xray has two outbound shapes: classic settings.vnext[0] and the newer flat settings.address/port/id
        $s = $ob.settings; $ss = $ob.streamSettings
        if ($s.vnext) { $addr = $s.vnext[0].address; $prt = $s.vnext[0].port; $flow = $s.vnext[0].users[0].flow; $shape = 'vnext' }
        else { $addr = $s.address; $prt = $s.port; $flow = $s.flow; $shape = 'flat' }
        Say ("Xray-конфиг от v2rayN (формат $shape): protocol=vless, flow=" + $flow + ", network=" + $ss.network + ", security=" + $ss.security + ", fingerprint=" + $ss.realitySettings.fingerprint + ", serverName задан=" + [bool]$ss.realitySettings.serverName + ", shortId длина=" + ([string]$ss.realitySettings.shortId).Length + ", publicKey длина=" + ([string]$ss.realitySettings.publicKey).Length + ", порт=" + $prt)
        $result.parsed_same_as_key = [ordered]@{ host = ([string]$addr -eq $u.Host); port = ([int]$prt -eq $u.Port); flow = $flow; fingerprint = [string]$ss.realitySettings.fingerprint; shortIdLength = ([string]$ss.realitySettings.shortId).Length }
        Say ("Адрес и порт, разобранные v2rayN, совпадают с ключом: адрес=" + $result.parsed_same_as_key.host + ", порт=" + $result.parsed_same_as_key.port)
      } catch { Say ("(структуру Xray-конфига разобрать не удалось: " + $_.Exception.Message + ")") }
    }
  } else { Say 'Xray-конфиг от v2rayN не создан (сервер не активирован)' }

  # ---- probes through the local v2rayN proxy: tunnel / page / country separately -----------------
  function Probe([string]$url) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $o = & curl.exe -sS --max-time 25 -x "socks5h://127.0.0.1:$Port" -o NUL -w '%{http_code}' $url 2>&1 | Out-String
    $code = $LASTEXITCODE; $ErrorActionPreference = $prev
    [pscustomobject]@{ exit = $code; out = $o.Trim() }
  }
  if ($listening) {
    $t = Probe 'https://example.com/'
    $tunnel = ($t.exit -eq 0)
    Say ("1) Туннель и загрузка страницы example.com через локальный прокси v2rayN: " + $(if ($tunnel) { "успешно (HTTP $($t.out))" } else { "НЕТ (curl exit $($t.exit): $($t.out))" }))
    $result.tunnel_and_page = [ordered]@{ ok = $tunnel; curl_exit = $t.exit; detail = (Redact $t.out) }
    if ($tunnel) {
      $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
      $c = & curl.exe -sS --max-time 25 -x "socks5h://127.0.0.1:$Port" 'https://api.country.is/' 2>&1 | Out-String
      $ErrorActionPreference = $prev
      $cc = [regex]::Match($c, '"country"\s*:\s*"([A-Z]{2})"').Groups[1].Value
      Say ("2) Страна выхода (api.country.is через v2rayN): " + $(if ($cc) { $cc } else { 'не определена: ' + (Redact $c.Trim()) }))
      $result.exit_country = $cc
    } else { Say '2) Страна выхода: не проверялась (туннель не установлен); это НЕ отказ по стране'; $result.exit_country = 'не проверялась' }
  } else { Say '1) Проверочный запрос не отправлялся: локальный прокси v2rayN не запущен'; $result.tunnel_and_page = 'не проверялось' }

  Start-Sleep -Seconds 1
  $logLines = @()
  foreach ($f in (Get-ChildItem (Join-Path $Dst 'guiLogs') -File -ErrorAction SilentlyContinue)) {
    $logLines += (Get-Content $f.FullName -Encoding UTF8 -ErrorAction SilentlyContinue | ? { $_ -match 'refused|failed|error|timeout|REALITY|reset|EOF|dial|reject' })
  }
  $uniq = @($logLines | % { Redact ([regex]::Replace($_, '^\S+\s+\S+\s+', '')) } | select -Unique | select -First 10)
  Say ("Строки журнала v2rayN/Xray (уникальные, адреса скрыты):`n   " + $(if ($uniq.Count) { $uniq -join "`n   " } else { '(нет строк с ошибками в guiLogs)' }))
  $result.log_lines = $uniq
}
finally {
  try { if ($clipHadText) { SetClip $clipBackup } } catch {}
  $all = New-Object System.Collections.Generic.HashSet[int]
  foreach ($id in $started) { [void]$all.Add($id) }
  foreach ($c in (Get-CimInstance Win32_Process | ? { $started.Contains([int]$_.ParentProcessId) })) { [void]$all.Add([int]$c.ProcessId) }
  foreach ($id in $all) { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 2
  $left = @(Get-Process -ErrorAction SilentlyContinue | ? { $_.Path -like "$Dst*" }).Count
  $sysAfter = SysProxy
  Say "Остановлено процессов, запущенных мной: $($all.Count); осталось процессов из копии: $left"
  Say "Системный прокси Windows после: [$sysAfter]; не изменился: $($sysAfter -eq $sysBefore)"
  # what v2rayN actually used / wrote (before the copy, which holds the key, is deleted)
  try {
    $cj = Get-Content (Join-Path $Dst 'guiConfigs\guiNConfig.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Say ("Итоговые настройки копии v2rayN: SysProxyType=" + $cj.SystemProxyItem.SysProxyType + ", LocalPort=" + $cj.Inbound.LocalPort + ", EnableTun=" + $cj.TunModeItem.EnableTun)
    Say ("Файлы binConfigs: " + ((Get-ChildItem (Join-Path $Dst 'binConfigs') -File -ErrorAction SilentlyContinue | % { "$($_.Name)($($_.Length))" }) -join ', '))
    foreach ($f in (Get-ChildItem (Join-Path $Dst 'guiLogs') -File -ErrorAction SilentlyContinue)) {
      Say ("--- журнал " + $f.Name + " (последние 40 строк, адреса скрыты):")
      Get-Content $f.FullName -Encoding UTF8 -Tail 40 | % { Say $_ }
    }
    foreach ($f in 'stdout.txt', 'stderr.txt') { $x = Join-Path $Dst $f; if ((Test-Path $x) -and (Get-Item $x).Length -gt 0) { Say ("--- $f :"); Get-Content $x -Tail 20 | % { Say $_ } } }
  } catch { Say ("(не удалось прочитать итоговые файлы копии: " + $_.Exception.Message + ")") }
  $result.system_proxy_unchanged = ($sysAfter -eq $sysBefore)
  if ($Dst.StartsWith($Root) -and (Test-Path $Dst)) { Remove-Item -LiteralPath $Dst -Recurse -Force -ErrorAction SilentlyContinue }
  Say ("Копия v2rayN (в ней был ключ) удалена: " + (-not (Test-Path $Dst)))
  [IO.File]::WriteAllText((Join-Path $Root '.local\logs\real-v2rayn-compare.json'), ($result | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
}

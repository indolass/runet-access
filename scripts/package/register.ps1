# Runet Access: register / unregister the native-messaging host for Google Chrome.
#
# EXACTLY ONE registry value is written (per user, no admin rights):
#   HKCU\Software\Google\Chrome\NativeMessagingHosts\com.runet_access.host
#   (Default) = <this folder>\bin\com.runet_access.host.json
# Nothing else: no system proxy, no network adapters, no services, no other browsers.
#
#   .\register.ps1              show what would be done (dry run)
#   .\register.ps1 -Apply       do it
#   .\register.ps1 -Uninstall -Apply   remove it (and the temp work folder of the host)
param([switch]$Apply, [switch]$Uninstall)
$ErrorActionPreference = 'Stop'

$HostName = 'com.runet_access.host'
$Key      = "HKCU:\Software\Google\Chrome\NativeMessagingHosts\$HostName"
$Manifest = Join-Path $PSScriptRoot "bin\$HostName.json"
$HostExe  = Join-Path $PSScriptRoot 'bin\runet-access-host.exe'
$SingBox  = Join-Path $PSScriptRoot 'bin\sing-box.exe'

if ($Uninstall) {
  Write-Host "Будет удалён ключ реестра: $Key"
  if (-not $Apply) { Write-Host "(пробный запуск, ничего не изменено; добавьте -Apply)"; return }
  if (Test-Path $Key) { Remove-Item -LiteralPath $Key -Force; Write-Host "Ключ реестра удалён." } else { Write-Host "Ключа не было." }
  $tmp = Join-Path $env:TEMP 'runet-access'
  if (Test-Path $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force; Write-Host "Временная папка удалена: $tmp" }
  Write-Host "Готово. Расширение удалите в chrome://extensions, папку программы можно удалить вручную."
  return
}

foreach ($f in $Manifest, $HostExe, $SingBox) {
  if (-not (Test-Path $f)) { throw "Не найден файл: $f. Распакуйте архив целиком и не переносите отдельные файлы." }
}
Write-Host "Будет записано одно значение реестра (только для вашего пользователя):"
Write-Host "  $Key"
Write-Host "  (по умолчанию) = $Manifest"
Write-Host "Системный прокси, сетевые адаптеры и другие браузеры не затрагиваются."
if (-not $Apply) { Write-Host "(пробный запуск, ничего не изменено; добавьте -Apply)"; return }

New-Item -Path $Key -Force | Out-Null
Set-ItemProperty -Path $Key -Name '(default)' -Value $Manifest
Write-Host "Готово. Теперь перезапустите Chrome и добавьте расширение (см. INSTALL.md)."

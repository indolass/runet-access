@echo off
rem Runet Access - uninstall (ASCII only on purpose).
echo Runet Access: removing the registration of the connection helper.
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0register.ps1" -Uninstall -Apply
echo.
pause

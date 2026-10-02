@echo off
rem Runet Access - install (ASCII only on purpose: cmd parsing breaks on other encodings).
rem Registers the native-messaging host for Google Chrome for the current user.
echo Runet Access: registering the connection helper for Google Chrome (current user only).
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0register.ps1" -Apply
echo.
pause

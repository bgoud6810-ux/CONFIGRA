@echo off
setlocal
cd /d "%~dp0"

echo Stopping CONFIGRA tunnel...
taskkill /IM cloudflared.exe /F >nul 2>&1
echo Done.

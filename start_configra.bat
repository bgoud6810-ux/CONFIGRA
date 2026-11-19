@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

rem Bind to all interfaces so phones/other PCs on the same Wi-Fi can connect.
set HOST=0.0.0.0
set PORT=5000
set CONFIGRA_DEV_RELOAD=0

set LANIP=
for /f "delims=" %%a in ('powershell -NoProfile -Command "@(Get-NetIPAddress -AddressFamily IPv4).Where({$_.IPAddress -notmatch '^(127|169\.254)\.'})[0].IPAddress"') do set "LANIP=%%a"

echo.
echo ==========================================================
echo   CONFIGRA is starting
echo ==========================================================
echo   This PC     : http://127.0.0.1:%PORT%
echo   Same Wi-Fi  : http://!LANIP!:%PORT%
echo ==========================================================
echo   Press CTRL+C to stop.
echo.
echo   If other devices cannot connect, allow Python through
echo   Windows Firewall (run once, as Administrator):
echo     New-NetFirewallRule -DisplayName "CONFIGRA Web 5000" -Direction Inbound -Protocol TCP -LocalPort %PORT% -Action Allow -Profile Any
echo.

python app.py

echo.
echo CONFIGRA stopped.
pause

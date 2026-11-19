@echo off
setlocal
cd /d "%~dp0"

if not exist "tools" mkdir "tools"

if not exist "tools\cloudflared.exe" (
    echo Downloading cloudflared ^(one time, ~55 MB^)...
    powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe' -OutFile 'tools\cloudflared.exe' -UseBasicParsing"
    if not exist "tools\cloudflared.exe" (
        echo Download failed. Check your internet connection.
        pause
        exit /b 1
    )
)

echo.
echo ==========================================================
echo   CONFIGRA public tunnel
echo ==========================================================
echo   CONFIGRA itself must already be running (start_configra.bat).
echo   Look below for:  https://something.trycloudflare.com
echo   That URL changes every time you start the tunnel.
echo   Press CTRL+C to stop the tunnel.
echo.

tools\cloudflared.exe tunnel --url http://127.0.0.1:5000 --no-autoupdate

echo.
echo Tunnel stopped.
pause

@echo off
setlocal
cd /d "%~dp0"

echo Stopping CONFIGRA on port 5000...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr /r /c:"TCP.*:5000 .*LISTENING"') do (
    echo   killing PID %%p
    taskkill /PID %%p /F >nul 2>&1
)
echo Done.

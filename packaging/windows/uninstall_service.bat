@echo off
rem Emby Proxy : Windows service removal (double-click).
rem Settings, cache and logs stay in the folder.
chcp 65001 >nul
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
EmbyProxy-service.exe stop
rem wait for a complete stop before removing the service
powershell -NoProfile -Command "for ($i=0; $i -lt 30 -and (Get-Service EmbyProxy -ErrorAction SilentlyContinue).Status -eq 'Running'; $i++) { Start-Sleep 1 }"
EmbyProxy-service.exe uninstall
netsh advfirewall firewall delete rule name="Emby Proxy - users" >nul 2>&1
netsh advfirewall firewall delete rule name="Emby Proxy - admin" >nul 2>&1
netsh advfirewall firewall delete rule name="Emby Proxy - utilisateurs" >nul 2>&1
netsh advfirewall firewall delete rule name="Emby Proxy - administration" >nul 2>&1
echo.
echo  Emby Proxy service removed. Settings, cache and logs are kept.
pause

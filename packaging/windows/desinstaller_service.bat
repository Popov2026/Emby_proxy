@echo off
rem Emby Proxy : desinstallation du service Windows (double-clic).
rem Les reglages, le cache et les journaux restent dans le dossier.
chcp 65001 >nul
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"
EmbyProxy-service.exe stop
rem attendre l'arret complet avant de retirer le service
powershell -NoProfile -Command "for ($i=0; $i -lt 30 -and (Get-Service EmbyProxy -ErrorAction SilentlyContinue).Status -eq 'Running'; $i++) { Start-Sleep 1 }"
EmbyProxy-service.exe uninstall
netsh advfirewall firewall delete rule name="Emby Proxy - utilisateurs" >nul 2>&1
netsh advfirewall firewall delete rule name="Emby Proxy - administration" >nul 2>&1
echo.
echo  Service Emby Proxy desinstalle. Reglages, cache et journaux sont conserves.
pause

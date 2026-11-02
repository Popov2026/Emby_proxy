@echo off
rem ===================================================================
rem  Emby Proxy : installation du service Windows (double-clic)
rem  Emby Proxy : Windows service installation (double-click)
rem  - demarre avec Windows / starts with Windows
rem  - redemarre en cas de plantage / restarts after a crash
rem ===================================================================
chcp 65001 >nul
setlocal EnableExtensions
cd /d "%~dp0"

rem -- droits administrateur / administrator rights
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"

echo.
echo  Installation d'Emby Proxy comme service Windows
echo  Installing Emby Proxy as a Windows service
echo  Dossier / Folder : %~dp0
echo.

if not exist "emby_proxy.exe" (
    echo  ERREUR : emby_proxy.exe introuvable dans ce dossier.
    echo  ERROR  : emby_proxy.exe not found in this folder.
    goto :failed
)

rem -- installation precedente remplacee / previous installation replaced
EmbyProxy-service.exe stop >nul 2>&1
EmbyProxy-service.exe uninstall >nul 2>&1

EmbyProxy-service.exe install
if errorlevel 1 goto :failed

rem -- pare-feu / firewall : users' port (8097) open,
rem    admin page (8098) from the local network only
rem    (anciennes regles aux noms francais retirees / old French-named rules removed)
netsh advfirewall firewall delete rule name="Emby Proxy - utilisateurs" >nul 2>&1
netsh advfirewall firewall delete rule name="Emby Proxy - administration" >nul 2>&1
netsh advfirewall firewall delete rule name="Emby Proxy - users" >nul 2>&1
netsh advfirewall firewall add rule name="Emby Proxy - users" dir=in action=allow protocol=TCP localport=8097 >nul
netsh advfirewall firewall delete rule name="Emby Proxy - admin" >nul 2>&1
netsh advfirewall firewall add rule name="Emby Proxy - admin" dir=in action=allow protocol=TCP localport=8098 remoteip=localsubnet >nul

EmbyProxy-service.exe start
if errorlevel 1 goto :failed

rem -- premier demarrage : emby_proxy.ini et mot de passe crees
rem    first start: emby_proxy.ini and password are created
set "PWD_VALUE="
for /l %%i in (1,1,30) do (
    for /f "tokens=1,* delims==" %%a in ('findstr /b /c:"password = " emby_proxy.ini 2^>nul') do set "PWD_VALUE=%%b"
    if defined PWD_VALUE goto :ready
    timeout /t 1 /nobreak >nul
)
:ready
echo.
echo  ============================================================
echo   Service installe et demarre (redemarre avec Windows).
echo   Service installed and started (starts with Windows).
echo.
echo   Page d'administration / Admin page : http://localhost:8098/
echo   (autre appareil / other device : http://THIS-PC-ADDRESS:8098/)
if defined PWD_VALUE echo   Mot de passe / Password :%PWD_VALUE%
echo   (emby_proxy.ini, section [status])
echo.
echo   Ensuite / Next : onglet Configuration / Settings tab,
echo   adresse d'Emby et cle API / Emby address and API key, Enregistrer / Save.
echo  ============================================================
echo.
start "" "http://localhost:8098/"
pause
exit /b 0

:failed
echo.
echo  L'installation a echoue / Installation failed.
echo  Detail : EmbyProxy-service.wrapper.log, EmbyProxy-service.err.log
pause
exit /b 1

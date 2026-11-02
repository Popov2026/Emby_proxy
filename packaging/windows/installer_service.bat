@echo off
rem ===================================================================
rem  Emby Proxy : installation du service Windows (double-clic)
rem  - demarre automatiquement avec Windows, meme sans session ouverte
rem  - redemarre tout seul en cas de plantage
rem ===================================================================
chcp 65001 >nul
setlocal EnableExtensions
cd /d "%~dp0"

rem -- droits administrateur demandes automatiquement
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"

echo.
echo  Installation d'Emby Proxy comme service Windows
echo  Dossier : %~dp0
echo.

if not exist "emby_proxy.exe" (
    echo  ERREUR : emby_proxy.exe est introuvable dans ce dossier.
    goto :echec
)

rem -- ancienne installation : on la remplace
EmbyProxy-service.exe stop >nul 2>&1
EmbyProxy-service.exe uninstall >nul 2>&1

EmbyProxy-service.exe install
if errorlevel 1 goto :echec

rem -- pare-feu : port des utilisateurs (8097) ouvert ;
rem    page d'administration (8098) seulement depuis le reseau local
netsh advfirewall firewall delete rule name="Emby Proxy - utilisateurs" >nul 2>&1
netsh advfirewall firewall add rule name="Emby Proxy - utilisateurs" dir=in action=allow protocol=TCP localport=8097 >nul
netsh advfirewall firewall delete rule name="Emby Proxy - administration" >nul 2>&1
netsh advfirewall firewall add rule name="Emby Proxy - administration" dir=in action=allow protocol=TCP localport=8098 remoteip=localsubnet >nul

EmbyProxy-service.exe start
if errorlevel 1 goto :echec

rem -- au premier demarrage le proxy cree emby_proxy.ini et le mot de passe
set "MDP="
for /l %%i in (1,1,30) do (
    for /f "tokens=1,* delims==" %%a in ('findstr /b /c:"password = " emby_proxy.ini 2^>nul') do set "MDP=%%b"
    if defined MDP goto :pret
    timeout /t 1 /nobreak >nul
)
:pret
echo.
echo  ============================================================
echo   Service installe et demarre.
echo   Il redemarrera tout seul avec Windows.
echo.
echo   Page d'administration :  http://localhost:8098/
echo   (depuis un autre appareil de la maison : http://ADRESSE-DE-CE-PC:8098/)
if defined MDP echo   Mot de passe          :%MDP%
echo   (il est aussi dans emby_proxy.ini, section [status])
echo.
echo   Etape suivante : onglet Configuration, adresse de ton Emby
echo   et cle API, puis Enregistrer.
echo  ============================================================
echo.
start "" "http://localhost:8098/"
pause
exit /b 0

:echec
echo.
echo  L'installation a echoue. Le detail est dans EmbyProxy-service.wrapper.log
echo  et EmbyProxy-service.err.log, dans ce dossier.
pause
exit /b 1

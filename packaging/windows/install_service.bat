@echo off
rem ===================================================================
rem  Emby Proxy : Windows service installation (double-click)
rem  - starts with Windows, even when nobody is logged in
rem  - restarts by itself after a crash
rem ===================================================================
chcp 65001 >nul
setlocal EnableExtensions
cd /d "%~dp0"

rem -- administrator rights are requested automatically
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
cd /d "%~dp0"

if not exist "emby_proxy.exe" (
    echo  ERROR: emby_proxy.exe not found in this folder.
    goto :failed
)
set "VERSION=Emby Proxy"
for /f "delims=" %%v in ('emby_proxy.exe --version 2^>nul') do set "VERSION=%%v"

echo.
echo  Installing %VERSION% as a Windows service
echo  Folder: %~dp0
echo.

rem -- a previous installation is replaced
EmbyProxy-service.exe stop >nul 2>&1
EmbyProxy-service.exe uninstall >nul 2>&1

EmbyProxy-service.exe install
if errorlevel 1 goto :failed

rem -- firewall: users' port (8097) open, admin page (8098) from the local
rem    network only (old French-named rules are removed)
netsh advfirewall firewall delete rule name="Emby Proxy - utilisateurs" >nul 2>&1
netsh advfirewall firewall delete rule name="Emby Proxy - administration" >nul 2>&1
netsh advfirewall firewall delete rule name="Emby Proxy - users" >nul 2>&1
netsh advfirewall firewall add rule name="Emby Proxy - users" dir=in action=allow protocol=TCP localport=8097 >nul
netsh advfirewall firewall delete rule name="Emby Proxy - admin" >nul 2>&1
netsh advfirewall firewall add rule name="Emby Proxy - admin" dir=in action=allow protocol=TCP localport=8098 remoteip=localsubnet >nul

EmbyProxy-service.exe start
if errorlevel 1 goto :failed

echo.
echo  Waiting for the admin page to be ready...
rem -- the admin page is opened only once it answers (up to 60 s)
set "ADMIN_PORT="
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0wait_admin_page.ps1" > "%TEMP%\emby_proxy_port.txt" 2>nul
if not errorlevel 1 set /p ADMIN_PORT=<"%TEMP%\emby_proxy_port.txt"
del "%TEMP%\emby_proxy_port.txt" >nul 2>&1

set "PWD_VALUE="
for /f "tokens=1,* delims==" %%a in ('findstr /b /c:"password = " emby_proxy.ini 2^>nul') do set "PWD_VALUE=%%b"

echo.
echo  ============================================================
echo   %VERSION% installed and started (it starts with Windows).
echo.
if defined ADMIN_PORT (
    echo   Admin page is ready: http://localhost:%ADMIN_PORT%/
) else (
    echo   The admin page does not answer yet: open http://localhost:8098/
    echo   in a moment. Details: emby_proxy.log in this folder.
)
echo   From another device at home: http://THIS-PC-ADDRESS:8098/
if defined PWD_VALUE echo   Password:%PWD_VALUE%
echo   (also in emby_proxy.ini, [status] section)
echo.
echo   Next: Settings tab, your Emby address and API key, then Save.
echo   The English / Francais button (top right) switches the language.
echo  ============================================================
echo.
if defined ADMIN_PORT start "" "http://localhost:%ADMIN_PORT%/"
pause
exit /b 0

:failed
echo.
echo  Installation failed. Details: EmbyProxy-service.wrapper.log and
echo  EmbyProxy-service.err.log in this folder.
pause
exit /b 1

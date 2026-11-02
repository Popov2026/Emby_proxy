@echo off
rem Compilation locale de la version Windows (si on ne passe pas par GitHub).
rem Resultat : dist\EmbyProxy, pret a copier dans C:\EmbyProxy.
chcp 65001 >nul
cd /d "%~dp0"
py -m pip install -r requirements.txt pyinstaller || goto :err
py -m PyInstaller --noconfirm --onefile --console --name emby_proxy --hidden-import emby_quota --hidden-import emby_quota_i18n --hidden-import emby_proxy_lang emby_proxy.py || goto :err
if not exist dist\EmbyProxy mkdir dist\EmbyProxy
copy /y dist\emby_proxy.exe dist\EmbyProxy\ >nul
copy /y packaging\windows\* dist\EmbyProxy\ >nul
copy /y emby_quota.ini.example dist\EmbyProxy\ >nul
copy /y emby_proxy.example.ini dist\EmbyProxy\ >nul
if not exist dist\EmbyProxy\EmbyProxy-service.exe powershell -NoProfile -Command "Invoke-WebRequest https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe -OutFile dist\EmbyProxy\EmbyProxy-service.exe" || goto :err
echo.
echo Pret : dist\EmbyProxy  (copie-le dans C:\EmbyProxy puis lance installer_service.bat)
pause
exit /b 0
:err
echo Echec de la compilation.
pause
exit /b 1

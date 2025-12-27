@echo off
echo Установка ML Security Scanner v1.0.0
echo =====================================

REM Определяем путь установки
set INSTALL_PATH=%LOCALAPPDATA%\ML-Scanner

echo Установка в: %INSTALL_PATH%

REM Создаем папку
if not exist "%INSTALL_PATH%" mkdir "%INSTALL_PATH%"

REM Извлекаем архив (предполагаем, что архив рядом)
if exist "%~dp0..\releases\windows\scan-latest.zip" (
    powershell -Command "Expand-Archive -Path '%~dp0..\releases\windows\scan-latest.zip' -DestinationPath '%INSTALL_PATH%' -Force"
    echo Файлы распакованы
) else (
    echo Ошибка: архив scan-latest.zip не найден
    pause
    exit /b 1
)

REM Добавляем в PATH
echo Добавляем в переменную PATH...
setx PATH "%PATH%;%INSTALL_PATH%\scan" /M

REM Создаем ярлык на рабочем столе
echo Создаю ярлык на рабочем столе...
echo Set oWS = WScript.CreateObject("WScript.Shell") > "%TEMP%\create_shortcut.vbs"
echo sLinkFile = "%USERPROFILE%\Desktop\ML Scanner.lnk" >> "%TEMP%\create_shortcut.vbs"
echo Set oLink = oWS.CreateShortcut(sLinkFile) >> "%TEMP%\create_shortcut.vbs"
echo oLink.TargetPath = "%INSTALL_PATH%\scan\scan.exe" >> "%TEMP%\create_shortcut.vbs"
echo oLink.WorkingDirectory = "%INSTALL_PATH%\scan" >> "%TEMP%\create_shortcut.vbs"
echo oLink.Description = "ML Security Scanner" >> "%TEMP%\create_shortcut.vbs"
echo oLink.Save >> "%TEMP%\create_shortcut.vbs"
cscript //nologo "%TEMP%\create_shortcut.vbs"
del "%TEMP%\create_shortcut.vbs"

echo.
echo =====================================
echo Установка завершена!
echo 1. Ярлык создан на рабочем столе
echo 2. Можно запускать из командной строки: scan модель.pth
echo 3. Или щелкнуть по ярлыку на рабочем столе
echo =====================================
pause
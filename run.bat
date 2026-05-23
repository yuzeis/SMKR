@echo off
chcp 65001 >nul
setlocal EnableExtensions

cd /d "%~dp0"
set "PYTHONPATH=%CD%\src;%PYTHONPATH%"

set "PY="
where python.exe >nul 2>&1
if not errorlevel 1 (
    set "PY=python"
    goto :found_py
)
where py.exe >nul 2>&1
if not errorlevel 1 (
    set "PY=py -3"
    goto :found_py
)

echo.
echo [ERROR] Python 3.10+ not found. Install Python and enable "Add Python to PATH".
echo.
pause
exit /b 1

:found_py
echo [info] Python: %PY%

taskkill /F /FI "WINDOWTITLE eq RKMS Divert*" >nul 2>&1

for %%L in (18195 18196) do (
    for /f "tokens=5" %%P in ('netstat -ano ^| findstr /R /C:":%%L .*LISTENING"') do (
        if not "%%P"=="0" (
            echo [info] Stop old listener: port=%%L pid=%%P
            taskkill /F /PID %%P >nul 2>&1
        )
    )
)
timeout /t 1 /nobreak >nul

for %%L in (18195 18196) do (
    netstat -ano | findstr /R /C:":%%L .*LISTENING" >nul 2>&1
    if not errorlevel 1 (
        echo [ERROR] Port %%L is still in use. Close the old RKMS process or run this bat as administrator.
        netstat -ano | findstr /R /C:":%%L .*LISTENING"
        pause
        exit /b 1
    )
)

%PY% -c "import aiohttp, Crypto, psutil" >nul 2>&1
if errorlevel 1 (
    echo [info] Installing web dependencies: aiohttp pycryptodome psutil ...
    %PY% -m pip install --user --upgrade aiohttp pycryptodome psutil
    if errorlevel 1 (
        echo.
        echo [ERROR] Failed to install web dependencies. Run manually:
        echo        %PY% -m pip install --user aiohttp pycryptodome psutil
        echo.
        pause
        exit /b 1
    )
)

set "SKIP_DIVERT="
if /i "%RKMS_SKIP_DIVERT%"=="1" set "SKIP_DIVERT=1"
if not defined SKIP_DIVERT (
    %PY% -c "import pydivert" >nul 2>&1
    if errorlevel 1 (
        echo [info] Installing optional WinDivert dependency: pydivert ...
        %PY% -m pip install --user --upgrade pydivert
        if errorlevel 1 (
            echo [warn] WinDivert dependencies failed. Web UI will still start.
            set "SKIP_DIVERT=1"
        )
    )
)

if exist "src\roco_mitm\divert\proc_divert.py" if not defined SKIP_DIVERT (
    echo [info] Starting WinDivert redirector. Confirm UAC if prompted.
    start "RKMS Divert" cmd /d /c "%PY% -m roco_mitm divert --run || (echo. & echo [ERROR] WinDivert redirector exited with error. & pause)"
)
if defined SKIP_DIVERT (
    echo [warn] WinDivert skipped. Set RKMS_SKIP_DIVERT=0 and install psutil/pydivert to enable it.
)

echo.
echo ========================================================
echo   RocoMITMServer Ver2.1 Verzweifelt ^(RKMS^) - Web Mode
echo ========================================================
echo.
echo [info] Web UI: http://127.0.0.1:18196/
echo.
%PY% -m roco_mitm web

if errorlevel 1 (
    echo.
    echo [ERROR] RKMS exited with error code %ERRORLEVEL%.
    pause
)
endlocal

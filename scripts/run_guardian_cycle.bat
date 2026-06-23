@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%..") do set "PROJECT_ROOT=%%~fI"
set "DJANGO_DIR=%PROJECT_ROOT%\GuardianNet\GuardianNet"
set "LOG_DIR=%PROJECT_ROOT%\logs"
set "LOG_FILE=%LOG_DIR%\monitoring_cycle_task.log"

if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

cd /d "%DJANGO_DIR%" || (
    echo [%date% %time%] ERROR: Could not enter Django directory "%DJANGO_DIR%" >> "%LOG_FILE%"
    exit /b 1
)

echo [%date% %time%] Starting GuardianNet monitoring cycle >> "%LOG_FILE%"
python manage.py run_monitoring_cycle --scan-limit 10 >> "%LOG_FILE%" 2>&1
set "EXIT_CODE=%ERRORLEVEL%"
echo [%date% %time%] Finished GuardianNet monitoring cycle with exit code %EXIT_CODE% >> "%LOG_FILE%"

exit /b %EXIT_CODE%

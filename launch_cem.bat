@echo off
title Certificate Expiry Monitor
cd /d "%~dp0"

REM Check for virtual environment
if exist ".venv\Scripts\activate.bat" (
    echo [*] Activating virtual environment...
    call .venv\Scripts\activate.bat
) else (
    echo [!] Virtual environment not found. Run this first:
    echo     python -m venv .venv
    echo     .venv\Scripts\activate
    echo     pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

:menu
cls
echo ============================================
echo   Certificate Expiry Monitor (CEM)
echo ============================================
echo.
echo Commands:
echo   1) Quick check (default targets)
echo   2) Check custom URL
echo   3) Continuous monitor mode
echo   4) Start API server
echo   5) Dry-run (no email sent)
echo   0) Exit
echo.

set /p CHOICE="Select option (0-5): "

REM Remove any spaces
set CHOICE=%CHOICE: =%

if "%CHOICE%"=="1" (
    echo.
    echo [*] Running certificate check with example config...
    python -m checker --config example_config.yaml
    echo.
    echo [*] Check complete.
    pause
    exit /b
)

if "%CHOICE%"=="2" (
    set /p URL="Enter URL to check (e.g. https://google.com): "
    echo.
    echo [*] Checking: %URL%
    python -m checker --url "%URL%" --verbose
    echo.
    pause
    exit /b
)

if "%CHOICE%"=="3" (
    set /p INTERVAL="Check interval in seconds (default 21600 = 6 hours): "
    if "%INTERVAL%"=="" set INTERVAL=21600
    echo.
    echo [*] Starting monitor mode (interval: %INTERVAL%s)...
    echo [*] Press Ctrl+C to stop.
    echo.
    python -m checker monitor --config example_config.yaml --interval %INTERVAL%
    pause
    exit /b
)

if "%CHOICE%"=="4" (
    set /p PORT="API server port (default 8000): "
    if "%PORT%"=="" set PORT=8000
    echo.
    echo [*] Starting API server on http://127.0.0.1:%PORT%/api/monitors
    echo [*] Press Ctrl+C to stop.
    echo.
    python -m checker serve --config example_config.yaml --port %PORT%
    pause
    exit /b
)

if "%CHOICE%"=="5" (
    echo.
    echo [*] Running dry-run check (no emails sent)...
    python -m checker --config example_config.yaml --dry-run --verbose
    echo.
    pause
    exit /b
)

if "%CHOICE%"=="0" (
    echo Exiting.
    exit /b 0
)

REM Invalid choice
echo.
echo [!] Invalid option "%CHOICE%"
echo Press any key to try again...
pause >nul
goto menu

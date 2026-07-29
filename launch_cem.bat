@echo off
setlocal enabledelayedexpansion
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
echo   2) Check custom URL(s) - multiple allowed!
echo   3) Continuous monitor mode
echo   4) Start API server
echo   5) Dry-run (no email sent)
echo   6) One-shot check (exits after)
echo   0) Exit
echo.

set /p CHOICE="Select option (0-6): "

REM Remove any spaces
set CHOICE=%CHOICE: =%

if "%CHOICE%"=="1" (
    echo.
    echo [*] Running certificate check with example config...
    python -m checker --config example_config.yaml
    echo.
    echo [*] Check complete.
    echo.
    echo Press any key to return to menu...
    pause >nul
    goto menu
)

if "%CHOICE%"=="2" goto check_url_handler

if "%CHOICE%"=="3" (
    set /p INTERVAL="Check interval in seconds (default 21600 = 6 hours): "
    if "%INTERVAL%"=="" set INTERVAL=21600
    echo.
    echo [*] Starting monitor mode (interval: %INTERVAL%s)...
    echo [*] Press Ctrl+C to stop.
    echo.
    python -m checker monitor --config example_config.yaml --interval %INTERVAL%
    echo.
    echo [*] Monitor stopped.
    echo Press any key to return to menu...
    pause >nul
    goto menu
)

if "%CHOICE%"=="4" (
    set /p PORT="API server port (default 8000): "
    if "%PORT%"=="" set PORT=8000
    echo.
    echo [*] Starting API server on http://127.0.0.1:%PORT%/api/monitors
    echo [*] Press Ctrl+C to stop.
    echo.
    python -m checker serve --config example_config.yaml --port %PORT%
    echo.
    echo [*] Server stopped.
    echo Press any key to return to menu...
    pause >nul
    goto menu
)

if "%CHOICE%"=="5" (
    echo.
    echo [*] Running dry-run check (no emails sent)...
    python -m checker --config example_config.yaml --dry-run --verbose
    echo.
    echo [*] Dry-run complete.
    echo Press any key to return to menu...
    pause >nul
    goto menu
)

if "%CHOICE%"=="0" (
    echo Exiting.
    exit /b 0
)

if "%CHOICE%"=="6" (
    set /p URL="Enter URL to check (e.g. https://google.com): "
    if "%URL%"=="" (
        echo [!] No URL entered.
        timeout /t 2 >nul
        goto menu
    )
    echo.
    python -m checker --url "%URL%"
    echo.
    pause
    exit /b
)

REM Invalid choice
echo.
echo [!] Invalid option "%CHOICE%"
echo Press any key to try again...
pause >nul
goto menu


REM ============================================
REM  Custom URL check handler (loop)
REM  Label is OUTSIDE the if block for safety
REM ============================================
:check_url_handler
:check_url_loop
set URL=
set /p URL="Enter URL to check (e.g. https://google.com): "
if "%URL%"=="" (
    echo [!] No URL entered. Returning to menu...
    timeout /t 2 >nul
    goto menu
)
echo.
echo [*] Checking: %URL%
echo.
python -m checker --url "%URL%" --verbose
echo.
echo ============================================
echo  Result for: %URL%
echo ============================================
echo.
set ANOTHER=
set /p ANOTHER="Check another URL? (Y/n): "
if /i "!ANOTHER!"=="" goto check_url_loop
if /i "!ANOTHER!"=="y" goto check_url_loop
if /i "!ANOTHER!"=="yes" goto check_url_loop
echo.
echo Returning to main menu...
timeout /t 1 >nul
goto menu

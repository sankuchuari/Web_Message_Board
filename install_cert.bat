@echo off
:: This line moves the script's focus to the folder where the .bat is saved
cd /d "%~dp0"

setlocal

echo ======================================================
echo Certificate Auto-Installer for Windows
echo ======================================================

:: 1. Check if the certificate file exists in the CURRENT folder
if not exist "cert.pem" (
    echo [ERROR] cert.pem not found at: %cd%
    echo Please ensure the .pem file is in the same folder as this script.
    pause
    exit /b 1
)

:: 2. Install the certificate
echo [INFO] Installing cert.pem into Trusted Root Store...
certutil -addstore -f "Root" "cert.pem"

if %errorlevel% equ 0 (
    echo.
    echo [SUCCESS] Certificate installed! Restart Chrome to see changes.
) else (
    echo.
    echo [FAILED] Please right-click and select "Run as administrator".
)

pause
endlocal
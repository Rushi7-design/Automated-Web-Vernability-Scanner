@echo off
title MongoDB Community Server Downloader & Installer
echo ============================================================
echo           MongoDB Community Server Auto-Installer
echo ============================================================
echo.

:: Check permissions
openfiles >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] Error: Please run this script as Administrator.
    echo Right-click this file and choose "Run as administrator".
    pause
    exit /b
)

:: Download MongoDB MSI package
set MSI_URL=https://fastdl.mongodb.org/windows/mongodb-windows-x86_64-7.0.6-signed.msi
set DEST_MSI=%temp%\mongodb.msi

echo [*] Downloading MongoDB Community Server MSI (approx. 480MB)...
echo Please wait, this may take a few minutes depending on your internet speed.
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object System.Net.WebClient).DownloadFile('%MSI_URL%', '%DEST_MSI%')"

if not exist "%DEST_MSI%" (
    echo [-] Error: Failed to download MongoDB installer. Check your internet connection.
    pause
    exit /b
)

echo [+] Download completed successfully.
echo [*] Installing MongoDB Server silently (default folder: C:\Program Files\MongoDB\)...
msiexec.exe /i "%DEST_MSI%" /qd /l*v "%temp%\mongodb_install.log" SHOULD_INSTALL_COMPASS=0 ADDLOCAL="ServerService,Server"

echo [*] Verifying MongoDB Service...
timeout /t 5 >nul
sc query MongoDB >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] MongoDB Windows Service created successfully.
    echo [*] Starting MongoDB service...
    net start MongoDB >nul 2>&1
    echo [+] MongoDB service is now running!
) else (
    echo [!] Warning: MongoDB service not found. Starting manual directory setup...
    set DB_DIR=C:\data\db
    if not exist "%DB_DIR%" mkdir "%DB_DIR%"
    echo [+] Created default database folder: C:\data\db
)

echo.
echo ============================================================
echo [+] MongoDB Installation Complete!
echo You can now start the scanner using run_scanner.bat safely.
echo ============================================================
pause

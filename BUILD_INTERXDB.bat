@echo off
:: ============================================================
:: BUILD_INTERXDB.bat
:: Builds InterXDB_FFServer.exe using PyInstaller
:: Output: dist\InterXDB_FFServer\InterXDB_FFServer.exe
:: ============================================================

cd /d "%~dp0"

echo.
echo ============================================================
echo  InterXDB_FFServer - EXE Build
echo ============================================================
echo.

:: Check Python is available
py -3 --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 3 not found. Install from python.org
    pause
    exit /b 1
)

:: Check PyInstaller
py -3 -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing PyInstaller...
    py -3 -m pip install pyinstaller
)

:: Check PyQt6
py -3 -c "import PyQt6" >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing PyQt6...
    py -3 -m pip install PyQt6
)

echo [INFO] Starting build...
echo.

py -3 -m PyInstaller InterXDB_FFServer.spec --clean

if errorlevel 1 (
    echo.
    echo [ERROR] Build failed. Check output above.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  Build complete!
echo  EXE: dist\InterXDB_FFServer\InterXDB_FFServer.exe
echo ============================================================
echo.
pause

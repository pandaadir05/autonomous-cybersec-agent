@echo off
echo === VENV GIT TRACKING FIX UTILITY ===
echo.

REM Check if Python is available
where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo Running Python fix script...
    python scripts\venv_fix.py
) else (
    echo Python not found, running PowerShell script instead...
    powershell -ExecutionPolicy Bypass -File scripts\fix-venv.ps1
)

echo.
echo === MANUAL STEPS TO COMPLETE FIX ===
echo.
echo 1. Run: git add .gitignore
echo 2. Run: git commit -m "Fix: Remove venv from Git tracking"
echo.
echo Press any key to exit...
pause > nul

@echo off
echo Fixing virtual environment tracking in Git...
echo.

REM Check if Python is installed
where python >nul 2>&1
if %ERRORLEVEL% neq 0 (
  echo Python not found. Trying to run PowerShell script instead.
  powershell -ExecutionPolicy Bypass -File scripts\fix_venv_tracking.ps1
) else (
  python scripts\fix_gitignore.py
)

echo.
echo Press any key to exit...
pause >nul

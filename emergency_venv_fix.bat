@echo off
echo === EMERGENCY VENV FIX ===
echo.

echo Step 1: Creating fresh .gitignore with venv rules...
echo # Virtual Environment - DO NOT TRACK> .gitignore.new
echo venv/>> .gitignore.new
echo /venv/>> .gitignore.new
echo venv/**/*>> .gitignore.new
echo /venv/**/*>> .gitignore.new
echo .venv/>> .gitignore.new
echo /.venv/>> .gitignore.new
echo env/>> .gitignore.new
echo /env/>> .gitignore.new
echo ENV/>> .gitignore.new
echo /ENV/>> .gitignore.new
echo.>> .gitignore.new

echo Step 2: Appending existing .gitignore content...
if exist .gitignore (
    type .gitignore >> .gitignore.new
)

echo Step 3: Replacing old .gitignore...
move /y .gitignore.new .gitignore

echo Step 4: Forcibly removing venv from Git tracking (without deleting files)...
git rm -r --cached venv --force 2>nul

echo.
echo === MANUAL STEPS TO COMPLETE FIX ===
echo.
echo 1. Run: git add .gitignore
echo 2. Run: git commit -m "Fix: Remove venv directory from version control"
echo.
echo Press any key to exit...
pause > nul

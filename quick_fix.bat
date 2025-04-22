@echo off
echo Creating strong venv exclusion in .gitignore and removing venv from tracking...
(echo # Virtual Environment - DO NOT REMOVE THESE LINES & echo venv/ & echo /venv/ & echo venv/** & echo /venv/** & echo.) > .gitignore.tmp
if exist .gitignore type .gitignore >> .gitignore.tmp
move /y .gitignore.tmp .gitignore
git rm -r --cached venv --force 2>nul
echo Now run: git add .gitignore && git commit -m "Fix: Remove venv from Git tracking"
pause

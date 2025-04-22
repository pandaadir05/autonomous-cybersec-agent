# Script to untrack the venv directory without deleting it

Write-Host "Fixing Git tracking for venv directory..." -ForegroundColor Green

# Make sure we're in the repository root
if (-not (Test-Path ".git")) {
    Write-Host "Error: This script must be run from the repository root directory." -ForegroundColor Red
    exit 1
}

# Untrack the venv directory without deleting files
Write-Host "Removing venv directory from Git tracking (files will remain on disk)..." -ForegroundColor Yellow
git rm -r --cached venv/

# Add additional entries to .gitignore if needed
Write-Host "Ensuring .gitignore has proper venv entries..." -ForegroundColor Yellow
$gitignoreContent = Get-Content .gitignore -ErrorAction SilentlyContinue
$venvEntries = @("venv/", "/venv/", "venv/*", "**/__pycache__/")
$addedEntries = $false

foreach ($entry in $venvEntries) {
    if (-not ($gitignoreContent -match "^$entry$")) {
        if (-not $addedEntries) {
            Add-Content -Path .gitignore -Value "`n# Virtual Environment (added by fix script)"
            $addedEntries = $true
        }
        Add-Content -Path .gitignore -Value $entry
    }
}

# Set Git config to properly handle line endings
Write-Host "Configuring Git to handle line endings properly..." -ForegroundColor Yellow
git config core.autocrlf true

Write-Host "Done! Now you should commit these changes:" -ForegroundColor Green
Write-Host "  git add .gitignore" -ForegroundColor Cyan
Write-Host "  git commit -m ""Remove venv directory from Git tracking""" -ForegroundColor Cyan

Write-Host "Future git commands should no longer track the venv directory." -ForegroundColor Green

# PowerShell script to fix Git tracking venv directory issue

Write-Host "`n=== VENV GIT TRACKING FIX ===`n" -ForegroundColor Cyan

# Check if we're in a Git repository
if (-not (Test-Path ".git")) {
    Write-Host "Error: Not in a Git repository root directory." -ForegroundColor Red
    Write-Host "Current directory: $pwd" -ForegroundColor Red
    exit 1
}

# Check if venv is tracked
$trackedFiles = git ls-files | Select-String -Pattern "venv/" -Quiet
if ($trackedFiles) {
    Write-Host "Found venv files in Git tracking. Removing them..." -ForegroundColor Yellow
    git rm -r --cached --force venv 2>$null
} else {
    Write-Host "No venv files found in Git tracking." -ForegroundColor Green
}

# Update .gitignore file
Write-Host "Updating .gitignore file..." -ForegroundColor Yellow

$venvRules = @"
# Virtual Environment - DO NOT REMOVE OR MODIFY THESE LINES
venv/
/venv/
venv/**/*
/venv/**/*
.venv/
/.venv/
env/
/env/
ENV/
/ENV/

"@

# Check if .gitignore exists
if (Test-Path ".gitignore") {
    # Read existing content
    $existingContent = Get-Content -Path ".gitignore" -Raw -ErrorAction SilentlyContinue
    
    # Create new content with venv rules at the top
    if ($existingContent -notmatch "# Virtual Environment - DO NOT REMOVE") {
        $newContent = $venvRules + $existingContent
    } else {
        $newContent = $existingContent
    }
} else {
    $newContent = $venvRules
}

# Write content back
$newContent | Set-Content -Path ".gitignore" -Encoding utf8

Write-Host "Successfully updated .gitignore with venv exclusion rules." -ForegroundColor Green

# Instructions for next steps
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "1. Run: git add .gitignore" -ForegroundColor White
Write-Host "2. Run: git commit -m `"Fix: Remove venv from Git tracking`"" -ForegroundColor White
Write-Host "3. On future git commands, venv should no longer be tracked" -ForegroundColor White

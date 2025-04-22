#!/bin/bash
# Script to untrack the venv directory without deleting it

echo "Fixing Git tracking for venv directory..."

# Make sure we're in the repository root
if [ ! -d ".git" ]; then
  echo "Error: This script must be run from the repository root directory."
  exit 1
fi

# Untrack the venv directory without deleting files
echo "Removing venv directory from Git tracking (files will remain on disk)..."
git rm -r --cached venv/

# Add additional entries to .gitignore if needed
echo "Ensuring .gitignore has proper venv entries..."
if ! grep -q "^venv/$" .gitignore; then
  echo -e "\n# Virtual Environment (added by fix script)" >> .gitignore
  echo "venv/" >> .gitignore
  echo "/venv/" >> .gitignore
  echo "venv/*" >> .gitignore
  echo "**/__pycache__/" >> .gitignore
fi

# Set Git config to properly handle line endings
echo "Configuring Git to handle line endings properly..."
git config core.autocrlf true

echo "Done! Now you should commit these changes:"
echo "  git add .gitignore"
echo "  git commit -m \"Remove venv directory from Git tracking\""

echo "Future git commands should no longer track the venv directory."

"""
Script to fix Git tracking issues with virtual environments.
This will untrack the venv directory without deleting it.
"""

import os
import subprocess
import sys
import re

def run_command(command, quiet=False):
    """Run a shell command and print output."""
    if not quiet:
        print(f"Executing: {command}")
    
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    if process.stdout and not quiet:
        print(f"Output: {process.stdout.strip()}")
    
    if process.returncode != 0 and process.stderr:
        print(f"Error: {process.stderr.strip()}")
        return False
    
    return True

def is_git_repo():
    """Check if current directory is a git repository."""
    return os.path.exists(".git")

def check_if_venv_tracked(venv_dir="venv"):
    """Check if the venv directory is tracked by git."""
    if not os.path.exists(venv_dir):
        return False
        
    result = subprocess.run(
        f"git ls-files {venv_dir} | head -1",
        shell=True, capture_output=True, text=True
    )
    
    return bool(result.stdout.strip())

def update_gitignore():
    """Update .gitignore with proper venv entries."""
    with open(".gitignore", "r") as f:
        content = f.read()
    
    entries_to_add = []
    venv_entries = [
        "venv/", 
        "/venv/", 
        "venv", 
        "/venv",
        "venv/*",
        "**/__pycache__/",
        ".venv/",
        "env/",
        "ENV/"
    ]
    
    for entry in venv_entries:
        # Use regex to check if entry or similar already exists
        if not re.search(rf"^{re.escape(entry)}$", content, re.MULTILINE):
            entries_to_add.append(entry)
    
    if entries_to_add:
        with open(".gitignore", "a") as f:
            f.write("\n\n# Virtual Environment (added by fix script)\n")
            for entry in entries_to_add:
                f.write(f"{entry}\n")
        return True
    
    return False

def fix_line_endings_config():
    """Configure git to handle line endings properly."""
    return run_command("git config core.autocrlf true", quiet=True)

def main():
    """Main function to fix Git tracking issues."""
    print("\n🛠️ Git Virtual Environment Tracking Fix Tool 🛠️\n")
    
    # Check if we're in a Git repository
    if not is_git_repo():
        print("❌ Error: Not in a Git repository root directory.")
        print(f"   Current directory: {os.getcwd()}")
        sys.exit(1)
    
    # Check if venv is tracked
    if not check_if_venv_tracked():
        print("✅ Good news! The venv directory doesn't appear to be tracked by Git.")
        
        # Still update .gitignore and config to be safe
        updated = update_gitignore()
        if updated:
            print("✅ Added additional venv entries to .gitignore")
        
        fix_line_endings_config()
        print("✅ Updated git config for proper line ending handling")
        
        print("\n🎉 Your repository is properly set up!")
        return
    
    # Untrack the venv directory
    print("🔄 Removing venv directory from Git tracking (files won't be deleted)...")
    if run_command("git rm -r --cached venv/"):
        print("✅ Successfully untracked venv directory")
    else:
        print("❌ Failed to untrack venv directory")
        print("   You may need to manually run: git rm -r --cached venv/")
    
    # Update .gitignore
    updated = update_gitignore()
    if updated:
        print("✅ Added venv entries to .gitignore")
    else:
        print("✅ .gitignore already has the necessary entries")
    
    # Fix git config for line endings
    if fix_line_endings_config():
        print("✅ Updated git config for proper line ending handling")
    
    print("\n📝 Next steps:")
    print("   1. Review the changes with 'git status'")
    print("   2. Commit the changes:")
    print("      git add .gitignore")
    print('      git commit -m "Remove venv directory from version control"')
    print("\n✅ Done! Future git commands should no longer track the venv directory.")

if __name__ == "__main__":
    main()

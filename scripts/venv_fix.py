"""
Direct fix for Git tracking venv directory issue.
This script forcibly removes venv from Git tracking without deleting the actual directory.
"""

import os
import subprocess
import sys

def main():
    """Execute the fix."""
    print("\n=== VENV GIT TRACKING FIX ===\n")
    
    # Check if we're in a Git repository
    if not os.path.exists(".git"):
        print("Error: Not in a Git repository root directory.")
        print(f"Current directory: {os.getcwd()}")
        sys.exit(1)

    # First check if venv exists in Git's tracking
    result = subprocess.run("git ls-files | grep -i venv/", 
                          shell=True, capture_output=True, text=True)
    
    if result.stdout.strip():
        print("Found venv files in Git tracking. Removing them...")
        subprocess.run("git rm -r --cached --force venv", shell=True)
    else:
        print("No venv files found in Git tracking.")
    
    # Create/update .gitignore file with strong venv exclusion rules
    print("Updating .gitignore file...")
    
    try:
        # Try reading existing content with UTF-8 encoding
        gitignore_content = ""
        if os.path.exists(".gitignore"):
            try:
                with open(".gitignore", "r", encoding="utf-8") as f:
                    gitignore_content = f.read()
            except UnicodeDecodeError:
                # Fall back to reading without specific encoding
                try:
                    with open(".gitignore", "r", encoding="latin-1") as f:
                        gitignore_content = f.read()
                except Exception as e:
                    print(f"Warning: Could not read .gitignore: {e}")
                    gitignore_content = ""
        
        # Write new content
        with open(".gitignore", "w", encoding="utf-8") as f:
            # Add venv rules at the top
            venv_rules = """# Virtual Environment - DO NOT REMOVE OR MODIFY THESE LINES
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

"""
            # Write venv rules and existing content (if any)
            f.write(venv_rules)
            
            # Add existing content if it doesn't already have these rules
            if gitignore_content and "# Virtual Environment - DO NOT REMOVE" not in gitignore_content:
                f.write(gitignore_content)
        
        print("Successfully updated .gitignore with venv exclusion rules.")
        
    except Exception as e:
        print(f"Error updating .gitignore: {e}")
        return 1
    
    print("\nNext steps:")
    print("1. Run: git add .gitignore")
    print("2. Run: git commit -m \"Fix: Remove venv from Git tracking\"")
    print("3. On future git commands, venv should no longer be tracked")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

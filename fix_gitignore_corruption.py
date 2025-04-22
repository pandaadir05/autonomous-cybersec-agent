#!/usr/bin/env python3
"""
Script to fix the corrupted .gitignore file.
"""
import os
import sys

def create_clean_gitignore():
    """Create a clean .gitignore file with proper entries."""
    venv_entries = [
        "# Virtual Environment - DO NOT REMOVE OR MODIFY THESE LINES",
        "venv/",
        "/venv/",
        "venv/**",
        "/venv/**",
        ".venv/",
        "/.venv/",
        "env/",
        "/env/",
        "ENV/",
        "/ENV/",
        "",
        "# === Python Cache Files ===",
        "__pycache__/",
        "**/__pycache__/",
        "*.py[cod]",
        "*$py.class",
        "*.so",
        ".Python",
        "",
        "# === Build and Distribution ===",
        "build/",
        "dist/",
        "downloads/",
        "eggs/",
        ".eggs/",
        "parts/",
        "sdist/",
        "wheels/",
        "*.egg-info/",
        ".installed.cfg",
        "*.egg",
        "",
        "# === IDE & Editor Settings ===",
        ".vscode/",
        ".idea/",
        "*.swp",
        "*.swo",
        ".vs/",
        "*.sublime*",
        ".atom/",
        ".eclipse/",
        ".project",
        ".pydevproject",
        ".settings/",
        "",
        "# === OS Generated Files ===",
        ".DS_Store",
        ".DS_Store?",
        "._*",
        ".Spotlight-V100",
        ".Trashes",
        "ehthumbs.db",
        "Thumbs.db",
        "desktop.ini",
        "",
        "# === Logs and Local Data ===",
        "logs/",
        "*.log",
        "data/",
        "*.csv",
        "*.tmp",
        "",
        "# === Secrets and Configs ===",
        "*.env",
        ".env.*",
        "*.envrc",
        "*.env.bak",
        "config/secrets.yaml",
        "config/private.yaml",
        "",
        "# === Jupyter Notebooks ===",
        ".ipynb_checkpoints/",
        "",
        "# === Testing and Coverage ===",
        ".coverage",
        "*.cover",
        ".pytest_cache/",
        "htmlcov/",
        ".tox/",
        ".nox/",
        "",
        "# === Machine Learning & Experiment Tracking ===",
        "mlruns/",
        "wandb/",
        "models/*.pt",
        "models/*.pkl",
        "",
        "# === Visualizations ===",
        "visualizations/",
        "",
        "# === Misc Analytics Files ===",
        "analytics_*.json",
        "",
        "# === Temporary Files ===",
        "*.tmp",
        "*.bak",
        "*.swp",
        "*.swo",
        "",
        "# === Backup Files ===",
        "*.bak",
        "*.orig",
        "",
        "# === Database Files ===",
        "*.sqlite",
        "*.db",
        "",
        "# === Docker Files ===",
        "docker-compose.override.yml",
        "docker-compose.local.yml",
        "",
        "# === Kubernetes Files ===",
        "*.kube",
        "",
        "# === Cloud Provider Files ===",
        "*.aws",
        "*.gcp"
    ]
    
    # Create the new gitignore file
    with open(".gitignore", "w", encoding="utf-8") as f:
        for entry in venv_entries:
            f.write(f"{entry}\n")
    
    print("✅ Successfully created a clean .gitignore file")
    print("📝 Next steps:")
    print("   1. Review the changes with 'git status'")
    print("   2. Commit the changes:")
    print("      git add .gitignore")
    print("      git commit -m \"Fix: Restore .gitignore file with proper encoding\"")

if __name__ == "__main__":
    if not os.path.exists(".git"):
        print("❌ Error: Not in a Git repository root directory.")
        print(f"   Current directory: {os.getcwd()}")
        sys.exit(1)
    
    create_clean_gitignore()
    
    # Untrack venv directory if it exists
    if os.path.exists("venv"):
        os.system("git rm -r --cached venv/ --force 2>nul")
        print("🔄 Removed venv directory from Git tracking (files weren't deleted)")
    
    # Configure git for line endings
    os.system("git config core.autocrlf true")
    print("✅ Updated git config for proper line ending handling")

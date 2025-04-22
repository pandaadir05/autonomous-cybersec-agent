"""
Banner display utility for Lesh
"""

import os
import sys
import platform
import time

# ANSI color codes
BLUE = '\033[94m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'

def display_banner() -> None:
    """Display a beautiful ASCII art banner for Lesh."""
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # ASCII Art for Lesh
    banner = f"""
{BLUE}{BOLD}    __               __  
   / /  ___ ___ ___/ /  
  / /__/ -_|_-</ _  /   
 /____/\\__/___/\\_,_/    {ENDC}
                         
{GREEN}{BOLD}╔════════════════════════════════════════════════════════════╗
║  {YELLOW}Lesh: Autonomous Cybersecurity Defense Agent {GREEN}               ║
║  {YELLOW}Version: 1.0.0                             {GREEN}                 ║
╚════════════════════════════════════════════════════════════╝{ENDC}

{BLUE}• System: {ENDC}{platform.system()} {platform.release()}
{BLUE}• Python: {ENDC}{platform.python_version()}
{BLUE}• Time:   {ENDC}{time.strftime("%Y-%m-%d %H:%M:%S")}

{YELLOW}Starting agent...{ENDC}
"""
    print(banner)
    
    # Small delay for effect
    time.sleep(0.5)

def display_success_message(message: str) -> None:
    """Display a success message."""
    print(f"\n{GREEN}[✓] {message}{ENDC}\n")

def display_error_message(message: str) -> None:
    """Display an error message."""
    print(f"\n{RED}[✗] {message}{ENDC}\n")

def display_warning_message(message: str) -> None:
    """Display a warning message."""
    print(f"\n{YELLOW}[!] {message}{ENDC}\n")

if __name__ == "__main__":
    # Test banner display
    display_banner()
    display_success_message("Lesh started successfully!")
    display_warning_message("Running in simulation mode")
    display_error_message("Configuration error detected")

#!/usr/bin/env python3
"""
Lesh: Autonomous Cybersecurity Defense Agent
Main execution script for running dashboard and other components
"""

import os
import sys
import argparse
import logging
import time
import threading
from typing import Dict, Any

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="LESH Autonomous Cybersecurity Defense Agent"
    )
    
    parser.add_argument("--dashboard", action="store_true", help="Run the dashboard")
    parser.add_argument("--agent", action="store_true", help="Run the security agent")
    parser.add_argument("--api", action="store_true", help="Run the API server")
    parser.add_argument("--all", action="store_true", help="Run all components")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    
    return parser.parse_args()

def setup_logging(verbose: bool = False) -> None:
    """Set up basic logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler()
        ]
    )

def run_dashboard() -> None:
    """Run the dashboard component."""
    from dashboard.dashboard import app_run
    logging.info("Starting cybersecurity dashboard...")
    app_run()

def run_agent() -> None:
    """Run the security agent component."""
    logging.info("Security agent would start here...")
    # This is a placeholder - in a real implementation, this would import and start the agent
    while True:
        time.sleep(1)

def run_api() -> None:
    """Run the API server component."""
    logging.info("API server would start here...")
    # This is a placeholder - in a real implementation, this would import and start the API server
    while True:
        time.sleep(1)

def main() -> None:
    """Main entry point."""
    args = parse_arguments()
    
    # Set up logging
    setup_logging(args.verbose)
    
    # Determine which components to run
    run_all = args.all or not any([args.dashboard, args.agent, args.api])
    
    # If only dashboard is requested, run it directly in the main thread
    if args.dashboard and not (args.agent or args.api or run_all):
        run_dashboard()
        return
        
    threads = []
    
    # Otherwise, run components in threads
    if args.dashboard or run_all:
        dashboard_thread = threading.Thread(target=run_dashboard, name="Dashboard", daemon=True)
        dashboard_thread.start()
        threads.append(dashboard_thread)
        
    if args.agent or run_all:
        agent_thread = threading.Thread(target=run_agent, name="Agent", daemon=True)
        agent_thread.start()
        threads.append(agent_thread)
        
    if args.api or run_all:
        api_thread = threading.Thread(target=run_api, name="API", daemon=True)
        api_thread.start()
        threads.append(api_thread)
    
    # Keep main thread alive until all components terminate
    try:
        for thread in threads:
            while thread.is_alive():
                thread.join(1)  # Join with timeout to allow keyboard interrupts
    except KeyboardInterrupt:
        logging.info("Keyboard interrupt received, shutting down...")
        sys.exit(0)

if __name__ == "__main__":
    main()

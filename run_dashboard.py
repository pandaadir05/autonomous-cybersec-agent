#!/usr/bin/env python3
"""
LESH: Run Dashboard directly
This script runs the dashboard directly without threading issues
"""

import os
import sys
import argparse
import logging
from dashboard.dashboard import app

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="LESH Autonomous Cybersecurity Dashboard"
    )
    
    parser.add_argument("--port", type=int, default=8050,
                       help="Port to run the dashboard on")
    parser.add_argument("--debug", action="store_true",
                       help="Run in debug mode")
    parser.add_argument("--status-page", action="store_true",
                       help="Run the agent status page instead of main dashboard")
    parser.add_argument("--host", default="127.0.0.1",
                       help="Host to bind the server to")
    
    return parser.parse_args()

def setup_logging() -> None:
    """Set up basic logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler()
        ]
    )

def run_status_page(host, port, debug):
    """Run the agent status page."""
    from dashboard.status_page import app as status_app
    logging.info(f"Starting agent status page on http://{host}:{port}")
    status_app.run(debug=debug, host=host, port=port)

def main() -> int:
    """Main function."""
    args = parse_arguments()
    setup_logging()
    
    try:
        if args.status_page:
            run_status_page(args.host, args.port, args.debug)
        else:
            logging.info(f"Starting dashboard on http://{args.host}:{args.port}")
            app.run(debug=args.debug, host=args.host, port=args.port)
        return 0
    except Exception as e:
        logging.error(f"Error running dashboard: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())

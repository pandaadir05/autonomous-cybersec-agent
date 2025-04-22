#!/usr/bin/env python3
"""
Autonomous Cybersecurity Defense Agent
Main entry point for the application.
"""

import argparse
import logging
import sys
import time
from pathlib import Path

from agent.core import DefenseAgent
from agent.config import load_config
from agent.utils.logger import setup_logging

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Autonomous Cybersecurity Defense Agent"
    )
    parser.add_argument(
        "-c", "--config", 
        default="config/config.yaml", 
        help="Path to configuration file"
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true", 
        help="Enable verbose output"
    )
    parser.add_argument(
        "--simulate", 
        action="store_true", 
        help="Run in simulation mode without making actual system changes"
    )
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_arguments()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)
    logger = logging.getLogger("main")
    
    try:
        logger.info("Starting Autonomous Cybersecurity Defense Agent")
        
        # Load configuration
        config_path = Path(args.config)
        config = load_config(config_path)
        
        # Initialize agent
        agent = DefenseAgent(config, simulation_mode=args.simulate)
        
        # Start agent
        agent.start()
        
        # Keep main thread alive while agent runs in background
        try:
            while agent.is_running():
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Received shutdown signal")
            agent.stop()
            
        logger.info("Agent stopped")
        
    except Exception as e:
        logger.exception(f"Fatal error: {e}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())

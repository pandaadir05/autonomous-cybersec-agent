#!/usr/bin/env python3
"""
Lesh: Autonomous Cybersecurity Defense Agent
Main execution script for starting the agent
"""

import os
import sys
import argparse
import logging
import time
from typing import Dict, Any

# Set up path for imports
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import agent components
from agent.core.defense_agent import DefenseAgent
from agent.utils.config import init_config, get_agent_config
from agent.utils.banner import display_banner
from agent.utils.interactive import InteractiveShell

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Lesh: Autonomous Cybersecurity Defense Agent"
    )
    parser.add_argument(
        "--config", 
        type=str, 
        help="Path to configuration file"
    )
    parser.add_argument(
        "--verbose", 
        action="store_true", 
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--simulate", 
        action="store_true", 
        help="Run in simulation mode without making system changes"
    )
    parser.add_argument(
        "--interactive", 
        action="store_true", 
        help="Run in interactive mode with command shell"
    )
    parser.add_argument(
        "--profile", 
        type=str, 
        default="default",
        help="Configuration profile to use"
    )
    
    return parser.parse_args()

def setup_logging(verbose: bool = False) -> None:
    """Set up basic logging before config is loaded."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler()
        ]
    )

def main() -> None:
    """Main entry point for the agent."""
    # Get command line arguments
    args = parse_arguments()
    
    # Set up initial logging
    setup_logging(args.verbose)
    
    # Display banner
    display_banner()
    
    # Initialize configuration
    try:
        if args.config:
            config_manager = init_config(args.config)
        else:
            config_manager = init_config()
            
        # Apply profile if specified
        if args.profile != "default":
            config_manager.apply_profile(args.profile)
            
        # Get agent configuration
        config = get_agent_config()
        
    except Exception as e:
        logging.critical(f"Failed to load configuration: {e}")
        sys.exit(1)
    
    # Create and start agent
    try:
        agent = DefenseAgent(config=config, simulation_mode=args.simulate)
        agent.start()
        
        logging.info("Lesh Agent started successfully")
        
        # Run in interactive mode if requested
        if args.interactive:
            shell = InteractiveShell(agent)
            shell.cmdloop()
        else:
            # Wait for keyboard interrupt
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                logging.info("Keyboard interrupt received, shutting down...")
                
    except Exception as e:
        logging.critical(f"Failed to start agent: {e}", exc_info=True)
        sys.exit(1)
    finally:
        # Ensure we shutdown cleanly
        try:
            agent.shutdown()
            logging.info("Lesh Agent shut down successfully")
        except:
            pass

if __name__ == "__main__":
    main()

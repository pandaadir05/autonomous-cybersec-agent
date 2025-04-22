#!/usr/bin/env python3
"""
Run the Autonomous Cybersecurity Defense Agent in interactive mode.
This script provides a command-line interface to control and monitor the agent.
"""

import argparse
import sys
import time
import os
import json
import logging
import threading
from pathlib import Path

from agent.core import DefenseAgent
from agent.config import init_config, get_agent_config
from agent.utils.logger import setup_logging

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Run Autonomous Cybersecurity Defense Agent"
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
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Run in interactive mode with command prompt"
    )
    parser.add_argument(
        "--profile",
        choices=["default", "development", "production", "testing"],
        help="Use specific configuration profile"
    )
    return parser.parse_args()

def interactive_shell(agent):
    """
    Run an interactive shell to control the agent.
    
    Args:
        agent: The DefenseAgent instance
    """
    logger = logging.getLogger("interactive")
    logger.info("Starting interactive shell. Type 'help' for available commands.")
    
    # Command handlers
    def cmd_help():
        """Display help information."""
        print("\nAvailable commands:")
        print("  status      - Show agent status")
        print("  threats     - List detected threats")
        print("  start       - Start the agent")
        print("  stop        - Stop the agent")
        print("  config      - Show current configuration")
        print("  health      - Run a health check")
        print("  scan        - Run a manual threat scan")
        print("  quit        - Exit the program")
        print()
    
    def cmd_status():
        """Show agent status."""
        status = agent.get_status()
        print("\nAgent Status:")
        print(f"  Running: {status['running']}")
        print(f"  Simulation Mode: {status['simulation_mode']}")
        print("\nDetection Status:")
        print(f"  Last Detection: {time.ctime(status['detection']['last_detection_time'])}")
        print(f"  Total Threats: {status['detection']['total_threats_detected']}")
        print(f"  Active Threats: {status['detection']['active_threats']}")
        print("\nResponse Status:")
        print(f"  Last Response: {time.ctime(status['response']['last_response_time'])}")
        print(f"  Total Responses: {status['response']['total_responses']}")
        print(f"  Successful Responses: {status['response']['successful_responses']}")
        print()
    
    def cmd_threats():
        """List detected threats."""
        threats = agent.threat_detector.detected_threats
        if not threats:
            print("\nNo threats detected.")
            return
            
        print(f"\nDetected Threats ({len(threats)}):")
        for i, threat in enumerate(threats):
            status = "RESOLVED" if threat.resolved else "ACTIVE"
            print(f"  {i+1}. [{status}] {threat.type} from {threat.source} (Severity: {threat.severity}/5, Confidence: {threat.confidence:.2f})")
            if threat.resolved:
                print(f"     Resolved at {time.ctime(threat.resolution_time)} by {threat.resolution_action}")
        print()
    
    def cmd_start():
        """Start the agent."""
        if agent.is_running():
            print("\nAgent is already running.")
        else:
            agent.start()
            print("\nAgent started.")
    
    def cmd_stop():
        """Stop the agent."""
        if not agent.is_running():
            print("\nAgent is already stopped.")
        else:
            agent.stop()
            print("\nAgent stopped.")
    
    def cmd_config():
        """Show current configuration."""
        print("\nCurrent Configuration:")
        print(json.dumps(agent.config, indent=2, default=str))
        print()
    
    def cmd_health():
        """Run a health check."""
        health_status = agent.health_monitor.check_health()
        print("\nHealth Check Results:")
        print(f"  Healthy: {health_status.healthy}")
        print(f"  Message: {health_status.message}")
        
        print("\nSystem Resources:")
        print(f"  CPU: {health_status.details['system']['cpu_percent']}%")
        print(f"  Memory: {health_status.details['system']['memory_percent']}%")
        print(f"  Disk: {health_status.details['system']['disk_percent']}%")
        
        if health_status.details['issues']:
            print("\nIssues Detected:")
            for issue in health_status.details['issues']:
                print(f"  - {issue}")
        print()
    
    def cmd_scan():
        """Run a manual threat scan."""
        print("\nRunning manual threat scan...")
        threats = agent.threat_detector.detect_threats()
        if threats:
            print(f"Detected {len(threats)} threats:")
            for i, threat in enumerate(threats):
                print(f"  {i+1}. {threat.type} from {threat.source} (Severity: {threat.severity}/5)")
        else:
            print("No threats detected.")
        print()
    
    # Command dispatch table
    commands = {
        "help": cmd_help,
        "status": cmd_status,
        "threats": cmd_threats,
        "start": cmd_start,
        "stop": cmd_stop,
        "config": cmd_config,
        "health": cmd_health,
        "scan": cmd_scan,
    }
    
    # Interactive loop
    while True:
        try:
            cmd = input("agent> ").strip().lower()
            
            if not cmd:
                continue
                
            if cmd == "quit" or cmd == "exit":
                if agent.is_running():
                    agent.stop()
                print("Exiting...")
                break
                
            if cmd in commands:
                commands[cmd]()
            else:
                print(f"Unknown command: {cmd}")
                cmd_help()
                
        except KeyboardInterrupt:
            print("\nExiting...")
            if agent.is_running():
                agent.stop()
            break
        except Exception as e:
            print(f"Error: {e}")

def main():
    """Main function."""
    args = parse_arguments()
    
    # Initialize configuration
    config_manager = init_config(Path(args.config))
    
    # Override with command-line arguments
    if args.profile:
        config_manager._config_data["agent"]["profile"] = args.profile
        config_manager._apply_profile()
        config_manager._validate_config()
    
    # Get validated configuration
    config = get_agent_config()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else getattr(logging, config.logging.level)
    setup_logging(
        level=log_level,
        log_file=config.logging.file,
        max_size=config.logging.max_size_mb,
        backup_count=config.logging.backup_count
    )
    
    # Create agent instance
    agent = DefenseAgent(
        config=config,
        simulation_mode=args.simulate
    )
    
    try:
        # Start the agent
        agent.start()
        
        if args.interactive:
            # Run interactive shell
            interactive_shell(agent)
        else:
            # Run in background until interrupted
            print(f"Agent '{config.system.name}' started. Press Ctrl+C to exit.")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        # Clean shutdown
        agent.shutdown()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())

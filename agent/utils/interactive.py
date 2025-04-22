"""
Interactive shell for the agent.
"""

import cmd
import os
import sys
import time
import json
from typing import Dict, Any, Optional

class InteractiveShell(cmd.Cmd):
    """
    Interactive command shell for the agent.
    Provides commands to interact with and control the agent.
    """
    
    intro = "Lesh Interactive Shell. Type help or ? to list commands.\n"
    prompt = "lesh> "
    
    def __init__(self, agent):
        """
        Initialize the interactive shell.
        
        Args:
            agent: Defense agent instance
        """
        super().__init__()
        self.agent = agent
        self.recent_threats = []
        
    def do_status(self, arg):
        """Display agent status and statistics."""
        status = self.agent.get_status()
        
        print("\n=== Agent Status ===")
        print(f"Running: {status['running']}")
        print(f"Simulation Mode: {status['simulation_mode']}")
        print(f"Uptime: {status['uptime']:.2f} seconds")
        print(f"Threats Detected: {status['threats_detected']}")
        
        if status['last_scan_time']:
            last_scan = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(status['last_scan_time']))
            print(f"Last Scan: {last_scan}")
            
        print("\n=== Detection Status ===")
        if status['detection_status']:
            print(f"Running: {status['detection_status']['running']}")
            print(f"Scan Interval: {status['detection_status']['scan_interval']} seconds")
            
        print("\n=== Response Status ===")
        if status['response_status']:
            print(f"Running: {status['response_status']['running']}")
            print(f"Successful Responses: {status['response_status'].get('successful_responses', 0)}")
            print(f"Available Actions: {', '.join(status['response_status'].get('available_actions', []))}")
        
    def do_scan(self, arg):
        """Run manual threat scan."""
        print("Running manual threat scan...")
        threats = self.agent.scan()
        
        if threats:
            print(f"\nDetected {len(threats)} potential threats:")
            for i, threat in enumerate(threats):
                print(f"\n--- Threat {i+1} ---")
                print(f"Type: {threat['type']}")
                print(f"Source: {threat['source']}")
                print(f"Severity: {threat['severity']}/5")
                print(f"Confidence: {threat['confidence']:.2f}")
                
            self.recent_threats = threats
        else:
            print("\nNo threats detected")
            
    def do_block(self, arg):
        """Block IP address. Usage: block [IP]"""
        if not arg:
            print("Error: IP address required")
            print("Usage: block [IP]")
            return
            
        # Create a simulated threat
        threat = {
            "id": f"manual-block-{int(time.time())}",
            "timestamp": time.time(),
            "type": "suspicious_connection",
            "source": arg,
            "severity": 3,
            "confidence": 1.0,
            "details": {
                "description": "Manually blocked IP",
                "remote_address": f"{arg}:0"
            }
        }
        
        # Use the response manager to block it
        if self.agent._running and hasattr(self.agent, 'response_manager'):
            results = self.agent.response_manager.handle_threats([threat])
            
            for result in results:
                if result["action"] == "network_block":
                    if result["success"]:
                        print(f"Successfully blocked IP: {arg}")
                    else:
                        print(f"Failed to block IP: {arg}")
                        if "error" in result["details"]:
                            print(f"Error: {result['details']['error']}")
        else:
            print("Agent not running, can't block IP")
    
    def do_reports(self, arg):
        """Show recent threat reports."""
        if not self.recent_threats:
            print("No recent threats detected")
            return
            
        print(f"\n=== Recent Threats ({len(self.recent_threats)}) ===")
        
        for i, threat in enumerate(self.recent_threats):
            print(f"\n--- Threat {i+1} ---")
            print(f"ID: {threat['id']}")
            print(f"Type: {threat['type']}")
            print(f"Source: {threat['source']}")
            print(f"Severity: {threat['severity']}/5")
            print(f"Confidence: {threat['confidence']:.2f}")
            print(f"Details: {json.dumps(threat['details'], indent=2)}")
    
    def do_exit(self, arg):
        """Exit interactive mode."""
        print("Exiting interactive mode...")
        return True
        
    def do_quit(self, arg):
        """Exit interactive mode."""
        return self.do_exit(arg)
        
    def do_EOF(self, arg):
        """Handle EOF (Ctrl+D)."""
        print()  # Add a newline
        return self.do_exit(arg)

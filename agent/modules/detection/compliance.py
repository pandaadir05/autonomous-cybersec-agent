"""
Security compliance checking module.
Examines system configurations for compliance with security best practices.
"""

import logging
import time
import os
import platform
import json
import re
import socket
import subprocess
from typing import Dict, List, Any, Optional, Tuple
import uuid

class ComplianceChecker:
    """
    Checks system configurations for security compliance issues.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the compliance checker.
        
        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        
        # Load compliance rules
        self.rules_file = config.get("compliance_rules_file", "data/rules/compliance_rules.json")
        self.rules = self._load_rules()
        
        # Configuration
        self.check_password_policy = config.get("check_password_policy", True)
        self.check_firewall = config.get("check_firewall", True)
        self.check_updates = config.get("check_updates", True)
        self.check_services = config.get("check_services", True)
        
        self.logger.info("Compliance checker initialized")
    
    def _load_rules(self) -> Dict[str, Any]:
        """
        Load compliance rules from file.
        
        Returns:
            Dictionary of compliance rules
        """
        rules = {
            "password_policy": {
                "min_length": 8,
                "require_complexity": True
            },
            "services": {
                "disabled": ["telnet", "ftp"],
                "required": ["firewall", "antivirus"]
            },
            "configurations": {
                "auto_updates": True,
                "firewall_enabled": True,
                "guest_account_disabled": True
            }
        }
        
        try:
            # Ensure the directory exists
            os.makedirs(os.path.dirname(self.rules_file), exist_ok=True)
            
            # Try to load existing rules file
            if os.path.exists(self.rules_file):
                with open(self.rules_file, 'r') as f:
                    rules = json.load(f)
            else:
                # Create a new rules file
                with open(self.rules_file, 'w') as f:
                    json.dump(rules, f, indent=2)
            
            self.logger.info(f"Loaded compliance rules")
            
        except Exception as e:
            self.logger.error(f"Error loading compliance rules: {e}")
        
        return rules
    
    def check_compliance(self) -> List[Dict[str, Any]]:
        """
        Check system compliance with security standards.
        
        Returns:
            List of compliance issues detected
        """
        issues = []
        
        # Check different compliance areas
        if self.check_password_policy:
            issues.extend(self._check_password_policy())
        
        if self.check_firewall:
            issues.extend(self._check_firewall())
        
        if self.check_updates:
            issues.extend(self._check_system_updates())
        
        if self.check_services:
            issues.extend(self._check_running_services())
        
        self.logger.info(f"Completed compliance check, found {len(issues)} issues")
        return issues
    
    def _check_password_policy(self) -> List[Dict[str, Any]]:
        """
        Check password policy compliance.
        
        Returns:
            List of password policy issues
        """
        issues = []
        
        try:
            if platform.system() == "Windows":
                # On Windows, use net accounts command to get password policy
                result = subprocess.run(
                    ["net", "accounts"], 
                    capture_output=True, 
                    text=True, 
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                output = result.stdout
                
                # Extract password length requirement
                min_length_match = re.search(r"Minimum password length\s*:\s*(\d+)", output)
                min_length = int(min_length_match.group(1)) if min_length_match else 0
                
                # Check against our rule
                if min_length < self.rules["password_policy"]["min_length"]:
                    issues.append({
                        "id": str(uuid.uuid4()),
                        "timestamp": time.time(),
                        "type": "compliance_issue",
                        "source": "password_policy",
                        "severity": 3,  # High
                        "confidence": 0.95,
                        "details": {
                            "description": "Password minimum length too short",
                            "current_value": min_length,
                            "recommended_value": self.rules["password_policy"]["min_length"],
                            "compliance_category": "password_policy",
                            "remediation": "Increase minimum password length in Group Policy"
                        }
                    })
                
            else:
                # For non-Windows systems, implement specific checks here
                # This is just a placeholder for demonstration
                self.logger.info("Password policy checking on non-Windows systems not implemented")
                
        except Exception as e:
            self.logger.error(f"Error checking password policy: {e}")
        
        return issues
    
    def _check_firewall(self) -> List[Dict[str, Any]]:
        """
        Check firewall configuration compliance.
        
        Returns:
            List of firewall configuration issues
        """
        issues = []
        
        try:
            if platform.system() == "Windows":
                # On Windows, check firewall status using netsh
                result = subprocess.run(
                    ["netsh", "advfirewall", "show", "allprofiles"], 
                    capture_output=True, 
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                output = result.stdout
                
                # Check if firewall is enabled for all profiles
                for profile in ["Domain Profile", "Private Profile", "Public Profile"]:
                    state_match = re.search(f"{profile} State\s*:\s*(\w+)", output)
                    if state_match and state_match.group(1).lower() != "on":
                        issues.append({
                            "id": str(uuid.uuid4()),
                            "timestamp": time.time(),
                            "type": "compliance_issue",
                            "source": "firewall",
                            "severity": 4,  # High
                            "confidence": 0.95,
                            "details": {
                                "description": f"Firewall disabled for {profile}",
                                "current_status": state_match.group(1),
                                "recommended_status": "ON",
                                "compliance_category": "firewall",
                                "remediation": f"Enable Windows Firewall for {profile}"
                            }
                        })
            
            else:
                # For Linux, check iptables or ufw
                self.logger.info("Firewall checking on non-Windows systems not fully implemented")
                
        except Exception as e:
            self.logger.error(f"Error checking firewall: {e}")
        
        return issues
    
    def _check_system_updates(self) -> List[Dict[str, Any]]:
        """
        Check system update configuration.
        
        Returns:
            List of system update issues
        """
        issues = []
        
        try:
            if platform.system() == "Windows":
                # Check Windows Update settings
                result = subprocess.run(
                    ["reg", "query", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU", "/v", "NoAutoUpdate"],
                    capture_output=True, 
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                # If the command was successful and returned data
                if result.returncode == 0 and "0x1" in result.stdout:
                    issues.append({
                        "id": str(uuid.uuid4()),
                        "timestamp": time.time(),
                        "type": "compliance_issue",
                        "source": "windows_update",
                        "severity": 3,  # Medium-high
                        "confidence": 0.9,
                        "details": {
                            "description": "Automatic updates are disabled",
                            "current_setting": "Disabled",
                            "recommended_setting": "Enabled",
                            "compliance_category": "system_updates",
                            "remediation": "Enable automatic updates in Windows Update settings"
                        }
                    })
                
            else:
                # For Linux, we would check package manager configurations
                self.logger.info("Update checking on non-Windows systems not fully implemented")
                
        except Exception as e:
            self.logger.error(f"Error checking system updates: {e}")
        
        return issues
    
    def _check_running_services(self) -> List[Dict[str, Any]]:
        """
        Check for problematic running services.
        
        Returns:
            List of service-related issues
        """
        issues = []
        
        try:
            if platform.system() == "Windows":
                # Check for services that should be disabled
                for service in self.rules["services"]["disabled"]:
                    result = subprocess.run(
                        ["sc", "query", service], 
                        capture_output=True, 
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    
                    # If service exists and is running
                    if result.returncode == 0 and "RUNNING" in result.stdout:
                        issues.append({
                            "id": str(uuid.uuid4()),
                            "timestamp": time.time(),
                            "type": "compliance_issue",
                            "source": f"service_{service}",
                            "severity": 3,  # Medium-high
                            "confidence": 0.85,
                            "details": {
                                "description": f"Insecure service {service} is running",
                                "service_name": service,
                                "current_status": "Running",
                                "recommended_status": "Disabled",
                                "compliance_category": "services",
                                "remediation": f"Disable the {service} service"
                            }
                        })
                
                # Check for services that should be running
                for service in self.rules["services"]["required"]:
                    result = subprocess.run(
                        ["sc", "query", service], 
                        capture_output=True, 
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    
                    # If service doesn't exist or isn't running
                    if result.returncode != 0 or "RUNNING" not in result.stdout:
                        issues.append({
                            "id": str(uuid.uuid4()),
                            "timestamp": time.time(),
                            "type": "compliance_issue",
                            "source": f"service_{service}",
                            "severity": 2,  # Medium
                            "confidence": 0.85,
                            "details": {
                                "description": f"Required service {service} is not running",
                                "service_name": service,
                                "current_status": "Not running or not installed",
                                "recommended_status": "Running",
                                "compliance_category": "services",
                                "remediation": f"Install and start the {service} service"
                            }
                        })
                
            else:
                # For Linux, we would check systemd services
                self.logger.info("Service checking on non-Windows systems not fully implemented")
                
        except Exception as e:
            self.logger.error(f"Error checking services: {e}")
        
        return issues

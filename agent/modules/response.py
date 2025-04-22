"""
Response orchestration module for the Lesh Autonomous Cybersecurity Defense Agent.
"""

import logging
import time
import subprocess
import platform
import os
import json
import smtplib
import requests
import psutil
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Any, Optional
import ipaddress

from agent.utils.logger import log_security_event
from agent.utils.config import Config

class ResponseAction:
    """Base class for response actions."""
    
    def __init__(self, config: Dict[str, Any], simulation_mode: bool = False):
        """
        Initialize the response action.
        
        Args:
            config: Response configuration
            simulation_mode: If True, don't make actual changes
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.simulation_mode = simulation_mode
        
    def execute(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the response action for a given threat.
        
        Args:
            threat: Threat to respond to
            
        Returns:
            Dictionary with response results
        """
        raise NotImplementedError("Subclasses must implement execute()")
        
    def _log_action(self, action: str, target: str, success: bool, details: Dict[str, Any] = None):
        """
        Log a response action.
        
        Args:
            action: Action taken
            target: Target of the action
            success: Whether the action was successful
            details: Additional details about the action
        """
        status = "SUCCESS" if success else "FAILURE"
        msg = f"Response action {action} against {target}: {status}"
        level = logging.INFO if success else logging.WARNING
        
        self.logger.log(level, msg)
        log_security_event(msg, level, action=action, target=target, success=success, details=details)

class NetworkBlockAction(ResponseAction):
    """Block network connections related to a threat."""
    
    def execute(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute network blocking response.
        
        Args:
            threat: Threat to respond to
            
        Returns:
            Dictionary with response results
        """
        result = {
            "action": "network_block",
            "success": False,
            "details": {}
        }
        
        try:
            # Get the IP to block
            if threat["type"] == "suspicious_connection":
                ip = threat["details"]["remote_address"].split(":")[0]
            elif "source" in threat and self._is_valid_ip(threat["source"]):
                ip = threat["source"]
            else:
                self.logger.warning(f"No valid IP found in threat: {threat['id']}")
                result["details"]["error"] = "No valid IP address found in threat"
                return result
                
            # Check if this is a valid IP to block
            if not self._is_valid_ip(ip) or self._is_safe_ip(ip):
                self.logger.warning(f"IP {ip} is not valid or is in safe list")
                result["details"]["error"] = f"IP {ip} is not valid or is in safe list"
                return result
                
            # Execute the block
            if self.simulation_mode:
                self.logger.info(f"SIMULATION: Would block IP: {ip}")
                result["success"] = True
                result["details"]["ip"] = ip
                result["details"]["simulated"] = True
                self._log_action("network_block", ip, True, {"simulated": True})
            else:
                # Perform actual blocking based on OS
                if platform.system() == "Linux":
                    success = self._block_ip_linux(ip)
                elif platform.system() == "Windows":
                    success = self._block_ip_windows(ip)
                else:
                    self.logger.error(f"Unsupported OS: {platform.system()}")
                    result["details"]["error"] = f"Unsupported OS: {platform.system()}"
                    return result
                    
                result["success"] = success
                result["details"]["ip"] = ip
                self._log_action("network_block", ip, success)
                
        except Exception as e:
            self.logger.error(f"Error in network block action: {e}", exc_info=True)
            result["details"]["error"] = str(e)
            
        return result
        
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if an IP address is valid."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
            
    def _is_safe_ip(self, ip: str) -> bool:
        """Check if an IP address is in the safe list."""
        # List of IPs that should never be blocked
        safe_ips = self.config.get("safe_ips", [
            "127.0.0.1",      # Localhost
            "192.168.1.1",    # Default gateway (example)
        ])
        
        # Check if it's a local network address
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Never block localhost
            if ip_obj.is_loopback:
                return True
                
            # Check safe list
            if ip in safe_ips:
                return True
                
        except ValueError:
            pass
            
        return False
        
    def _block_ip_linux(self, ip: str) -> bool:
        """
        Block an IP address on Linux using iptables.
        
        Args:
            ip: IP address to block
            
        Returns:
            True if successful, False otherwise
        """
        try:
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Check result
            if result.returncode != 0:
                self.logger.error(f"Failed to block IP {ip}: {result.stderr}")
                return False
                
            self.logger.info(f"Successfully blocked IP: {ip}")
            return True
            
        except subprocess.SubprocessError as e:
            self.logger.error(f"Error blocking IP {ip}: {e}")
            return False
            
    def _block_ip_windows(self, ip: str) -> bool:
        """
        Block an IP address on Windows using Windows Firewall.
        
        Args:
            ip: IP address to block
            
        Returns:
            True if successful, False otherwise
        """
        rule_name = f"BlockIP_{ip.replace('.', '_')}"
        
        try:
            # Create a new Windows Firewall rule to block the IP
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip}"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Check result
            if result.returncode != 0:
                self.logger.error(f"Failed to block IP {ip}: {result.stderr}")
                return False
                
            self.logger.info(f"Successfully blocked IP: {ip}")
            return True
            
        except subprocess.SubprocessError as e:
            self.logger.error(f"Error blocking IP {ip}: {e}")
            return False

class ProcessTerminateAction(ResponseAction):
    """Terminate a suspicious process."""
    
    def execute(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute process termination response.
        
        Args:
            threat: Threat to respond to
            
        Returns:
            Dictionary with response results
        """
        result = {
            "action": "process_terminate",
            "success": False,
            "details": {}
        }
        
        try:
            # Get the process ID to terminate
            if threat["type"] == "suspicious_process" and "pid" in threat["details"]:
                pid = threat["details"]["pid"]
            elif threat["source"] and threat["source"].startswith("PID:"):
                pid = int(threat["source"].split(":")[1])
            else:
                self.logger.warning(f"No valid PID found in threat: {threat['id']}")
                result["details"]["error"] = "No valid PID found in threat"
                return result
                
            # Check if this is a valid PID
            if not self._is_valid_pid(pid) or self._is_safe_process(pid):
                self.logger.warning(f"PID {pid} is not valid or is in safe list")
                result["details"]["error"] = f"PID {pid} is not valid or is in safe list"
                return result
                
            # Execute the termination
            if self.simulation_mode:
                self.logger.info(f"SIMULATION: Would terminate process: {pid}")
                result["success"] = True
                result["details"]["pid"] = pid
                result["details"]["simulated"] = True
                self._log_action("process_terminate", f"PID:{pid}", True, {"simulated": True})
            else:
                # Get process name for logging before termination
                process_name = "Unknown"
                try:
                    process = psutil.Process(pid)
                    process_name = process.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                    
                # Terminate the process
                success = self._terminate_process(pid)
                    
                result["success"] = success
                result["details"]["pid"] = pid
                result["details"]["process_name"] = process_name
                self._log_action("process_terminate", f"{process_name} (PID:{pid})", success)
                
        except Exception as e:
            self.logger.error(f"Error in process terminate action: {e}", exc_info=True)
            result["details"]["error"] = str(e)
            
        return result
        
    def _is_valid_pid(self, pid: int) -> bool:
        """Check if a process ID is valid."""
        try:
            return psutil.pid_exists(pid)
        except:
            return False
            
    def _is_safe_process(self, pid: int) -> bool:
        """Check if a process should not be terminated."""
        try:
            process = psutil.Process(pid)
            
            # Never terminate system critical processes
            if process.username() in ["root", "SYSTEM", "NT AUTHORITY\\SYSTEM"]:
                # Check if it's in the allowed list for termination
                safe_processes = self.config.get("safe_processes", [
                    "svchost.exe",
                    "systemd",
                    "init",
                    "lsass.exe"
                ])
                
                if process.name() in safe_processes:
                    return True
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
        return False
        
    def _terminate_process(self, pid: int) -> bool:
        """
        Terminate a process.
        
        Args:
            pid: Process ID to terminate
            
        Returns:
            True if successful, False otherwise
        """
        try:
            process = psutil.Process(pid)
            process.terminate()
            
            # Wait up to 3 seconds for process to terminate
            gone, still_alive = psutil.wait_procs([process], timeout=3)
            
            if still_alive:
                # Process didn't terminate, try to kill it
                process.kill()
                gone, still_alive = psutil.wait_procs([process], timeout=2)
                
            if still_alive:
                self.logger.error(f"Failed to terminate process {pid}")
                return False
                
            self.logger.info(f"Successfully terminated process: {pid}")
            return True
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            self.logger.error(f"Error terminating process {pid}: {e}")
            return False
            
        except Exception as e:
            self.logger.error(f"Unexpected error terminating process {pid}: {e}")
            return False

class NotificationAction(ResponseAction):
    """Send notifications about detected threats."""
    
    def execute(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send notifications about a threat.
        
        Args:
            threat: Threat to notify about
            
        Returns:
            Dictionary with notification results
        """
        result = {
            "action": "notification",
            "success": False,
            "methods": {},
            "details": {}
        }
        
        try:
            # Format the threat information for notification
            threat_info = self._format_threat_info(threat)
            result["details"]["threat_info"] = threat_info
            
            # Decide which notification methods to use based on severity
            notification_config = self.config.get("notification", {})
            methods = []
            
            if threat["severity"] >= 4:  # High severity
                if notification_config.get("email", False):
                    methods.append("email")
                if notification_config.get("slack", False):
                    methods.append("slack")
                if notification_config.get("webhook", False):
                    methods.append("webhook")
                    
            elif threat["severity"] >= 2:  # Medium severity
                if notification_config.get("email", False):
                    methods.append("email")
                    
            # Low severity threats might not need immediate notification
            
            # Send notifications by each method
            success = False
            for method in methods:
                method_result = False
                
                if method == "email":
                    method_result = self._send_email_notification(threat_info)
                elif method == "slack":
                    method_result = self._send_slack_notification(threat_info)
                elif method == "webhook":
                    method_result = self._send_webhook_notification(threat_info)
                    
                result["methods"][method] = method_result
                
                # If any method succeeds, consider the notification successful
                if method_result:
                    success = True
                    
            result["success"] = success
            
            if success:
                self._log_action("notification", 
                            f"{', '.join(methods)} for {threat['type']}", 
                            True, 
                            {"methods": methods})
            else:
                self._log_action("notification", 
                            f"all methods for {threat['type']}", 
                            False,
                            {"methods": methods})
                            
        except Exception as e:
            self.logger.error(f"Error in notification action: {e}", exc_info=True)
            result["details"]["error"] = str(e)
            
        return result
        
    def _format_threat_info(self, threat: Dict[str, Any]) -> str:
        """Format threat information for notifications."""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(threat["timestamp"]))
        
        info = f"""
LESH SECURITY ALERT: {threat['type'].upper()}
Timestamp: {timestamp}
Source: {threat['source']}
Severity: {threat['severity']}/5
Confidence: {threat['confidence']:.2f}

Details:
"""
        
        # Add threat details
        for key, value in threat["details"].items():
            if key != "anomaly_reasons":
                info += f"- {key}: {value}\n"
                
        # Add anomaly reasons if present
        if "anomaly_reasons" in threat["details"]:
            info += "\nReasons for detection:\n"
            for reason in threat["details"]["anomaly_reasons"]:
                info += f"- {reason}\n"
                
        info += f"\nThreat ID: {threat['id']}"
        
        return info
        
    def _send_email_notification(self, threat_info: str) -> bool:
        """
        Send email notification.
        
        Args:
            threat_info: Formatted threat information
            
        Returns:
            True if successful, False otherwise
        """
        if self.simulation_mode:
            self.logger.info(f"SIMULATION: Would send email notification:\n{threat_info}")
            return True
            
        email_config = self.config.get("notification", {}).get("email_config", {})
        recipients = self.config.get("notification", {}).get("email_recipients", [])
        
        if not recipients:
            self.logger.error("No email recipients configured")
            return False
            
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = email_config.get("sender", "lesh-security@example.com")
            msg['To'] = ", ".join(recipients)
            msg['Subject'] = "LESH SECURITY ALERT - Cybersecurity Threat Detected"
            
            msg.attach(MIMEText(threat_info, 'plain'))
            
            # Connect to SMTP server
            with smtplib.SMTP(email_config.get("smtp_server", "localhost"), 
                             email_config.get("smtp_port", 25)) as server:
                
                # Use TLS if configured
                if email_config.get("use_tls", False):
                    server.starttls()
                    
                # Login if credentials provided
                if email_config.get("username") and email_config.get("password"):
                    server.login(email_config["username"], email_config["password"])
                    
                # Send email
                server.send_message(msg)
                
            self.logger.info(f"Sent email notification to {len(recipients)} recipients")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending email notification: {e}")
            return False
            
    def _send_slack_notification(self, threat_info: str) -> bool:
        """
        Send Slack notification.
        
        Args:
            threat_info: Formatted threat information
            
        Returns:
            True if successful, False otherwise
        """
        if self.simulation_mode:
            self.logger.info(f"SIMULATION: Would send Slack notification:\n{threat_info}")
            return True
            
        slack_config = self.config.get("notification", {}).get("slack_config", {})
        webhook_url = slack_config.get("webhook_url")
        
        if not webhook_url:
            self.logger.error("No Slack webhook URL configured")
            return False
            
        try:
            # Create payload
            payload = {
                "text": "🚨 *LESH SECURITY ALERT* 🚨",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": "🚨 *LESH SECURITY ALERT* 🚨"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "plain_text",
                            "text": threat_info
                        }
                    }
                ]
            }
            
            # Send to Slack
            response = requests.post(webhook_url, json=payload)
            
            if response.status_code == 200:
                self.logger.info("Sent Slack notification successfully")
                return True
            else:
                self.logger.error(f"Error sending Slack notification: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending Slack notification: {e}")
            return False
            
    def _send_webhook_notification(self, threat_info: str) -> bool:
        """
        Send notification to a custom webhook.
        
        Args:
            threat_info: Formatted threat information
            
        Returns:
            True if successful, False otherwise
        """
        if self.simulation_mode:
            self.logger.info(f"SIMULATION: Would send webhook notification")
            return True
            
        webhook_config = self.config.get("notification", {}).get("webhook_config", {})
        webhook_url = webhook_config.get("url")
        
        if not webhook_url:
            self.logger.error("No webhook URL configured")
            return False
            
        try:
            # Create payload (can be customized based on webhook expectations)
            payload = {
                "event_type": "security_alert",
                "timestamp": time.time(),
                "threat_info": threat_info,
                "source": "lesh_cybersecurity_agent"
            }
            
            # Add custom headers if configured
            headers = webhook_config.get("headers", {})
            
            # Send to webhook
            response = requests.post(webhook_url, json=payload, headers=headers)
            
            if response.status_code == 200:
                self.logger.info("Sent webhook notification successfully")
                return True
            else:
                self.logger.error(f"Error sending webhook notification: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending webhook notification: {e}")
            return False

class ResponseManager:
    """
    Manages and orchestrates response actions to security threats.
    Decides which responses are appropriate for each threat.
    """
    
    def __init__(self, config: Config, simulation_mode: bool = False):
        """
        Initialize the response manager.
        
        Args:
            config: Agent configuration
            simulation_mode: If True, don't make actual changes
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.simulation_mode = simulation_mode
        
        # Get response-specific configuration
        response_config = config.get_section("response")
        
        # Create response actions
        self.actions = {
            "network_block": NetworkBlockAction(response_config, simulation_mode),
            "process_terminate": ProcessTerminateAction(response_config, simulation_mode),
            "notification": NotificationAction(response_config, simulation_mode)
        }
        
        # Runtime variables
        self.last_response_time = None
        self.successful_responses = 0
        self._running = False
        
        # Response rules mapping threats to appropriate actions
        self.response_rules = {
            "suspicious_connection": ["network_block", "notification"],
            "suspicious_process": ["process_terminate", "notification"],
            "brute_force_attempt": ["network_block", "notification"]
        }
        
        # Cache to prevent repeated responses to the same threat
        self.response_cache = {}
        self.cooldown_period = response_config.get("cooldown_period", 300)  # 5 minutes default
        
    def start(self):
        """Start the response manager."""
        if self._running:
            return
            
        self.logger.info("Starting response manager")
        self._running = True
        
        if self.simulation_mode:
            self.logger.warning("Response manager running in SIMULATION MODE")
            
        self.logger.info("Response manager started")
        
    def stop(self):
        """Stop the response manager."""
        if not self._running:
            return
            
        self.logger.info("Stopping response manager")
        self._running = False
        
        self.logger.info("Response manager stopped")
    
    def handle_threats(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Handle a list of detected threats with appropriate responses.
        
        Args:
            threats: List of threat dictionaries
            
        Returns:
            List of response result dictionaries
        """
        if not self._running:
            self.logger.warning("Response manager not running, can't handle threats")
            return []
            
        results = []
        
        for threat in threats:
            # Skip if we've already responded to this threat recently
            if self._is_in_cooldown(threat["id"]):
                self.logger.debug(f"Skipping threat {threat['id']} due to cooldown period")
                continue
                
            # Only auto-respond if severity is below threshold
            max_severity = self.config.get("response.max_severity", 3)
            
            if threat["severity"] > max_severity:
                self.logger.warning(
                    f"Threat {threat['id']} severity ({threat['severity']}) exceeds auto-response threshold ({max_severity}), "
                    "manual intervention required"
                )
                # Still send notification
                if "notification" in self.actions:
                    result = self.actions["notification"].execute(threat)
                    results.append(result)
                continue
                
            # Get appropriate response actions for this threat type
            response_actions = self.response_rules.get(threat["type"], ["notification"])
            
            # Execute each action
            for action_name in response_actions:
                if action_name in self.actions:
                    result = self.actions[action_name].execute(threat)
                    results.append(result)
                    
                    # Track successful responses
                    if result["success"] == True:
                        self.successful_responses += 1
            
            # Update cooldown cache
            self._add_to_cooldown(threat["id"])
            
        # Update last response time
        if results:
            self.last_response_time = time.time()
            
        return results
    
    def _is_in_cooldown(self, threat_id: str) -> bool:
        """Check if a threat is in the cooldown period."""
        if threat_id in self.response_cache:
            last_time = self.response_cache[threat_id]
            if time.time() - last_time < self.cooldown_period:
                return True
        return False
        
    def _add_to_cooldown(self, threat_id: str):
        """Add a threat to the cooldown cache."""
        self.response_cache[threat_id] = time.time()
        
        # Clean up old entries
        self._cleanup_cooldown_cache()
        
    def _cleanup_cooldown_cache(self):
        """Clean up old entries in the cooldown cache."""
        now = time.time()
        expired_entries = [
            threat_id for threat_id, timestamp in self.response_cache.items()
            if now - timestamp >= self.cooldown_period
        ]
        
        for threat_id in expired_entries:
            del self.response_cache[threat_id]
            
    def get_status(self) -> Dict[str, Any]:
        """
        Get the status of the response manager.
        
        Returns:
            Dictionary with manager status
        """
        return {
            "running": self._running,
            "simulation_mode": self.simulation_mode,
            "last_response_time": self.last_response_time or 0,
            "successful_responses": self.successful_responses,
            "active_responses": len(self.response_cache),
            "available_actions": list(self.actions.keys())
        }

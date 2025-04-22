"""
Response orchestration module for the Autonomous Cybersecurity Defense Agent.
"""

import logging
import time
import subprocess
import platform
import os
import json
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Any, Optional

from ..utils.logger import log_security_event
from .threat_detection import Threat

class ResponseAction:
    """Base class for response actions."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the response action.
        
        Args:
            config: Configuration dictionary for the response action
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        
    def execute(self, threat: Threat) -> bool:
        """
        Execute the response action for the given threat.
        
        Args:
            threat: The threat to respond to
            
        Returns:
            True if the action was successful, False otherwise
        """
        raise NotImplementedError("Response actions must implement execute method")
        
    def _log_action(self, threat: Threat, action: str, success: bool, details: str = None) -> None:
        """
        Log the response action.
        
        Args:
            threat: The threat being responded to
            action: The action taken
            success: Whether the action was successful
            details: Additional details about the action
        """
        result = "successful" if success else "failed"
        msg = f"Response action {action} {result} for {threat.type} threat {threat.id}"
        
        if details:
            msg += f": {details}"
            
        log_level = logging.INFO if success else logging.ERROR
        log_security_event(msg, level=log_level,
                          threat_id=threat.id, 
                          threat_type=threat.type, 
                          action=action,
                          success=success)

class NetworkBlockAction(ResponseAction):
    """Block network connections related to a threat."""
    
    def execute(self, threat: Threat) -> bool:
        """
        Block network connections related to a threat.
        
        Args:
            threat: The threat to respond to
            
        Returns:
            True if the action was successful, False otherwise
        """
        if threat.type != "suspicious_connection":
            self.logger.warning(f"NetworkBlockAction not applicable for threat type {threat.type}")
            return False
            
        try:
            # Extract remote address from threat details
            if 'remote_address' not in threat.details:
                self.logger.error(f"Missing remote_address in threat details: {threat.details}")
                return False
                
            remote = threat.details['remote_address']
            ip = remote.split(':')[0]
            
            # In simulation mode, just log the action
            if self.config.get('simulation_mode', False):
                self.logger.info(f"SIMULATION: Would block IP {ip} due to threat {threat.id}")
                self._log_action(threat, "network_block", True, f"Simulated blocking {ip}")
                return True
            
            # Implement actual blocking logic based on the OS
            os_name = platform.system().lower()
            success = False
            
            if os_name == 'windows':
                # Use Windows Firewall to block the IP
                cmd = f'netsh advfirewall firewall add rule name="Block {ip} - Security Agent" dir=in action=block remoteip={ip}'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                success = result.returncode == 0
                details = result.stdout if success else result.stderr
                
            elif os_name in ('linux', 'darwin'):  # Linux or macOS
                # Use iptables (Linux) or pf (macOS) to block the IP
                if os_name == 'linux':
                    cmd = f'sudo iptables -A INPUT -s {ip} -j DROP'
                else:  # macOS
                    cmd = f'echo "block in from {ip} to any" | sudo pfctl -ef -'
                    
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                success = result.returncode == 0
                details = result.stdout if success else result.stderr
            
            else:
                self.logger.warning(f"Network blocking not implemented for OS: {os_name}")
                return False
                
            # Log the action
            self._log_action(threat, "network_block", success, 
                            f"{'Successfully blocked' if success else 'Failed to block'} {ip}")
                
            return success
            
        except Exception as e:
            self.logger.error(f"Error executing network block action: {e}", exc_info=True)
            self._log_action(threat, "network_block", False, f"Error: {str(e)}")
            return False

class ProcessTerminateAction(ResponseAction):
    """Terminate a suspicious process."""
    
    def execute(self, threat: Threat) -> bool:
        """
        Terminate a suspicious process.
        
        Args:
            threat: The threat to respond to
            
        Returns:
            True if the action was successful, False otherwise
        """
        if threat.type != "suspicious_process":
            self.logger.warning(f"ProcessTerminateAction not applicable for threat type {threat.type}")
            return False
            
        try:
            # Extract PID from threat details
            if 'pid' not in threat.details:
                self.logger.error(f"Missing pid in threat details: {threat.details}")
                return False
                
            pid = threat.details['pid']
            
            # In simulation mode, just log the action
            if self.config.get('simulation_mode', False):
                self.logger.info(f"SIMULATION: Would terminate process {pid} due to threat {threat.id}")
                self._log_action(threat, "process_terminate", True, f"Simulated terminating PID {pid}")
                return True
            
            # Implement actual process termination
            import psutil
            
            try:
                process = psutil.Process(pid)
                process_name = process.name()
                process.terminate()
                
                # Wait for process to terminate
                try:
                    process.wait(timeout=5)
                    success = True
                    details = f"Successfully terminated {process_name} (PID: {pid})"
                except psutil.TimeoutExpired:
                    # If terminate fails, try kill
                    process.kill()
                    process.wait(timeout=5)
                    success = True
                    details = f"Forcefully killed {process_name} (PID: {pid}) after terminate failed"
                    
            except psutil.NoSuchProcess:
                success = False
                details = f"Process {pid} not found"
            except psutil.AccessDenied:
                success = False
                details = f"Access denied when terminating process {pid}"
                
            # Log the action
            self._log_action(threat, "process_terminate", success, details)
                
            return success
            
        except Exception as e:
            self.logger.error(f"Error executing process termination action: {e}", exc_info=True)
            self._log_action(threat, "process_terminate", False, f"Error: {str(e)}")
            return False

class NotificationAction(ResponseAction):
    """Send notifications about detected threats."""
    
    def execute(self, threat: Threat) -> bool:
        """
        Send notifications about the detected threat.
        
        Args:
            threat: The threat to notify about
            
        Returns:
            True if the notification was sent successfully, False otherwise
        """
        try:
            notification_config = self.config.get('notification', {})
            
            # Format the notification message
            subject = f"Security Alert: {threat.type} detected"
            
            message = f"""
Security Alert: {threat.type} detected

Severity: {threat.severity}/5
Confidence: {threat.confidence:.2f}
Source: {threat.source}
Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(threat.timestamp))}

Details:
{json.dumps(threat.details, indent=2)}
            """
            
            # Track notification success
            success = True
            details = []
            
            # Send email notification if configured
            if notification_config.get('email', False):
                email_success, email_details = self._send_email(subject, message)
                success = success and email_success
                if not email_success:
                    details.append(f"Email: {email_details}")
                    
            # Send Slack notification if configured
            if notification_config.get('slack', False):
                slack_success, slack_details = self._send_slack(subject, message)
                success = success and slack_success
                if not slack_success:
                    details.append(f"Slack: {slack_details}")
                    
            # Send webhook notification if configured
            if notification_config.get('webhook', False):
                webhook_success, webhook_details = self._send_webhook(subject, threat)
                success = success and webhook_success
                if not webhook_success:
                    details.append(f"Webhook: {webhook_details}")
                    
            # Log the action
            detail_str = "; ".join(details) if details else "All notifications sent successfully"
            self._log_action(threat, "notification", success, detail_str)
                
            return success
            
        except Exception as e:
            self.logger.error(f"Error sending notification: {e}", exc_info=True)
            self._log_action(threat, "notification", False, f"Error: {str(e)}")
            return False
            
    def _send_email(self, subject: str, message: str) -> tuple[bool, str]:
        """
        Send an email notification.
        
        Args:
            subject: Email subject
            message: Email message body
            
        Returns:
            Tuple of (success, details)
        """
        try:
            email_config = self.config.get('notification', {}).get('email_config', {})
            
            # Check if email is properly configured
            required_configs = ['smtp_server', 'smtp_port', 'sender', 'recipients']
            for config in required_configs:
                if config not in email_config:
                    return False, f"Missing email config: {config}"
            
            # In simulation mode, just log the action
            if self.config.get('simulation_mode', False):
                self.logger.info(f"SIMULATION: Would send email with subject '{subject}'")
                return True, "Simulated email sending"
                
            # Create message
            msg = MIMEMultipart()
            msg['From'] = email_config['sender']
            msg['To'] = ", ".join(email_config['recipients'])
            msg['Subject'] = subject
            
            msg.attach(MIMEText(message, 'plain'))
            
            # Send email
            with smtplib.SMTP(email_config['smtp_server'], email_config['smtp_port']) as server:
                if email_config.get('use_tls', False):
                    server.starttls()
                    
                if 'username' in email_config and 'password' in email_config:
                    server.login(email_config['username'], email_config['password'])
                    
                server.send_message(msg)
                
            return True, "Email sent successfully"
            
        except Exception as e:
            self.logger.error(f"Error sending email: {e}", exc_info=True)
            return False, str(e)
            
    def _send_slack(self, subject: str, message: str) -> tuple[bool, str]:
        """
        Send a Slack notification.
        
        Args:
            subject: Message subject/title
            message: Message body
            
        Returns:
            Tuple of (success, details)
        """
        try:
            slack_config = self.config.get('notification', {}).get('slack_config', {})
            
            # Check if Slack is properly configured
            if 'webhook_url' not in slack_config:
                return False, "Missing Slack webhook URL"
            
            # In simulation mode, just log the action
            if self.config.get('simulation_mode', False):
                self.logger.info(f"SIMULATION: Would send Slack message with subject '{subject}'")
                return True, "Simulated Slack message sending"
                
            # Format Slack message
            payload = {
                "text": subject,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*{subject}*"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": message
                        }
                    }
                ]
            }
            
            # Send to Slack
            response = requests.post(
                slack_config['webhook_url'],
                json=payload,
                headers={'Content-Type': 'application/json'}
            )
            
            success = response.status_code == 200
            details = "Slack message sent successfully" if success else f"Error: {response.text}"
            
            return success, details
            
        except Exception as e:
            self.logger.error(f"Error sending Slack message: {e}", exc_info=True)
            return False, str(e)
            
    def _send_webhook(self, subject: str, threat: Threat) -> tuple[bool, str]:
        """
        Send a webhook notification.
        
        Args:
            subject: Message subject/title
            threat: The threat object
            
        Returns:
            Tuple of (success, details)
        """
        try:
            webhook_config = self.config.get('notification', {}).get('webhook_config', {})
            
            # Check if webhook is properly configured
            if 'url' not in webhook_config:
                return False, "Missing webhook URL"
            
            # In simulation mode, just log the action
            if self.config.get('simulation_mode', False):
                self.logger.info(f"SIMULATION: Would send webhook with subject '{subject}'")
                return True, "Simulated webhook sending"
                
            # Format webhook payload
            payload = {
                "event_type": "security_alert",
                "title": subject,
                "threat": {
                    "id": threat.id,
                    "type": threat.type,
                    "source": threat.source,
                    "severity": threat.severity,
                    "confidence": threat.confidence,
                    "timestamp": threat.timestamp,
                    "details": threat.details
                }
            }
            
            # Add additional webhook fields if specified
            if 'include_hostname' in webhook_config and webhook_config['include_hostname']:
                payload["hostname"] = platform.node()
                
            # Send to webhook
            headers = {'Content-Type': 'application/json'}
            
            # Add custom headers if specified
            if 'headers' in webhook_config:
                headers.update(webhook_config['headers'])
                
            response = requests.post(
                webhook_config['url'],
                json=payload,
                headers=headers
            )
            
            success = response.status_code == 200
            details = "Webhook sent successfully" if success else f"Error: {response.status_code}, {response.text}"
            
            return success, details
            
        except Exception as e:
            self.logger.error(f"Error sending webhook: {e}", exc_info=True)
            return False, str(e)

class ResponseOrchestrator:
    """Orchestrates response actions based on detected threats."""
    
    def __init__(self, config: Dict[str, Any], simulation_mode: bool = False):
        """
        Initialize the response orchestrator.
        
        Args:
            config: Response configuration
            simulation_mode: If True, actions will be simulated without making changes
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.config['simulation_mode'] = simulation_mode
        
        # Initialize response actions
        self.actions = {
            "network_block": NetworkBlockAction(self.config),
            "process_terminate": ProcessTerminateAction(self.config),
            "notification": NotificationAction(self.config)
        }
        
        # Track metrics
        self.last_response_time = 0
        self.response_count = 0
        self.successful_responses = 0
        
        # Maximum severity level for automatic response (1-5)
        self.max_auto_severity = config.get('max_severity', 3)
        self.auto_response = config.get('auto_response', True)
        
        if simulation_mode:
            self.logger.warning("Running in SIMULATION MODE - actions will be logged but not executed")
            
    def respond_to_threats(self, threats: List[Threat]) -> None:
        """
        Respond to detected threats.
        
        Args:
            threats: List of threats to respond to
        """
        self.last_response_time = time.time()
        
        for threat in threats:
            self._respond_to_threat(threat)
            
        self.logger.info(f"Completed response to {len(threats)} threats")
    
    def _respond_to_threat(self, threat: Threat) -> bool:
        """
        Respond to a single threat.
        
        Args:
            threat: The threat to respond to
            
        Returns:
            True if the response was successful, False otherwise
        """
        self.response_count += 1
        
        # Log the threat
        self.logger.warning(
            f"Responding to {threat.type} threat (ID: {threat.id}, Severity: {threat.severity}/5)"
        )
        
        # Only automatically respond to threats below the configured severity threshold
        if threat.severity > self.max_auto_severity:
            self.logger.warning(
                f"Threat severity {threat.severity} exceeds maximum auto-response threshold "
                f"of {self.max_auto_severity}"
            )
            # Send notification even if we don't take action
            self.actions["notification"].execute(threat)
            return False
        
        # Only respond if auto-response is enabled
        if not self.auto_response:
            self.logger.info("Auto-response is disabled, sending notification only")
            # Send notification even if auto-response is disabled
            self.actions["notification"].execute(threat)
            return False
        
        # Determine appropriate responses based on threat type
        if threat.type == "suspicious_connection":
            success = self.actions["network_block"].execute(threat)
            
        elif threat.type == "suspicious_process":
            success = self.actions["process_terminate"].execute(threat)
            
        else:
            self.logger.warning(f"No defined response actions for threat type: {threat.type}")
            success = False
        
        # Always send notification
        notification_success = self.actions["notification"].execute(threat)
        
        # Update metrics
        if success:
            self.successful_responses += 1
            
            # Mark threat as resolved if response was successful
            threat.resolved = True
            threat.resolution_time = time.time()
            threat.resolution_action = "auto_response"
            
        return success
            
    def get_status(self) -> Dict[str, Any]:
        """
        Get the status of the response orchestrator.
        
        Returns:
            Dictionary with response orchestrator status information
        """
        return {
            "last_response_time": self.last_response_time,
            "total_responses": self.response_count,
            "successful_responses": self.successful_responses,
            "simulation_mode": self.config.get('simulation_mode', False),
            "auto_response": self.auto_response
        }

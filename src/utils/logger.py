import os
import logging
import json
import time
from datetime import datetime
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional


class Logger:
    """
    Custom logger for the Autonomous Cybersecurity Agent.
    Provides structured logging of agent actions, detections, and metrics.
    """
    
    def __init__(self, log_dir: str, config: Dict = None):
        """
        Initialize the logger.
        
        Args:
            log_dir: Directory to store logs
            config: Logger configuration
        """
        self.config = config or {}
        self.log_dir = log_dir
        
        # Create log directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)
        
        # Set up file paths
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_file = os.path.join(log_dir, f"agent_log_{self.timestamp}.log")
        self.metrics_file = os.path.join(log_dir, f"metrics_{self.timestamp}.csv")
        self.alerts_file = os.path.join(log_dir, f"alerts_{self.timestamp}.json")
        
        # Configure standard logging
        logging.basicConfig(
            level=self.config.get('log_level', logging.INFO),
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger("CyberSecAgent")
        
        # Initialize metrics tracking
        self.metrics = []
        self.alerts = []
        
        self.info("Logger initialized")
    
    def info(self, message: str):
        """Log an informational message."""
        self.logger.info(message)
    
    def warning(self, message: str):
        """Log a warning message."""
        self.logger.warning(message)
    
    def error(self, message: str):
        """Log an error message."""
        self.logger.error(message)
    
    def debug(self, message: str):
        """Log a debug message."""
        self.logger.debug(message)
    
    def log_action(self, action_id: int, action_name: str, target: str, 
                  confidence: float, info: Dict[str, Any] = None):
        """
        Log an action taken by the agent.
        
        Args:
            action_id: Numeric ID of the action
            action_name: Name of the action
            target: Target of the action (e.g., host ID)
            confidence: Confidence level in the action
            info: Additional information about the action
        """
        info = info or {}
        
        log_msg = f"ACTION: {action_name} on {target} (confidence: {confidence:.2f})"
        if info:
            log_msg += f", details: {json.dumps(info)}"
        
        self.info(log_msg)
    
    def log_detection(self, detection_type: str, source: str, target: str, 
                     severity: float, details: Dict[str, Any] = None):
        """
        Log a security detection.
        
        Args:
            detection_type: Type of detection (e.g., "port_scan", "data_exfiltration")
            source: Source of the threat
            target: Target of the threat
            severity: Severity level (0-1)
            details: Additional details about the detection
        """
        details = details or {}
        
        # Format severity
        if severity < 0.3:
            severity_str = "LOW"
        elif severity < 0.7:
            severity_str = "MEDIUM"
        else:
            severity_str = "HIGH"
        
        log_msg = f"DETECTION: {detection_type} from {source} to {target} - Severity: {severity_str} ({severity:.2f})"
        self.warning(log_msg)
        
        # Store alert for later analysis
        alert = {
            "timestamp": datetime.now().isoformat(),
            "detection_type": detection_type,
            "source": source,
            "target": target,
            "severity": severity,
            "severity_level": severity_str,
            "details": details
        }
        
        self.alerts.append(alert)
        
        # Periodically save alerts
        if len(self.alerts) % 10 == 0:
            self._save_alerts()
    
    def log_metrics(self, step: int, metrics: Dict[str, Any]):
        """
        Log performance metrics.
        
        Args:
            step: Current step or episode
            metrics: Dictionary of metrics to log
        """
        metric_entry = {"step": step, "timestamp": time.time()}
        metric_entry.update(metrics)
        
        self.metrics.append(metric_entry)
        
        # Log summary
        metrics_str = ", ".join([f"{k}: {v:.4f}" if isinstance(v, float) else f"{k}: {v}" 
                              for k, v in metrics.items()])
        self.info(f"METRICS - Step {step}: {metrics_str}")
        
        # Periodically save metrics
        if len(self.metrics) % 10 == 0:
            self._save_metrics()
    
    def _save_metrics(self):
        """Save metrics to CSV file."""
        df = pd.DataFrame(self.metrics)
        df.to_csv(self.metrics_file, index=False)
    
    def _save_alerts(self):
        """Save alerts to JSON file."""
        with open(self.alerts_file, 'w') as f:
            json.dump(self.alerts, f, indent=2)
    
    def close(self):
        """Close the logger and save all pending data."""
        self._save_metrics()
        self._save_alerts()
        
        self.info("Logger closed")
        
        # Close handlers
        for handler in self.logger.handlers:
            handler.close()
            self.logger.removeHandler(handler)

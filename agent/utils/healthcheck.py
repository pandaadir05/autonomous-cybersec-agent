"""
Health monitoring utilities for the Autonomous Cybersecurity Defense Agent.
"""

import logging
import os
import platform
import psutil
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Any, Optional

@dataclass
class HealthStatus:
    """Health status container."""
    healthy: bool
    message: str
    details: Dict[str, Any]

class HealthMonitor:
    """Monitors the health of the agent and system."""
    
    def __init__(self, agent):
        """
        Initialize health monitor.
        
        Args:
            agent: Reference to the main agent
        """
        self.logger = logging.getLogger(__name__)
        self.agent = agent
        self.start_time = time.time()
        self.last_check_time = 0
        self.status_history = []
        self.max_history = 100
    
    def check_health(self) -> HealthStatus:
        """
        Perform health checks.
        
        Returns:
            HealthStatus object indicating current health state
        """
        self.last_check_time = time.time()
        issues = []
        
        # Check system resources
        cpu_percent = psutil.cpu_percent()
        memory_percent = psutil.virtual_memory().percent
        disk_percent = psutil.disk_usage('/').percent
        
        if cpu_percent > 90:
            issues.append(f"High CPU usage: {cpu_percent}%")
        
        if memory_percent > 90:
            issues.append(f"High memory usage: {memory_percent}%")
            
        if disk_percent > 90:
            issues.append(f"Low disk space: {disk_percent}% used")
        
        # Check thread health
        thread_issues = self._check_thread_health()
        issues.extend(thread_issues)
        
        # Build health status
        healthy = len(issues) == 0
        message = "System healthy" if healthy else f"Health issues detected: {len(issues)}"
        
        # Build detailed status
        details = {
            "uptime": time.time() - self.start_time,
            "system": {
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "disk_percent": disk_percent,
                "platform": platform.platform(),
                "python_version": platform.python_version()
            },
            "agent": self.agent.get_status() if hasattr(self.agent, 'get_status') else {},
            "threads": {t.name: t.is_alive() for t in threading.enumerate()},
            "issues": issues
        }
        
        # Create health status
        status = HealthStatus(healthy=healthy, message=message, details=details)
        
        # Store in history
        self.status_history.append(status)
        if len(self.status_history) > self.max_history:
            self.status_history.pop(0)
            
        return status
    
    def _check_thread_health(self) -> List[str]:
        """
        Check health of threads.
        
        Returns:
            List of thread health issues
        """
        issues = []
        
        # Get expected thread names from agent
        expected_threads = ["ThreatDetection", "Analytics", "HealthCheck"]
        
        # Check if expected threads are running
        current_threads = {t.name: t for t in threading.enumerate()}
        
        for expected in expected_threads:
            if expected not in current_threads:
                issues.append(f"Missing thread: {expected}")
            elif not current_threads[expected].is_alive():
                issues.append(f"Dead thread: {expected}")
                
        return issues
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get health monitor status.
        
        Returns:
            Dictionary with health status information
        """
        return {
            "last_check_time": self.last_check_time,
            "uptime": time.time() - self.start_time,
            "healthy": len(self.status_history) > 0 and self.status_history[-1].healthy
        }

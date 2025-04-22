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
    healthy: bool = True
    message: str = "All systems operational"
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    disk_usage: float = 0.0
    warnings: List[str] = None
    errors: List[str] = None
    
    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []
        if self.errors is None:
            self.errors = []

class HealthCheck:
    """Monitors the health of the agent and system."""
    
    def __init__(self, config: Any):
        """
        Initialize the health monitor.
        
        Args:
            config: Configuration object or dictionary
        """
        self.logger = logging.getLogger(__name__)
        
        # Get config values (handle both dict and object formats)
        if hasattr(config, "get"):
            self.interval = config.get("system.health_check_interval", 120)
            self.warning_threshold = config.get("system.health.warning_threshold", 80)
            self.error_threshold = config.get("system.health.error_threshold", 95)
        else:
            # Assume it's an object with nested attributes
            self.interval = getattr(config, "health_check_interval", 120)
            self.warning_threshold = 80
            self.error_threshold = 95
            
        self.last_check_time = 0
        self.status = HealthStatus()
        
        # Configure components to check
        self.check_cpu = True
        self.check_memory = True
        self.check_disk = True
        self.check_network = True
        
        self.logger.info("Health check initialized")
    
    def run_checks(self) -> HealthStatus:
        """
        Run all health checks and update status.
        
        Returns:
            Current health status
        """
        self.logger.debug("Running health checks")
        self.last_check_time = time.time()
        
        # Reset status for new check
        self.status = HealthStatus()
        self.status.warnings = []
        self.status.errors = []
        
        try:
            # CPU Usage
            if self.check_cpu:
                self._check_cpu()
                
            # Memory Usage
            if self.check_memory:
                self._check_memory()
                
            # Disk Usage
            if self.check_disk:
                self._check_disk()
                
            # Network Connectivity
            if self.check_network:
                self._check_network()
                
            # Set overall health status based on warnings/errors
            if self.status.errors:
                self.status.healthy = False
                self.status.message = f"Health check critical: {len(self.status.errors)} errors detected"
            elif self.status.warnings:
                self.status.healthy = True
                self.status.message = f"Health check warning: {len(self.status.warnings)} warnings detected"
            else:
                self.status.healthy = True
                self.status.message = "All systems operational"
                
            self.logger.debug(f"Health status: {self.status.message}")
            
            return self.status
            
        except Exception as e:
            self.logger.error(f"Error during health check: {e}")
            self.status.healthy = False
            self.status.message = f"Health check error: {str(e)}"
            self.status.errors.append(f"Internal health check error: {str(e)}")
            return self.status
    
    def _check_cpu(self):
        """Check CPU usage."""
        cpu_percent = psutil.cpu_percent(interval=0.5)
        self.status.cpu_usage = cpu_percent
        
        if cpu_percent >= self.error_threshold:
            self.status.errors.append(f"CPU usage critical: {cpu_percent}%")
        elif cpu_percent >= self.warning_threshold:
            self.status.warnings.append(f"CPU usage high: {cpu_percent}%")
    
    def _check_memory(self):
        """Check memory usage."""
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        self.status.memory_usage = memory_percent
        
        if memory_percent >= self.error_threshold:
            self.status.errors.append(f"Memory usage critical: {memory_percent}%")
        elif memory_percent >= self.warning_threshold:
            self.status.warnings.append(f"Memory usage high: {memory_percent}%")
    
    def _check_disk(self):
        """Check disk usage."""
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        self.status.disk_usage = disk_percent
        
        if disk_percent >= self.error_threshold:
            self.status.errors.append(f"Disk usage critical: {disk_percent}%")
        elif disk_percent >= self.warning_threshold:
            self.status.warnings.append(f"Disk usage high: {disk_percent}%")
    
    def _check_network(self):
        """Check basic network connectivity."""
        try:
            # Simple connectivity test - try to resolve a domain name
            import socket
            socket.gethostbyname("www.google.com")
        except Exception as e:
            self.status.warnings.append(f"Network connectivity issue: {str(e)}")
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get the current health status.
        
        Returns:
            Dictionary with health status information
        """
        return {
            "healthy": self.status.healthy,
            "message": self.status.message,
            "last_check": self.last_check_time,
            "cpu_usage": self.status.cpu_usage,
            "memory_usage": self.status.memory_usage,
            "disk_usage": self.status.disk_usage,
            "warnings": self.status.warnings,
            "errors": self.status.errors
        }

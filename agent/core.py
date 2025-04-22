"""
Core functionality for the Autonomous Cybersecurity Defense Agent.
"""

import logging
import threading
import time
from typing import Dict, Any, List

from .modules.threat_detection import ThreatDetector
from .modules.response import ResponseOrchestrator
from .modules.analytics import AnalyticsEngine
from .utils.healthcheck import HealthMonitor

class DefenseAgent:
    """Main agent class that orchestrates all cybersecurity defense operations."""
    
    def __init__(self, config: Dict[str, Any], simulation_mode: bool = False):
        """
        Initialize the defense agent.
        
        Args:
            config: Configuration dictionary
            simulation_mode: If True, no actual system changes will be made
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.simulation_mode = simulation_mode
        self.running = False
        self._stop_event = threading.Event()
        
        # Initialize components
        self.logger.info("Initializing agent components")
        self.threat_detector = ThreatDetector(config.get('detection', {}))
        self.response_orchestrator = ResponseOrchestrator(
            config.get('response', {}), 
            simulation_mode=simulation_mode
        )
        self.analytics_engine = AnalyticsEngine(config.get('analytics', {}))
        self.health_monitor = HealthMonitor(self)
        
        # Component threads
        self._threads = []
        
    def start(self):
        """Start the agent and all its components."""
        if self.running:
            self.logger.warning("Agent is already running")
            return
            
        self.logger.info("Starting agent components")
        self._stop_event.clear()
        self.running = True
        
        # Start component threads
        thread_configs = [
            (self._threat_detection_loop, "ThreatDetection"),
            (self._analytics_loop, "Analytics"),
            (self._health_check_loop, "HealthCheck")
        ]
        
        for target_func, name in thread_configs:
            thread = threading.Thread(target=target_func, name=name, daemon=True)
            thread.start()
            self._threads.append(thread)
            
        self.logger.info("Agent started successfully")
        
        if self.simulation_mode:
            self.logger.warning("Running in SIMULATION MODE - no actual system changes will be made")
    
    def stop(self):
        """Stop the agent and all its components."""
        if not self.running:
            return
            
        self.logger.info("Stopping agent")
        self._stop_event.set()
        self.running = False
        
        # Wait for all threads to complete
        for thread in self._threads:
            thread.join(timeout=5.0)
            
        self._threads = []
        self.logger.info("Agent stopped")
    
    def is_running(self) -> bool:
        """Check if the agent is currently running."""
        return self.running
    
    def _threat_detection_loop(self):
        """Main loop for threat detection."""
        self.logger.info("Starting threat detection loop")
        detection_interval = self.config.get('detection', {}).get('interval', 60)
        
        while not self._stop_event.is_set():
            try:
                # Run threat detection
                threats = self.threat_detector.detect_threats()
                
                # Handle detected threats
                if threats:
                    self.logger.info(f"Detected {len(threats)} threats")
                    self.response_orchestrator.respond_to_threats(threats)
                    self.analytics_engine.record_threats(threats)
                
                # Wait for next detection cycle
                self._stop_event.wait(detection_interval)
                
            except Exception as e:
                self.logger.error(f"Error in threat detection loop: {e}", exc_info=True)
                self._stop_event.wait(10)  # Shorter wait on error
    
    def _analytics_loop(self):
        """Main loop for analytics processing."""
        self.logger.info("Starting analytics loop")
        analytics_interval = self.config.get('analytics', {}).get('interval', 300)
        
        while not self._stop_event.is_set():
            try:
                # Run analytics
                self.analytics_engine.process_analytics()
                
                # Wait for next analytics cycle
                self._stop_event.wait(analytics_interval)
                
            except Exception as e:
                self.logger.error(f"Error in analytics loop: {e}", exc_info=True)
                self._stop_event.wait(30)  # Shorter wait on error
    
    def _health_check_loop(self):
        """Main loop for health monitoring."""
        self.logger.info("Starting health check loop")
        health_check_interval = self.config.get('system', {}).get('health_check_interval', 120)
        
        while not self._stop_event.is_set():
            try:
                # Run health checks
                health_status = self.health_monitor.check_health()
                
                if not health_status.healthy:
                    self.logger.warning(f"Health check failed: {health_status.message}")
                    
                # Wait for next health check
                self._stop_event.wait(health_check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in health check loop: {e}", exc_info=True)
                self._stop_event.wait(30)  # Shorter wait on error
                
    def get_status(self) -> Dict[str, Any]:
        """Get the current status of the agent."""
        return {
            "running": self.running,
            "simulation_mode": self.simulation_mode,
            "detection": self.threat_detector.get_status(),
            "response": self.response_orchestrator.get_status(),
            "analytics": self.analytics_engine.get_status(),
            "health": self.health_monitor.get_status()
        }

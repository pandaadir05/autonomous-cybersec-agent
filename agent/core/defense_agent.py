"""
Defense Agent - Main agent class that orchestrates detection and response.
"""

import logging
import time
from typing import Dict, List, Any, Optional

from agent.modules.detection import DetectionManager
from agent.modules.response import ResponseManager
from agent.utils.config import Config

class DefenseAgent:
    """
    Main defense agent class that orchestrates the detection and response
    components of the autonomous cybersecurity system.
    """
    
    def __init__(self, config: Dict[str, Any], simulation_mode: bool = False):
        """
        Initialize the defense agent.
        
        Args:
            config: Configuration dictionary
            simulation_mode: If True, don't make actual system changes
        """
        self.logger = logging.getLogger(__name__)
        self.config = Config(config)
        self.simulation_mode = simulation_mode
        
        # Create managers
        self.detection_manager = DetectionManager(self.config)
        self.response_manager = ResponseManager(self.config, simulation_mode)
        
        # Runtime variables
        self._running = False
        self.start_time = None
        self.last_scan_time = None
        self.threats_detected = 0
        
    def start(self):
        """Start the defense agent and all its components."""
        if self._running:
            return
            
        self.logger.info("Starting Defense Agent")
        self._running = True
        self.start_time = time.time()
        
        # Start components
        self.detection_manager.start()
        self.response_manager.start()
        
        self.logger.info("Defense Agent started successfully")
        
    def shutdown(self):
        """Shutdown the defense agent and all its components."""
        if not self._running:
            return
            
        self.logger.info("Shutting down Defense Agent")
        
        # Stop components
        self.detection_manager.stop()
        self.response_manager.stop()
        
        self._running = False
        self.logger.info("Defense Agent shutdown complete")
        
    def scan(self):
        """
        Perform a manual scan for threats.
        
        Returns:
            List of detected threats
        """
        if not self._running:
            self.logger.warning("Cannot scan, agent is not running")
            return []
            
        self.logger.info("Manual scan initiated")
        
        # Run detection
        threats = self.detection_manager.detect_threats()
        self.last_scan_time = time.time()
        
        # Update threats count
        self.threats_detected += len(threats)
        
        if threats:
            self.logger.info(f"Detected {len(threats)} potential threats")
            
            # Handle threats if auto-response is enabled
            if self.config.get("response.auto_response", True):
                self.response_manager.handle_threats(threats)
        else:
            self.logger.info("No threats detected")
            
        return threats
        
    def get_status(self) -> Dict[str, Any]:
        """
        Get the current status of the agent.
        
        Returns:
            Dictionary with agent status
        """
        uptime = time.time() - self.start_time if self.start_time else 0
        
        return {
            "running": self._running,
            "uptime": uptime,
            "simulation_mode": self.simulation_mode,
            "threats_detected": self.threats_detected,
            "last_scan_time": self.last_scan_time,
            "detection_status": self.detection_manager.get_status() if self._running else None,
            "response_status": self.response_manager.get_status() if self._running else None
        }
        
    def handle_event(self, event_type: str, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Handle an external event.
        
        Args:
            event_type: Type of event
            data: Event data
            
        Returns:
            Response data or None
        """
        if not self._running:
            self.logger.warning(f"Cannot handle event {event_type}, agent is not running")
            return None
            
        self.logger.info(f"Handling event: {event_type}")
        
        # Handle different event types
        if event_type == "scan_request":
            return {"threats": self.scan()}
        elif event_type == "status_request":
            return self.get_status()
        elif event_type == "config_update":
            # Update configuration
            self.config.update(data.get("config", {}))
            return {"status": "config_updated"}
        else:
            self.logger.warning(f"Unknown event type: {event_type}")
            return None

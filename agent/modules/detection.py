"""
Detection management for the Autonomous Cybersecurity Defense Agent.
"""

import logging
import time
from typing import Dict, List, Any, Optional

from agent.modules.threat_detection import ThreatDetector, Threat
from agent.utils.config import Config

class DetectionManager:
    """
    Manages threat detection processes and coordinates different detection methods.
    Acts as an abstraction layer between the agent core and the specific detection methods.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the detection manager.
        
        Args:
            config: Agent configuration
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        
        # Get detection specific config
        detection_config = config.get_section("detection")
        
        # Initialize the threat detector
        self.threat_detector = ThreatDetector(detection_config)
        
        # Runtime variables
        self.last_detection_time = None
        self.active_threats = []
        self._running = False
        
    def start(self):
        """Start the detection manager and its components."""
        if self._running:
            return
            
        self.logger.info("Starting detection manager")
        self._running = True
        
        self.logger.info("Detection manager started")
    
    def stop(self):
        """Stop the detection manager and its components."""
        if not self._running:
            return
            
        self.logger.info("Stopping detection manager")
        self._running = False
        
        self.logger.info("Detection manager stopped")
    
    def run_scan(self) -> List[Dict[str, Any]]:
        """
        Run a complete threat scan using all available detection methods.
        
        Returns:
            List of detected threats as dictionaries
        """
        self.logger.debug("Running threat scan")
        
        # Detect threats using the threat detector
        threats = self.threat_detector.detect_threats()
        
        # Convert Threat objects to dictionaries
        threat_dicts = []
        for threat in threats:
            threat_dict = {
                "id": threat.id,
                "type": threat.type,
                "source": threat.source,
                "severity": threat.severity,
                "confidence": threat.confidence,
                "timestamp": threat.timestamp,
                "details": threat.details if hasattr(threat, "details") else {},
                "resolved": False
            }
            threat_dicts.append(threat_dict)
        
        # Update state
        self.last_detection_time = time.time()
        self.active_threats.extend([t for t in threat_dicts if not t.get("resolved")])
        
        return threat_dicts
    
    def get_active_threats(self) -> List[Dict[str, Any]]:
        """
        Get all active (unresolved) threats.
        
        Returns:
            List of active threats
        """
        return [t for t in self.active_threats if not t.get("resolved")]
    
    def mark_threat_resolved(self, threat_id: str, resolution_details: Dict[str, Any] = None) -> bool:
        """
        Mark a threat as resolved.
        
        Args:
            threat_id: ID of the threat to mark as resolved
            resolution_details: Details about the resolution
            
        Returns:
            True if the threat was found and marked as resolved, False otherwise
        """
        for threat in self.active_threats:
            if threat["id"] == threat_id:
                threat["resolved"] = True
                threat["resolution_time"] = time.time()
                threat["resolution_details"] = resolution_details or {}
                
                self.logger.info(f"Marked threat {threat_id} as resolved")
                return True
        
        self.logger.warning(f"Attempted to mark non-existent threat {threat_id} as resolved")
        return False

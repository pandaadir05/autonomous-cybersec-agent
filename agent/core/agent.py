import time
import logging
import threading
from typing import Dict, List, Optional, Any

from agent.modules.detection import DetectionManager
from agent.modules.response import ResponseManager
from agent.modules.analytics import AnalyticsEngine
from agent.utils.config import Config
from agent.utils.logger import setup_logger
from agent.utils.health_check import HealthCheck

class DefenseAgent:
    """
    Main autonomous cybersecurity defense agent class.
    Orchestrates detection, response, and monitoring components.
    """
    
    def __init__(self, config: Dict[str, Any], simulation_mode: bool = False):
        """
        Initialize the defense agent.
        
        Args:
            config: Configuration dictionary
            simulation_mode: If True, no actual system changes will be made
        """
        self.logger = logging.getLogger(__name__)
        self.config = Config(config)
        self.simulation_mode = simulation_mode
        
        # Initialize components
        self.logger.info("Initializing defense agent components")
        
        # Set up the threat detector
        self.detection_manager = DetectionManager(self.config)
        
        # Set up the response manager (with simulation mode if enabled)
        self.response_manager = ResponseManager(
            self.config,
            simulation_mode=simulation_mode
        )
        
        # Set up the analytics engine for insights
        self.analytics_engine = AnalyticsEngine(self.config)
        
        # Set up health monitoring
        self.health_check = HealthCheck(self.config)
        
        # Runtime variables
        self._running = False
        self._detection_thread = None
        self._health_check_thread = None
        self._last_scan_time = None
        self._stats = {
            "threats_detected": 0,
            "responses_triggered": 0,
            "start_time": None,
        }
        
        self.logger.info("Defense agent initialized successfully")
    
    def start(self):
        """Start the agent and all its components."""
        if self._running:
            self.logger.warning("Agent is already running")
            return
            
        self.logger.info("Starting defense agent")
        self._running = True
        self._stats["start_time"] = time.time()
        
        # Start components
        self.detection_manager.start()
        self.response_manager.start()
        self.analytics_engine.start()
        
        # Start background threads
        self._start_detection_thread()
        self._start_health_check_thread()
        
        self.logger.info("Agent started successfully")
        if self.simulation_mode:
            self.logger.warning("Running in SIMULATION MODE - no actual system changes will be made")

    def stop(self):
        """Stop the agent (alias for shutdown)."""
        self.shutdown()
        
    def is_running(self):
        """Check if the agent is currently running."""
        return self._running

    def shutdown(self):
        """Gracefully shut down the agent and all components."""
        if not self._running:
            return
            
        self.logger.info("Shutting down defense agent")
        self._running = False
        
        # Stop threads
        if self._detection_thread and self._detection_thread.is_alive():
            self._detection_thread.join(timeout=5.0)
        
        if self._health_check_thread and self._health_check_thread.is_alive():
            self._health_check_thread.join(timeout=5.0)
        
        # Stop components
        self.detection_manager.stop()
        self.response_manager.stop()
        self.analytics_engine.stop()
        
        self.logger.info("Agent shutdown complete")
    
    def scan(self) -> List[Dict[str, Any]]:
        """
        Perform a manual threat scan.
        
        Returns:
            List of detected threats
        """
        self.logger.info("Starting manual threat scan")
        threats = self.detection_manager.run_scan()
        
        if threats:
            self.logger.info(f"Detected {len(threats)} potential threats")
            self._stats["threats_detected"] += len(threats)
            
            # Process threats if auto-response is enabled
            if self.config.get("agent.response.auto_response", True):
                self._handle_threats(threats)
        else:
            self.logger.info("No threats detected")
            
        self._last_scan_time = time.time()
        return threats
    
    def get_status(self) -> Dict[str, Any]:
        """Get the current status and statistics of the agent."""
        uptime = 0
        if self._stats["start_time"]:
            uptime = time.time() - self._stats["start_time"]
        
        return {
            "running": self._running,
            "simulation_mode": self.simulation_mode,
            "uptime": uptime,
            "detection": {
                "last_detection_time": self.detection_manager.last_detection_time or 0,
                "total_threats_detected": self._stats["threats_detected"],
                "active_threats": len(self.detection_manager.get_active_threats())
            },
            "response": {
                "last_response_time": self.response_manager.last_response_time or 0,
                "total_responses": self._stats["responses_triggered"],
                "successful_responses": self.response_manager.successful_responses
            },
            "health": self.health_check.get_status()
        }
    
    def _start_detection_thread(self):
        """Start the background thread for periodic threat detection."""
        self._detection_thread = threading.Thread(
            target=self._detection_loop,
            daemon=True,
            name="DetectionThread"
        )
        self._detection_thread.start()
    
    def _start_health_check_thread(self):
        """Start the background thread for system health monitoring."""
        self._health_check_thread = threading.Thread(
            target=self._health_check_loop,
            daemon=True,
            name="HealthCheckThread"
        )
        self._health_check_thread.start()
    
    def _detection_loop(self):
        """Background loop for periodic threat detection."""
        interval = self.config.get("agent.detection.interval", 60)
        
        self.logger.info(f"Starting detection loop with {interval}s interval")
        
        while self._running:
            try:
                threats = self.scan()
                
                if threats:
                    self._handle_threats(threats)
                
                # Sleep for the configured interval
                time.sleep(interval)
            except Exception as e:
                self.logger.error(f"Error in detection loop: {e}")
                time.sleep(10)  # Shorter sleep on error
    
    def _health_check_loop(self):
        """Background loop for health checks."""
        while self._running:
            try:
                self.health_check.run_checks()
                time.sleep(self.health_check.interval)
            except Exception as e:
                self.logger.error(f"Error in health check loop: {e}")
                time.sleep(30)
    
    def _handle_threats(self, threats: List[Dict[str, Any]]):
        """Process and respond to detected threats."""
        response_results = self.response_manager.handle_threats(threats)
        successful_responses = [r for r in response_results if r.get("success")]
        self._stats["responses_triggered"] += len(successful_responses)
        
        # Send analytics data
        self.analytics_engine.record_threats(threats, response_results)

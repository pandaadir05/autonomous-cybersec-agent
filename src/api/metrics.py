"""
Metrics collection and reporting for the Lesh Autonomous Cybersecurity Agent.
Exposes metrics about agent performance, detections, and responses.
"""

import time
import json
import os
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

class MetricsCollector:
    """Collects and manages metrics for the cybersecurity agent."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the metrics collector.
        
        Args:
            config: Configuration dictionary containing metrics settings
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.metrics_dir = Path(config.get("data_dir", "data/analytics"))
        self.metrics_dir.mkdir(parents=True, exist_ok=True)
        
        # Basic metrics structure
        self._metrics = {
            "system": {"uptime": 0, "start_time": time.time()},
            "detection": {"total_scans": 0, "threats_detected": 0},
            "response": {"total_actions": 0, "successful_actions": 0}
        }
        
        self.logger.info("Metrics collector initialized")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get all current metrics."""
        return self._metrics
    
    def update_metric(self, category: str, name: str, value: Any):
        """Update a specific metric value."""
        if category in self._metrics:
            self._metrics[category][name] = value
    
    def save_metrics(self, filename: str = None) -> str:
        """Save current metrics to a JSON file."""
        if filename is None:
            filename = f"metrics_{int(time.time())}.json"
            
        filepath = self.metrics_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(self._metrics, f, indent=2)
            
        return str(filepath)

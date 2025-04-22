"""
Network traffic anomaly detection module.
Identifies unusual patterns in network traffic that may indicate security threats.
"""

import logging
import time
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Tuple, Optional
import ipaddress
import uuid

class NetworkAnomalyDetector:
    """
    Detects anomalies in network traffic using statistical methods.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the network anomaly detector.
        
        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        
        # Detection thresholds
        self.connection_threshold = config.get("connection_threshold", 50)
        self.bandwidth_threshold = config.get("bandwidth_threshold", 10000000)  # 10 MB/s
        self.packet_rate_threshold = config.get("packet_rate_threshold", 1000)  # packets/s
        
        # Traffic history for baseline
        self.traffic_history = {
            "connections": [],
            "bandwidth": [],
            "packet_rate": []
        }
        self.max_history_size = config.get("max_history_size", 100)
        
        # Minimum standard deviation to avoid division by zero or very small values
        self.min_std = 1.0
        
        # Z-score threshold for anomaly detection (default: 3 standard deviations)
        self.z_score_threshold = config.get("z_score_threshold", 3.0)
        
        self.logger.info("Network anomaly detector initialized")
    
    def analyze(self, network_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze network traffic data for anomalies.
        
        Args:
            network_data: Dictionary containing network traffic metrics
        
        Returns:
            List of detected anomalies
        """
        threats = []
        
        try:
            connections = network_data.get("connections", [])
            bytes_per_second = network_data.get("bytes_per_second", 0)
            packets_per_second = network_data.get("packets_per_second", 0)
            
            # Update traffic history
            self._update_history("connections", len(connections))
            self._update_history("bandwidth", bytes_per_second)
            self._update_history("packet_rate", packets_per_second)
            
            # Check for anomalies
            connection_anomaly = self._check_connection_anomaly(connections)
            if connection_anomaly:
                threats.append(connection_anomaly)
            
            bandwidth_anomaly = self._check_bandwidth_anomaly(bytes_per_second)
            if bandwidth_anomaly:
                threats.append(bandwidth_anomaly)
            
            packet_rate_anomaly = self._check_packet_rate_anomaly(packets_per_second)
            if packet_rate_anomaly:
                threats.append(packet_rate_anomaly)
            
        except Exception as e:
            self.logger.error(f"Error in network anomaly detection: {e}")
        
        return threats
    
    def _update_history(self, metric: str, value: float) -> None:
        """
        Update the traffic history for a specific metric.
        
        Args:
            metric: The metric to update
            value: The new value to add
        """
        self.traffic_history[metric].append(value)
        
        # Keep history size limited
        if len(self.traffic_history[metric]) > self.max_history_size:
            self.traffic_history[metric].pop(0)
    
    def _check_connection_anomaly(self, connections: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Check for anomalies in connection count.
        
        Args:
            connections: List of network connections
        
        Returns:
            Anomaly detection result or None
        """
        connection_count = len(connections)
        
        # Always check for threshold breach first - this is a hard limit
        if connection_count > self.connection_threshold:
            return self._create_anomaly_result("connection_spike", connection_count, self.connection_threshold)
            
        # Also check for statistical anomaly if we have enough history
        if len(self.traffic_history["connections"]) >= 3:
            # Calculate Z-score
            avg = np.mean(self.traffic_history["connections"])
            std = max(np.std(self.traffic_history["connections"]), self.min_std)
            z_score = (connection_count - avg) / std
            
            if z_score > self.z_score_threshold:
                return self._create_anomaly_result("connection_spike", connection_count, avg, z_score)
        
        return None
    
    def _check_bandwidth_anomaly(self, bytes_per_second: float) -> Optional[Dict[str, Any]]:
        """
        Check for anomalies in bandwidth usage.
        
        Args:
            bytes_per_second: Current bandwidth usage
        
        Returns:
            Anomaly detection result or None
        """
        # Always check for threshold breach first - this is a hard limit
        if bytes_per_second > self.bandwidth_threshold:
            return self._create_anomaly_result("bandwidth_spike", bytes_per_second, self.bandwidth_threshold)
        
        # Also check for statistical anomaly if we have enough history
        if len(self.traffic_history["bandwidth"]) >= 3:
            # Calculate Z-score
            avg = np.mean(self.traffic_history["bandwidth"])
            std = max(np.std(self.traffic_history["bandwidth"]), self.min_std)
            z_score = (bytes_per_second - avg) / std
            
            if z_score > self.z_score_threshold:
                return self._create_anomaly_result("bandwidth_spike", bytes_per_second, avg, z_score)
        
        return None
    
    def _check_packet_rate_anomaly(self, packets_per_second: float) -> Optional[Dict[str, Any]]:
        """
        Check for anomalies in packet rate.
        
        Args:
            packets_per_second: Current packet rate
        
        Returns:
            Anomaly detection result or None
        """
        # Always check for threshold breach first - this is a hard limit
        if packets_per_second > self.packet_rate_threshold:
            return self._create_anomaly_result("packet_rate_spike", packets_per_second, self.packet_rate_threshold)
        
        # Also check for statistical anomaly if we have enough history
        if len(self.traffic_history["packet_rate"]) >= 3:
            # Calculate Z-score
            avg = np.mean(self.traffic_history["packet_rate"])
            std = max(np.std(self.traffic_history["packet_rate"]), self.min_std)
            z_score = (packets_per_second - avg) / std
            
            if z_score > self.z_score_threshold:
                return self._create_anomaly_result("packet_rate_spike", packets_per_second, avg, z_score)
        
        return None
    
    def _create_anomaly_result(self, anomaly_type: str, current_value: float,
                               threshold_or_avg: float, z_score: float = None) -> Dict[str, Any]:
        """
        Create a standardized anomaly result dictionary.
        
        Args:
            anomaly_type: Type of anomaly detected
            current_value: Current value that triggered the anomaly
            threshold_or_avg: Either the threshold or average value
            z_score: Z-score if available

        Returns:
            Dictionary with anomaly details
        """
        confidence = 0.8  # Base confidence
        
        # If z_score is provided, adjust confidence based on it
        if z_score is not None:
            confidence = min(0.5 + (z_score / 10), 0.95)
            
        # Create descriptive text based on anomaly type
        if anomaly_type == "connection_spike":
            description = "Unusual spike in connection count"
            unit = "connections"
        elif anomaly_type == "bandwidth_spike":
            description = "Unusual spike in network bandwidth"
            unit = "bytes/sec"
            current_value_mb = current_value / 1000000
            threshold_mb = threshold_or_avg / 1000000
            display_value = f"{current_value_mb:.2f} MB/s"
            display_threshold = f"{threshold_mb:.2f} MB/s"
        elif anomaly_type == "packet_rate_spike":
            description = "Unusual spike in network packet rate"
            unit = "packets/sec"
            display_value = f"{current_value} packets/s"
            display_threshold = f"{threshold_or_avg} packets/s"
        else:
            description = f"Unknown anomaly type: {anomaly_type}"
            unit = "units"
            display_value = str(current_value)
            display_threshold = str(threshold_or_avg)
            
        # Create appropriate reasons array
        reasons = [f"Abnormal {unit.replace('_', ' ')}"]
        
        if z_score is not None:
            reasons.append(f"Value {current_value} is {z_score:.2f} standard deviations above normal")
        else:
            reasons.append(f"Value {current_value} exceeds threshold of {threshold_or_avg}")
            
        return {
            "id": str(uuid.uuid4()),
            "timestamp": time.time(),
            "type": anomaly_type,
            "source": "network",
            "severity": 3,
            "confidence": confidence,
            "details": {
                "description": description,
                "current_value": current_value,
                "threshold" if z_score is None else "average": threshold_or_avg,
                "z_score": z_score if z_score is not None else None,
                "anomaly_reasons": reasons
            }
        }

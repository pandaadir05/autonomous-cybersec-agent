"""
Unit tests for the network anomaly detector module.
"""

import unittest
import sys
from pathlib import Path
import time
import numpy as np
from unittest.mock import patch

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent))

from agent.modules.detection.anomaly import NetworkAnomalyDetector

class TestNetworkAnomalyDetector(unittest.TestCase):
    """Test cases for the NetworkAnomalyDetector class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            "connection_threshold": 10,
            "bandwidth_threshold": 5000000,  # 5 MB/s
            "packet_rate_threshold": 500,  # packets/s
            "max_history_size": 5,
            "z_score_threshold": 3.0
        }
        self.detector = NetworkAnomalyDetector(self.config)
    
    def test_init(self):
        """Test initialization of the detector."""
        self.assertEqual(self.detector.connection_threshold, 10)
        self.assertEqual(self.detector.bandwidth_threshold, 5000000)
        self.assertEqual(self.detector.packet_rate_threshold, 500)
        self.assertEqual(self.detector.max_history_size, 5)
        self.assertEqual(len(self.detector.traffic_history["connections"]), 0)
    
    def test_update_history(self):
        """Test updating traffic history."""
        # Add some values
        for i in range(10):
            self.detector._update_history("connections", i)
        
        # Check the history size is limited
        self.assertEqual(len(self.detector.traffic_history["connections"]), 5)
        # Check the oldest values were removed
        self.assertEqual(self.detector.traffic_history["connections"][0], 5)
    
    def test_detect_connection_spike(self):
        """Test detection of connection count anomalies."""
        # Create a baseline of normal connections
        for i in range(5):
            self.detector._update_history("connections", 5)  # 5 connections is normal
        
        # Test with normal number of connections
        network_data = {
            "connections": [{"local": "127.0.0.1:1234", "remote": "192.168.1.1:80"}] * 7,
            "bytes_per_second": 1000,
            "packets_per_second": 100
        }
        threats = self.detector.analyze(network_data)
        self.assertEqual(len(threats), 0)  # No anomaly detected
        
        # Test with connections exceeding threshold
        network_data = {
            "connections": [{"local": "127.0.0.1:1234", "remote": "192.168.1.1:80"}] * 15,
            "bytes_per_second": 1000,
            "packets_per_second": 100
        }
        threats = self.detector.analyze(network_data)
        self.assertEqual(len(threats), 1)  # Anomaly detected
        self.assertEqual(threats[0]["type"], "connection_spike")
    
    def test_detect_bandwidth_spike(self):
        """Test detection of bandwidth anomalies."""
        # Create a baseline of normal bandwidth
        for i in range(5):
            self.detector._update_history("bandwidth", 1000000)  # 1 MB/s is normal
        
        # Test with normal bandwidth
        network_data = {
            "connections": [],
            "bytes_per_second": 1500000,
            "packets_per_second": 100
        }
        threats = self.detector.analyze(network_data)
        self.assertEqual(len(threats), 0)  # No anomaly detected
        
        # Test with bandwidth exceeding threshold
        network_data = {
            "connections": [],
            "bytes_per_second": 6000000,  # 6 MB/s, above 5 MB/s threshold
            "packets_per_second": 100
        }
        threats = self.detector.analyze(network_data)
        self.assertEqual(len(threats), 1)  # Anomaly detected
        self.assertEqual(threats[0]["type"], "bandwidth_spike")
    
    def test_multiple_anomalies(self):
        """Test detection of multiple simultaneous anomalies."""
        # Create baselines
        for i in range(5):
            self.detector._update_history("connections", 5)
            self.detector._update_history("bandwidth", 1000000)
            self.detector._update_history("packet_rate", 100)
        
        # Test with multiple anomalies
        network_data = {
            "connections": [{"local": "127.0.0.1:1234", "remote": "192.168.1.1:80"}] * 15,  # Above threshold of 10
            "bytes_per_second": 6000000,  # Above threshold of 5 MB/s
            "packets_per_second": 600  # Above threshold of 500 packets/s
        }
        threats = self.detector.analyze(network_data)
        self.assertEqual(len(threats), 3)  # Three anomalies detected
        
        # Check that each threat is of the expected type
        threat_types = [threat["type"] for threat in threats]
        self.assertIn("connection_spike", threat_types)
        self.assertIn("bandwidth_spike", threat_types)
        self.assertIn("packet_rate_spike", threat_types)

if __name__ == '__main__':
    unittest.main()

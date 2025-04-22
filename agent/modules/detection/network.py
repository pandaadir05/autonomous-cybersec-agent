"""
Network-based threat detection for the Lesh agent.
"""

import socket
import subprocess
import re
import os
import time
import logging
from typing import Dict, List, Any, Set

class NetworkDetector:
    """Detects network-based threats like port scanning and unusual traffic."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the network detector."""
        self.logger = logging.getLogger(__name__)
        self.config = config
        
        # Connection tracking
        self.connection_history = {}
        self.port_scan_threshold = config.get("port_scan_threshold", 10)
        self.last_cleanup = time.time()
        
        # Known bad IPs (could be loaded from threat intelligence)
        self.known_bad_ips = set([
            "192.168.1.100",  # Test IP
            "10.0.0.99",      # Test IP
            "172.16.0.200"    # Test IP
        ])
        
    def cleanup_old_data(self):
        """Clean up old connection data."""
        current_time = time.time()
        if current_time - self.last_cleanup > 300:  # Every 5 minutes
            for ip, data in list(self.connection_history.items()):
                # Remove entries older than 10 minutes
                cutoff = current_time - 600
                if data["last_seen"] < cutoff:
                    del self.connection_history[ip]
            
            self.last_cleanup = current_time
    
    def detect_threats(self) -> List[Dict[str, Any]]:
        """
        Detect network-based threats.
        
        Returns:
            List of detected threats
        """
        threats = []
        
        # Clean up old data first
        self.cleanup_old_data()
        
        # Get current connections
        connections = self._get_current_connections()
        
        # Process connections for threat detection
        threats.extend(self._detect_port_scanning(connections))
        threats.extend(self._detect_known_bad_ips(connections))
        threats.extend(self._detect_unusual_traffic_patterns(connections))
        
        return threats
        
    def _get_current_connections(self) -> List[Dict[str, Any]]:
        """Get current network connections."""
        connections = []
        
        try:
            if os.name == 'nt':  # Windows
                cmd = ["netstat", "-n"]
            else:  # Linux/Unix
                cmd = ["netstat", "-tn"]
                
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            for line in result.stdout.splitlines():
                # Parse connection line
                if 'ESTABLISHED' in line or 'SYN_SENT' in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        local = parts[1]
                        remote = parts[2]
                        
                        # Parse IP and port
                        try:
                            local_ip, local_port = local.rsplit(':', 1)
                            remote_ip, remote_port = remote.rsplit(':', 1)
                            
                            connections.append({
                                "local_ip": local_ip,
                                "local_port": int(local_port),
                                "remote_ip": remote_ip,
                                "remote_port": int(remote_port),
                                "state": parts[3] if len(parts) > 3 else "UNKNOWN"
                            })
                        except ValueError:
                            pass
        except Exception as e:
            self.logger.error(f"Error getting connections: {e}")
            
        return connections
    
    def _detect_port_scanning(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect port scanning activity."""
        threats = []
        current_time = time.time()
        
        # Group connections by remote IP
        ip_connections = {}
        for conn in connections:
            remote_ip = conn["remote_ip"]
            if remote_ip not in ip_connections:
                ip_connections[remote_ip] = set()
            
            ip_connections[remote_ip].add(conn["local_port"])
            
            # Update connection history
            if remote_ip not in self.connection_history:
                self.connection_history[remote_ip] = {
                    "first_seen": current_time,
                    "last_seen": current_time,
                    "ports": set(),
                    "connection_count": 0
                }
                
            self.connection_history[remote_ip]["last_seen"] = current_time
            self.connection_history[remote_ip]["ports"].update([conn["local_port"]])
            self.connection_history[remote_ip]["connection_count"] += 1
            
        # Look for scanning patterns
        for ip, data in self.connection_history.items():
            # Is this IP connecting to many different ports?
            if len(data["ports"]) >= self.port_scan_threshold:
                # Calculate time window
                time_window = data["last_seen"] - data["first_seen"]
                # Calculate rate of port access
                if time_window > 0:
                    ports_per_second = len(data["ports"]) / time_window
                    # High rate indicates scanning
                    if ports_per_second > 0.5:  # Threshold: more than 1 port every 2 seconds
                        threats.append({
                            "type": "suspicious_connection",
                            "source": ip,
                            "severity": 3,
                            "confidence": min(0.5 + ports_per_second * 0.1, 0.95),
                            "details": {
                                "description": "Potential port scanning detected",
                                "unique_ports_accessed": len(data["ports"]),
                                "time_window_seconds": round(time_window, 1),
                                "ports_per_second": round(ports_per_second, 2),
                                "remote_address": f"{ip}:{list(data['ports'])[0]}",
                                "anomaly_reasons": [
                                    "High rate of connections to different ports",
                                    "Pattern consistent with port scanning activity"
                                ]
                            }
                        })
        
        return threats
    
    def _detect_known_bad_ips(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect connections to known malicious IP addresses."""
        threats = []
        
        for conn in connections:
            if conn["remote_ip"] in self.known_bad_ips:
                threats.append({
                    "type": "suspicious_connection",
                    "source": conn["remote_ip"],
                    "severity": 4,
                    "confidence": 0.9,
                    "details": {
                        "description": "Connection to known suspicious IP",
                        "remote_address": f"{conn['remote_ip']}:{conn['remote_port']}",
                        "local_address": f"{conn['local_ip']}:{conn['local_port']}",
                        "anomaly_reasons": [
                            "Connection to known suspicious address",
                            "Potential command and control channel"
                        ]
                    }
                })
                
        return threats
    
    def _detect_unusual_traffic_patterns(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual traffic patterns."""
        threats = []
        
        # Look for connections to unusual port combinations
        suspicious_ports = [4444, 31337, 8080, 1337, 9999]
        
        for conn in connections:
            if conn["remote_port"] in suspicious_ports:
                threats.append({
                    "type": "suspicious_connection",
                    "source": conn["remote_ip"],
                    "severity": 2,
                    "confidence": 0.7,
                    "details": {
                        "description": "Connection to suspicious port",
                        "remote_address": f"{conn['remote_ip']}:{conn['remote_port']}",
                        "local_address": f"{conn['local_ip']}:{conn['local_port']}",
                        "anomaly_reasons": [
                            f"Connection to suspicious port {conn['remote_port']}",
                            "Potential backdoor activity"
                        ]
                    }
                })
                
        return threats

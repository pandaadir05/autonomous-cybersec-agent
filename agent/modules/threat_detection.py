"""
Threat detection module for the Autonomous Cybersecurity Defense Agent.
"""

import logging
import time
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
import ipaddress
import re
import socket
import subprocess
import platform
import os
import psutil  # Add missing import

@dataclass
class Threat:
    """Detected security threat."""
    id: str
    type: str
    source: str
    severity: int  # 1-5, where 5 is most severe
    confidence: float  # 0.0-1.0
    timestamp: float
    details: Dict[str, Any]
    resolved: bool = False
    resolution_time: Optional[float] = None
    resolution_action: Optional[str] = None

class ThreatDetector:
    """Detects security threats across multiple sources."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the threat detector.
        
        Args:
            config: Threat detection configuration
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.detected_threats: List[Threat] = []
        self.known_signatures: Set[str] = set()
        self.last_detection_time = 0
        
        # Load threat signatures
        self._load_signatures()
        
        # Initialize detection modules
        self.enabled_modules = config.get("enabled_modules", ["network", "system", "log_analysis"])
        self.logger.info(f"Enabled detection modules: {', '.join(self.enabled_modules)}")
        
        # Thresholds
        self.thresholds = config.get("thresholds", {
            "network_anomaly": 0.8,
            "system_anomaly": 0.7,
        })
    
    def detect_threats(self) -> List[Threat]:
        """
        Run threat detection across all enabled modules.
        
        Returns:
            List of detected threats
        """
        self.last_detection_time = time.time()
        new_threats = []
        
        if "network" in self.enabled_modules:
            network_threats = self._detect_network_threats()
            new_threats.extend(network_threats)
            
        if "system" in self.enabled_modules:
            system_threats = self._detect_system_threats()
            new_threats.extend(system_threats)
            
        if "log_analysis" in self.enabled_modules:
            log_threats = self._analyze_logs()
            new_threats.extend(log_threats)
            
        # Add new unique threats to the list
        existing_ids = {threat.id for threat in self.detected_threats}
        for threat in new_threats:
            if threat.id not in existing_ids:
                self.detected_threats.append(threat)
                existing_ids.add(threat.id)
                
        # Log detection summary
        if new_threats:
            self.logger.info(f"Detected {len(new_threats)} new threats")
            for threat in new_threats:
                self.logger.warning(
                    f"Threat detected: {threat.type} from {threat.source} "
                    f"(Severity: {threat.severity}, Confidence: {threat.confidence:.2f})"
                )
        
        return new_threats
    
    def _detect_network_threats(self) -> List[Threat]:
        """
        Detect network-based threats.
        
        Returns:
            List of detected network threats
        """
        threats = []
        
        try:
            # Check for unusual network connections
            connections = self._get_network_connections()
            suspicious_connections = self._find_suspicious_connections(connections)
            
            for conn in suspicious_connections:
                threat_id = f"network-{conn['local']}:{conn['remote']}-{int(time.time())}"
                threats.append(Threat(
                    id=threat_id,
                    type="suspicious_connection",
                    source=conn['remote'],
                    severity=3,
                    confidence=conn['anomaly_score'],
                    timestamp=time.time(),
                    details={
                        "local_address": conn['local'],
                        "remote_address": conn['remote'],
                        "process": conn['process'],
                        "pid": conn['pid'],
                        "state": conn['state'],
                        "anomaly_reasons": conn['anomaly_reasons']
                    }
                ))
        
        except Exception as e:
            self.logger.error(f"Error in network threat detection: {e}", exc_info=True)
            
        return threats
    
    def _detect_system_threats(self) -> List[Threat]:
        """
        Detect system-based threats.
        
        Returns:
            List of detected system threats
        """
        threats = []
        
        try:
            # Check for suspicious processes
            processes = self._get_processes()
            suspicious_processes = self._find_suspicious_processes(processes)
            
            for proc in suspicious_processes:
                threat_id = f"process-{proc['pid']}-{int(time.time())}"
                threats.append(Threat(
                    id=threat_id,
                    type="suspicious_process",
                    source=f"PID:{proc['pid']}",
                    severity=4,
                    confidence=proc['anomaly_score'],
                    timestamp=time.time(),
                    details={
                        "process_name": proc['name'],
                        "pid": proc['pid'],
                        "cmdline": proc['cmdline'],
                        "username": proc['username'],
                        "cpu_percent": proc['cpu_percent'],
                        "memory_percent": proc['memory_percent'],
                        "anomaly_reasons": proc['anomaly_reasons']
                    }
                ))
                
            # Check for file system anomalies
            # (Implement file system scanning logic here)
            
        except Exception as e:
            self.logger.error(f"Error in system threat detection: {e}", exc_info=True)
            
        return threats
    
    def _analyze_logs(self) -> List[Threat]:
        """
        Analyze logs for security threats.
        
        Returns:
            List of detected log-based threats
        """
        threats = []
        
        try:
            # Implement log analysis logic here
            # This would scan system logs, application logs, etc.
            pass
            
        except Exception as e:
            self.logger.error(f"Error in log analysis: {e}", exc_info=True)
            
        return threats
    
    def _load_signatures(self) -> None:
        """Load threat signatures from signature database."""
        # In a real implementation, this would load signatures from files or a database
        self.known_signatures = {
            # Network signatures
            "network:connection:known_botnet",
            "network:connection:tor_exit_node",
            "network:connection:crypto_mining_pool",
            
            # Process signatures
            "process:name:cryptominer",
            "process:behavior:file_encryption",
            
            # Log signatures
            "log:auth:multiple_failures",
            "log:ssh:brute_force",
        }
        
        self.logger.info(f"Loaded {len(self.known_signatures)} threat signatures")
    
    def _get_network_connections(self) -> List[Dict[str, Any]]:
        """
        Get current network connections.
        
        Returns:
            List of dictionaries with connection information
        """
        connections = []
        
        try:
            net_connections = psutil.net_connections(kind='inet')
            
            for conn in net_connections:
                if conn.laddr and conn.raddr:
                    try:
                        # Get process information if available
                        process_name = ""
                        if conn.pid:
                            try:
                                process = psutil.Process(conn.pid)
                                process_name = process.name()
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                pass
                                
                        connection_info = {
                            'local': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'state': conn.status,
                            'pid': conn.pid,
                            'process': process_name,
                            'anomaly_score': 0.0,
                            'anomaly_reasons': []
                        }
                        connections.append(connection_info)
                    except Exception as e:
                        self.logger.debug(f"Error processing connection: {e}")
        except Exception as e:
            self.logger.error(f"Error getting network connections: {e}", exc_info=True)
            
        return connections
    
    def _find_suspicious_connections(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Find suspicious network connections.
        
        Args:
            connections: List of connection dictionaries
            
        Returns:
            List of suspicious connection dictionaries
        """
        suspicious = []
        threshold = self.thresholds.get('network_anomaly', 0.8)
        
        for conn in connections:
            # Initialize analysis
            anomaly_score = 0.0
            anomaly_reasons = []
            
            # Extract remote IP
            try:
                remote_ip = conn['remote'].split(':')[0]
                
                # Check if it's connecting to suspicious ports
                suspicious_ports = {4444, 8545, 3333, 14444, 9999}
                remote_port = int(conn['remote'].split(':')[1])
                
                if remote_port in suspicious_ports:
                    anomaly_score += 0.6
                    anomaly_reasons.append(f"Suspicious port: {remote_port}")
                    
                # Check if it's connecting to private IP ranges outside local network
                try:
                    ip = ipaddress.ip_address(remote_ip)
                    if ip.is_private and not ip.is_loopback:
                        # Implement logic to check if it's outside your known local network
                        if not remote_ip.startswith("192.168.1."):  # Example check
                            anomaly_score += 0.3
                            anomaly_reasons.append(f"Connection to unknown private IP: {remote_ip}")
                except ValueError:
                    pass
                    
                # Check for connections to processes without names
                if conn['pid'] and not conn['process']:
                    anomaly_score += 0.4
                    anomaly_reasons.append(f"Unknown process (PID: {conn['pid']}) with network activity")
                    
                # Apply final score
                conn['anomaly_score'] = min(1.0, anomaly_score)
                conn['anomaly_reasons'] = anomaly_reasons
                
                # If score exceeds threshold, mark as suspicious
                if anomaly_score >= threshold:
                    suspicious.append(conn)
                    
            except Exception as e:
                self.logger.debug(f"Error analyzing connection {conn['remote']}: {e}")
                
        return suspicious
    
    def _get_processes(self) -> List[Dict[str, Any]]:
        """
        Get information about running processes.
        
        Returns:
            List of dictionaries with process information
        """
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'cpu_percent', 'memory_percent']):
                try:
                    pinfo = proc.info
                    processes.append({
                        'pid': pinfo['pid'],
                        'name': pinfo['name'],
                        'username': pinfo['username'],
                        'cmdline': pinfo['cmdline'],
                        'cpu_percent': pinfo['cpu_percent'] if pinfo['cpu_percent'] is not None else 0,
                        'memory_percent': pinfo['memory_percent'] if pinfo['memory_percent'] is not None else 0,
                        'anomaly_score': 0.0,
                        'anomaly_reasons': []
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except Exception as e:
            self.logger.error(f"Error getting process list: {e}", exc_info=True)
            
        return processes
    
    def _find_suspicious_processes(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Find suspicious processes.
        
        Args:
            processes: List of process dictionaries
            
        Returns:
            List of suspicious process dictionaries
        """
        suspicious = []
        threshold = self.thresholds.get('system_anomaly', 0.7)
        
        # Define suspicious patterns in process names and command lines
        suspicious_names = {
            'miner', 'xmrig', 'cryptonight', 'monero', 'nscript', 'bitsadmin',
            'mimikatz', 'psexec', 'powersploit'
        }
        
        suspicious_cmd_patterns = [
            r'base64 -d', 
            r'wget .* \| bash',
            r'curl .* \| bash',
            r'powershell.*bypass',
            r'powershell.*hidden',
            r'powershell.*encodedcommand',
        ]
        
        for proc in processes:
            # Initialize analysis
            anomaly_score = 0.0
            anomaly_reasons = []
            
            # Check for suspicious process names
            if proc['name'] and any(susp.lower() in proc['name'].lower() for susp in suspicious_names):
                anomaly_score += 0.7
                anomaly_reasons.append(f"Suspicious process name: {proc['name']}")
                
            # Check for high resource usage
            if proc['cpu_percent'] > 90:
                anomaly_score += 0.4
                anomaly_reasons.append(f"High CPU usage: {proc['cpu_percent']}%")
                
            if proc['memory_percent'] > 50:
                anomaly_score += 0.3
                anomaly_reasons.append(f"High memory usage: {proc['memory_percent']}%")
            
            # Check for suspicious command line patterns
            if proc['cmdline']:
                cmdline = ' '.join(proc['cmdline'])
                for pattern in suspicious_cmd_patterns:
                    if re.search(pattern, cmdline, re.IGNORECASE):
                        anomaly_score += 0.6
                        anomaly_reasons.append(f"Suspicious command line pattern: {pattern}")
                        break
                        
            # Apply final score
            proc['anomaly_score'] = min(1.0, anomaly_score)
            proc['anomaly_reasons'] = anomaly_reasons
            
            # If score exceeds threshold, mark as suspicious
            if anomaly_score >= threshold:
                suspicious.append(proc)
                
        return suspicious
        
    def get_status(self) -> Dict[str, Any]:
        """
        Get the status of the threat detector.
        
        Returns:
            Dictionary with threat detector status information
        """
        return {
            "last_detection_time": self.last_detection_time,
            "total_threats_detected": len(self.detected_threats),
            "active_threats": sum(1 for threat in self.detected_threats if not threat.resolved)
        }

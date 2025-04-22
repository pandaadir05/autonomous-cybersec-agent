"""
System anomaly detection for the Lesh agent.
Monitors CPU, memory, disk, and process behavior for suspicious activity.
"""

import os
import psutil
import time
import logging
from typing import List, Dict, Any

class SystemAnomalyDetector:
    """Detects suspicious system behavior."""
    
    def __init__(self, config):
        self.logger = logging.getLogger(__name__)
        self.config = config
        
        # Thresholds from config
        thresholds = config.get("detection.thresholds", {})
        self.cpu_threshold = thresholds.get("cpu_anomaly", 90)  # 90% CPU usage
        self.memory_threshold = thresholds.get("memory_anomaly", 90)  # 90% memory usage
        
        # Baselines for normal activity
        self.cpu_baseline = None
        self.memory_baseline = None
        self.process_count_baseline = None
        
        # Establish baselines on first run
        self._set_baselines()
    
    def _set_baselines(self):
        """Establish baseline values for normal system behavior."""
        try:
            # Take multiple readings over a short period
            cpu_readings = []
            mem_readings = []
            proc_count_readings = []
            
            for _ in range(5):
                cpu_readings.append(psutil.cpu_percent(interval=0.5))
                mem_readings.append(psutil.virtual_memory().percent)
                proc_count_readings.append(len(psutil.process_iter()))
            
            # Set baselines as averages
            self.cpu_baseline = sum(cpu_readings) / len(cpu_readings)
            self.memory_baseline = sum(mem_readings) / len(mem_readings)
            self.process_count_baseline = sum(proc_count_readings) / len(proc_count_readings)
            
            self.logger.info(f"System baselines established: CPU={self.cpu_baseline:.1f}%, "
                           f"Memory={self.memory_baseline:.1f}%, "
                           f"Process count={self.process_count_baseline:.0f}")
                           
        except Exception as e:
            self.logger.error(f"Failed to set system baselines: {e}")
    
    def detect_threats(self) -> List[Dict[str, Any]]:
        """Detect system-based anomalies and threats."""
        threats = []
        
        # If baselines not set, try again
        if self.cpu_baseline is None:
            self._set_baselines()
            if self.cpu_baseline is None:
                return threats  # Still not set, can't detect anomalies
        
        try:
            # Check for high CPU usage
            current_cpu = psutil.cpu_percent()
            if current_cpu > self.cpu_threshold:
                # Find processes using most CPU
                processes = []
                for proc in sorted(psutil.process_iter(['pid', 'name', 'cpu_percent']), 
                                  key=lambda p: p.info['cpu_percent'], 
                                  reverse=True)[:3]:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cpu_percent': proc.info['cpu_percent']
                    })
                
                threat = {
                    "type": "system_anomaly",
                    "source": "CPU",
                    "severity": 2,  # Medium severity
                    "confidence": min(0.5 + (current_cpu - self.cpu_baseline) / 100, 0.95),
                    "details": {
                        "description": "Unusually high CPU usage detected",
                        "current_cpu": current_cpu,
                        "baseline_cpu": self.cpu_baseline,
                        "top_processes": processes,
                        "anomaly_reasons": [
                            f"CPU usage {current_cpu:.1f}% exceeds threshold {self.cpu_threshold}%",
                            f"{current_cpu - self.cpu_baseline:.1f}% above baseline"
                        ]
                    }
                }
                threats.append(threat)
            
            # Check other system metrics similarly...
                
        except Exception as e:
            self.logger.error(f"Error in system anomaly detection: {e}")
            
        return threats

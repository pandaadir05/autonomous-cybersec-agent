import random
import numpy as np
import json
import os
import time
from typing import Dict, List, Tuple, Any
from datetime import datetime, timedelta


class ThreatSimulator:
    """
    Simulates various cybersecurity threats to generate training data for the agent.
    This class provides more sophisticated attack patterns than the base environment.
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize the threat simulator.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Load MITRE ATT&CK techniques (simplified version)
        self.attack_techniques = self._load_attack_techniques()
        
        # Load or generate adversary profiles
        self.adversary_profiles = self._load_adversary_profiles()
        
        # Set up attack chain possibilities
        self.attack_chains = self._create_attack_chains()
    
    def _load_attack_techniques(self) -> Dict[str, Dict[str, Any]]:
        """Load MITRE ATT&CK techniques or create simplified version."""
        # In a real implementation, this would load from MITRE ATT&CK database
        # For now, we create a simplified version
        techniques = {
            "T1046": {
                "name": "Network Service Scanning",
                "tactic": "Discovery",
                "detection_difficulty": 0.3,
                "indicators": ["increased connection attempts", "sequential port access"],
                "typical_duration": 2,
                "network_signatures": [
                    {"protocol": "TCP", "pattern": "sequential_ports", "volume": "medium"},
                    {"protocol": "ICMP", "pattern": "ping_sweep", "volume": "low"}
                ]
            },
            "T1498": {
                "name": "Distributed Denial of Service",
                "tactic": "Impact",
                "detection_difficulty": 0.4,
                "indicators": ["traffic spike", "connection flood"],
                "typical_duration": 8,
                "network_signatures": [
                    {"protocol": "TCP", "pattern": "syn_flood", "volume": "very_high"},
                    {"protocol": "UDP", "pattern": "amplification", "volume": "extreme"}
                ]
            },
            "T1078": {
                "name": "Valid Accounts",
                "tactic": "Persistence",
                "detection_difficulty": 0.7,
                "indicators": ["unusual login times", "unusual account activity"],
                "typical_duration": 12,
                "network_signatures": [
                    {"protocol": "HTTP", "pattern": "credential_usage", "volume": "low"},
                    {"protocol": "SSH", "pattern": "successful_auth", "volume": "low"}
                ]
            },
            "T1059": {
                "name": "Command and Scripting Interpreter",
                "tactic": "Execution",
                "detection_difficulty": 0.6,
                "indicators": ["unusual process execution", "script execution"],
                "typical_duration": 5,
                "network_signatures": [
                    {"protocol": "DNS", "pattern": "unusual_queries", "volume": "medium"},
                    {"protocol": "HTTP", "pattern": "script_download", "volume": "low"}
                ]
            },
            "T1567": {
                "name": "Exfiltration Over Web Service",
                "tactic": "Exfiltration",
                "detection_difficulty": 0.8,
                "indicators": ["large uploads", "unusual destination"],
                "typical_duration": 4,
                "network_signatures": [
                    {"protocol": "HTTPS", "pattern": "large_post", "volume": "high"},
                    {"protocol": "HTTP", "pattern": "encoded_content", "volume": "medium"}
                ]
            },
            "T1110": {
                "name": "Brute Force",
                "tactic": "Credential Access",
                "detection_difficulty": 0.5,
                "indicators": ["repeated auth failures", "account lockouts"],
                "typical_duration": 6,
                "network_signatures": [
                    {"protocol": "SMB", "pattern": "auth_failures", "volume": "high"},
                    {"protocol": "HTTP", "pattern": "login_attempts", "volume": "high"}
                ]
            },
            "T1133": {
                "name": "External Remote Services",
                "tactic": "Initial Access",
                "detection_difficulty": 0.6,
                "indicators": ["VPN connections", "remote desktop"],
                "typical_duration": 10,
                "network_signatures": [
                    {"protocol": "RDP", "pattern": "connection", "volume": "medium"},
                    {"protocol": "SSH", "pattern": "external_ip", "volume": "low"}
                ]
            },
            "T1053": {
                "name": "Scheduled Task/Job",
                "tactic": "Execution",
                "detection_difficulty": 0.7,
                "indicators": ["new scheduled tasks", "unusual timing"],
                "typical_duration": 14,
                "network_signatures": [
                    {"protocol": "HTTPS", "pattern": "periodic_beacon", "volume": "low"},
                    {"protocol": "DNS", "pattern": "timed_requests", "volume": "low"}
                ]
            }
        }
        return techniques
    
    def _load_adversary_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Load or create adversary profiles."""
        profiles = {
            "opportunistic_criminal": {
                "name": "Opportunistic Cybercriminal",
                "sophistication": 0.3,
                "persistence": 0.2,
                "stealth": 0.3,
                "preferred_techniques": ["T1110", "T1046", "T1498"],
                "objectives": ["financial_gain", "quick_impact"]
            },
            "organized_crime": {
                "name": "Organized Crime Group",
                "sophistication": 0.7,
                "persistence": 0.6,
                "stealth": 0.5,
                "preferred_techniques": ["T1078", "T1567", "T1059"],
                "objectives": ["data_theft", "financial_gain", "ransomware"]
            },
            "nation_state": {
                "name": "Nation State Actor",
                "sophistication": 0.9,
                "persistence": 0.9,
                "stealth": 0.8,
                "preferred_techniques": ["T1133", "T1053", "T1078", "T1567"],
                "objectives": ["espionage", "long_term_access", "data_theft"]
            },
            "insider_threat": {
                "name": "Insider Threat",
                "sophistication": 0.5,
                "persistence": 0.4,
                "stealth": 0.6,
                "preferred_techniques": ["T1078", "T1567"],
                "objectives": ["data_theft", "sabotage"]
            },
            "hacktivist": {
                "name": "Hacktivist",
                "sophistication": 0.5,
                "persistence": 0.3,
                "stealth": 0.4,
                "preferred_techniques": ["T1498", "T1046"],
                "objectives": ["disruption", "public_exposure"]
            }
        }
        return profiles
    
    def _create_attack_chains(self) -> Dict[str, List[str]]:
        """Create attack chains based on MITRE ATT&CK tactics."""
        # Map techniques to form realistic attack chains
        chains = {
            "quick_breach": ["T1046", "T1110", "T1078"],
            "data_theft": ["T1046", "T1110", "T1078", "T1059", "T1567"],
            "service_disruption": ["T1046", "T1498"],
            "persistent_access": ["T1046", "T1133", "T1078", "T1053"],
            "ransomware": ["T1046", "T1110", "T1059", "T1498"]
        }
        return chains
    
    def generate_attack_scenario(self, adversary_type: str = None, duration_days: int = 7) -> Dict[str, Any]:
        """
        Generate a complete attack scenario for simulation.
        
        Args:
            adversary_type: Type of adversary to simulate (or random if None)
            duration_days: Duration of the scenario in days
            
        Returns:
            Dictionary with attack scenario details
        """
        # Select adversary
        if not adversary_type or adversary_type not in self.adversary_profiles:
            adversary_type = random.choice(list(self.adversary_profiles.keys()))
        
        adversary = self.adversary_profiles[adversary_type]
        
        # Select attack objective and chain
        objective = random.choice(adversary["objectives"])
        
        # Find suitable attack chain or use a random one
        matching_chains = []
        for chain_name, chain in self.attack_chains.items():
            if any(obj in chain_name for obj in adversary["objectives"]):
                matching_chains.append(chain)
        
        if not matching_chains:
            attack_chain = random.choice(list(self.attack_chains.values()))
        else:
            attack_chain = random.choice(matching_chains)
            
        # Adjust chain based on adversary sophistication
        if adversary["sophistication"] < 0.5:
            # Less sophisticated adversaries don't use all techniques
            attack_chain = attack_chain[:max(2, len(attack_chain) // 2)]
        
        # Generate timeline
        start_time = datetime.now()
        end_time = start_time + timedelta(days=duration_days)
        
        # Generate attack events
        events = []
        current_time = start_time
        
        for i, technique_id in enumerate(attack_chain):
            technique = self.attack_techniques[technique_id]
            
            # Determine timing - sophisticated adversaries space out attacks
            if adversary["stealth"] > 0.6:
                # More gaps between attacks
                time_gap = timedelta(hours=random.randint(8, 48))
            else:
                # Quick succession of attacks
                time_gap = timedelta(hours=random.randint(1, 12))
            
            # Add gap if not first technique
            if i > 0:
                current_time += time_gap
                
            # Skip if past the end time
            if current_time > end_time:
                break
                
            # Generate event duration based on technique and adversary persistence
            base_duration = technique["typical_duration"]
            duration_modifier = 1.0 + adversary["persistence"]
            duration_hours = int(base_duration * duration_modifier)
            
            # Generate detection difficulty based on technique and adversary stealth
            detection_difficulty = min(0.95, technique["detection_difficulty"] * (1.0 + adversary["stealth"]))
            
            # Create the event
            event = {
                "technique_id": technique_id,
                "technique_name": technique["name"],
                "start_time": current_time.isoformat(),
                "duration_hours": duration_hours,
                "detection_difficulty": detection_difficulty,
                "indicators": technique["indicators"],
                "network_signatures": technique["network_signatures"]
            }
            
            events.append(event)
            
            # Move time forward by event duration
            current_time += timedelta(hours=duration_hours)
        
        # Build complete scenario
        scenario = {
            "id": f"scenario_{int(time.time())}",
            "adversary_type": adversary_type,
            "adversary_name": adversary["name"],
            "objective": objective,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "events": events,
            "sophistication_level": adversary["sophistication"],
            "stealth_level": adversary["stealth"]
        }
        
        return scenario
    
    def generate_traffic_data(self, scenario: Dict[str, Any], hosts: int = 10) -> List[Dict[str, Any]]:
        """
        Generate network traffic data based on an attack scenario.
        
        Args:
            scenario: Attack scenario generated by generate_attack_scenario
            hosts: Number of hosts in the network
            
        Returns:
            List of traffic data points
        """
        traffic_data = []
        
        # Generate normal baseline traffic
        baseline_traffic = self._generate_baseline_traffic(hosts, scenario)
        traffic_data.extend(baseline_traffic)
        
        # Generate attack traffic for each event
        for event in scenario["events"]:
            attack_traffic = self._generate_attack_traffic(event, hosts, scenario)
            traffic_data.extend(attack_traffic)
        
        # Sort by timestamp
        traffic_data.sort(key=lambda x: x.get("timestamp", 0))
        
        return traffic_data
    
    def _generate_baseline_traffic(self, hosts: int, scenario: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate baseline normal traffic."""
        traffic = []
        
        # Parse time boundaries
        start_time = datetime.fromisoformat(scenario["start_time"])
        end_time = datetime.fromisoformat(scenario["end_time"])
        current_time = start_time
        
        # Generate hourly traffic samples
        while current_time < end_time:
            # Create traffic for each host
            for host_id in range(hosts):
                # Base traffic parameters
                hour_of_day = current_time.hour
                
                # Model day/night patterns
                if 8 <= hour_of_day <= 18:  # Business hours
                    traffic_volume = random.uniform(50, 100)
                    connection_count = random.randint(10, 30)
                elif 19 <= hour_of_day <= 23:  # Evening
                    traffic_volume = random.uniform(20, 60)
                    connection_count = random.randint(5, 15)
                else:  # Night
                    traffic_volume = random.uniform(5, 30)
                    connection_count = random.randint(1, 10)
                
                # Traffic record
                record = {
                    "timestamp": current_time.timestamp(),
                    "datetime": current_time.isoformat(),
                    "host_id": host_id,
                    "is_attack": False,
                    "host_traffic_volume": traffic_volume,
                    "host_connection_count": connection_count,
                    "host_packet_rate": traffic_volume / 10,
                    "flow_duration": random.uniform(0.5, 5.0),
                    "flow_packet_count": random.randint(5, 50),
                    "flow_bytes_per_second": traffic_volume * 1024,
                    "packet_size_mean": random.uniform(500, 1500),
                    "packet_size_std": random.uniform(100, 300),
                    "packet_interarrival_time": random.uniform(0.01, 0.1)
                }
                
                traffic.append(record)
            
            # Move to next hour
            current_time += timedelta(hours=1)
        
        return traffic
    
    def _generate_attack_traffic(self, event: Dict[str, Any], hosts: int, 
                                scenario: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate attack traffic for an event."""
        traffic = []
        
        # Parse event timing
        start_time = datetime.fromisoformat(event["start_time"])
        end_time = start_time + timedelta(hours=event["duration_hours"])
        
        # Get adversary characteristics
        sophistication = scenario["sophistication_level"]
        stealth = scenario["stealth_level"]
        
        # Select target hosts
        if event["technique_id"] in ["T1498"]:  # DDoS affects multiple hosts
            target_hosts = random.sample(range(hosts), min(hosts, random.randint(1, hosts // 2 + 1)))
        else:
            # Most attacks target specific hosts
            target_count = max(1, int(hosts * 0.3 * (1 - sophistication)))  # More focused with higher sophistication
            target_hosts = random.sample(range(hosts), min(hosts, target_count))
        
        # Select source (attacker)
        if event["technique_id"] in ["T1078", "T1059"]:  # Internal techniques
            source_hosts = random.sample(range(hosts), 1)
        else:
            # External source (represented as a host ID outside the range)
            source_hosts = [hosts + random.randint(1, 5)]
        
        # Generate traffic samples during the attack
        current_time = start_time
        interval = timedelta(minutes=15)  # 15-minute intervals
        
        # Get traffic signatures for this technique
        signatures = event.get("network_signatures", [])
        if not signatures:
            signatures = [{"protocol": "TCP", "pattern": "unknown", "volume": "medium"}]
        
        while current_time < end_time:
            # For each source-target pair
            for source in source_hosts:
                for target in target_hosts:
                    # Skip if source and target are the same (except for insider threats)
                    if source == target and scenario["adversary_type"] != "insider_threat":
                        continue
                    
                    # Select a network signature for this traffic
                    signature = random.choice(signatures)
                    
                    # Base anomaly level - higher for less stealthy attackers
                    base_anomaly = 0.3 + (1 - stealth) * 0.5
                    
                    # Adjust traffic parameters based on signature
                    if signature["pattern"] == "sequential_ports":
                        connection_count = random.randint(50, 200)
                        packet_rate = random.uniform(100, 500)
                        packet_size = random.uniform(60, 100)
                        traffic_volume = connection_count * packet_size / 1024
                        
                    elif signature["pattern"] in ["syn_flood", "amplification"]:
                        connection_count = random.randint(500, 10000)
                        packet_rate = random.uniform(1000, 10000)
                        packet_size = random.uniform(60, 1000)
                        traffic_volume = packet_rate * packet_size / 1024
                        
                    elif signature["pattern"] in ["credential_usage", "successful_auth"]:
                        connection_count = random.randint(5, 20)
                        packet_rate = random.uniform(10, 50)
                        packet_size = random.uniform(200, 500)
                        traffic_volume = packet_rate * packet_size / 1024
                        
                    elif signature["pattern"] in ["large_post", "encoded_content"]:
                        connection_count = random.randint(1, 10)
                        packet_rate = random.uniform(50, 200)
                        packet_size = random.uniform(1000, 10000)
                        traffic_volume = packet_rate * packet_size / 1024
                        
                    else:
                        # Default values
                        connection_count = random.randint(10, 100)
                        packet_rate = random.uniform(50, 200)
                        packet_size = random.uniform(100, 1000)
                        traffic_volume = packet_rate * packet_size / 1024
                    
                    # Adjust based on volume indicator
                    volume_multiplier = {
                        "low": 0.5,
                        "medium": 1.0,
                        "high": 5.0,
                        "very_high": 20.0,
                        "extreme": 100.0
                    }.get(signature["volume"], 1.0)
                    
                    traffic_volume *= volume_multiplier
                    connection_count = int(connection_count * volume_multiplier)
                    packet_rate *= volume_multiplier
                    
                    # Add jitter based on sophistication
                    jitter_factor = 1.0 - 0.9 * sophistication
                    traffic_volume *= random.uniform(1 - jitter_factor, 1 + jitter_factor)
                    connection_count = int(connection_count * random.uniform(1 - jitter_factor, 1 + jitter_factor))
                    packet_rate *= random.uniform(1 - jitter_factor, 1 + jitter_factor)
                    
                    # Create record
                    record = {
                        "timestamp": current_time.timestamp(),
                        "datetime": current_time.isoformat(),
                        "host_id": target,
                        "source_id": source,
                        "is_attack": True,
                        "technique_id": event["technique_id"],
                        "technique_name": event["technique_name"],
                        "host_traffic_volume": traffic_volume,
                        "host_connection_count": connection_count,
                        "host_packet_rate": packet_rate,
                        "flow_duration": random.uniform(0.2, 10.0),
                        "flow_packet_count": int(packet_rate * random.uniform(0.5, 2.0)),
                        "flow_bytes_per_second": traffic_volume * 1024,
                        "packet_size_mean": packet_size,
                        "packet_size_std": packet_size * 0.2,
                        "packet_interarrival_time": 1.0 / packet_rate,
                        "protocol": signature["protocol"],
                        "pattern": signature["pattern"],
                        "anomaly_level": base_anomaly * volume_multiplier
                    }
                    
                    # Highly sophisticated attacks may attempt to blend with normal traffic
                    if sophistication > 0.8 and stealth > 0.8:
                        # Make the attack look more like normal traffic
                        record["host_traffic_volume"] *= 0.3
                        record["host_connection_count"] = int(record["host_connection_count"] * 0.3)
                        record["host_packet_rate"] *= 0.3
                        record["anomaly_level"] *= 0.5
                    
                    traffic.append(record)
            
            # Move to next interval
            current_time += interval
        
        return traffic
    
    def save_scenario(self, scenario: Dict[str, Any], filename: str = None) -> str:
        """
        Save a generated attack scenario to file.
        
        Args:
            scenario: Attack scenario to save
            filename: Output filename (or auto-generated if None)
            
        Returns:
            Path to the saved file
        """
        if filename is None:
            scenario_id = scenario.get("id", f"scenario_{int(time.time())}")
            filename = f"{scenario_id}.json"
        
        os.makedirs("scenarios", exist_ok=True)
        filepath = os.path.join("scenarios", filename)
        
        with open(filepath, 'w') as f:
            json.dump(scenario, f, indent=2)
        
        return filepath
    
    def save_traffic_data(self, traffic_data: List[Dict[str, Any]], filename: str = None) -> str:
        """
        Save generated traffic data to file.
        
        Args:
            traffic_data: Traffic data to save
            filename: Output filename (or auto-generated if None)
            
        Returns:
            Path to the saved file
        """
        if filename is None:
            filename = f"traffic_data_{int(time.time())}.json"
        
        os.makedirs("data", exist_ok=True)
        filepath = os.path.join("data", filename)
        
        with open(filepath, 'w') as f:
            json.dump(traffic_data, f, indent=2)
        
        return filepath
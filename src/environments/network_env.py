import gymnasium as gym
import numpy as np
from gymnasium import spaces
import random
import json
import os
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any


class NetworkSecurityEnv(gym.Env):
    """
    A simulated network environment for training cybersecurity defense agents.
    
    This environment simulates a network with normal traffic and various cyber attacks,
    allowing an agent to take defensive actions.
    """
    
    metadata = {'render_modes': ['console']}
    
    def __init__(self, 
                 config: Dict = None,
                 render_mode: Optional[str] = None):
        """
        Initialize the network security environment.
        
        Args:
            config: Configuration dictionary for the environment
            render_mode: How to render the environment ('console' or None)
        """
        super().__init__()
        
        self.render_mode = render_mode
        self.config = config or {}
        
        # Environment parameters
        self.num_hosts = self.config.get('num_hosts', 10)
        self.max_steps = self.config.get('max_steps', 1000)
        self.attack_probability = self.config.get('attack_probability', 0.1)
        self.step_count = 0
        
        # Define action space
        # 0: Do nothing
        # 1-N: Block traffic from host i
        # N+1-2N: Isolate host i
        # 2N+1-3N: Reset host i
        # 3N+1: Block all external traffic
        self.action_space = spaces.Discrete(3 * self.num_hosts + 2)
        
        # Define observation space (features per host + global features)
        # Features per host: [traffic_volume, connection_count, packet_size_mean, 
        #                    packet_size_std, suspicious_ratio, is_flagged]
        # Global features: [total_traffic, total_alerts, time_since_last_incident]
        host_features = 6
        global_features = 3
        self.observation_space = spaces.Box(
            low=0, 
            high=float('inf'),
            shape=(self.num_hosts * host_features + global_features,),
            dtype=np.float32
        )
        
        # Initialize state
        self.state = None
        self.hosts_status = None
        self.current_attacks = None
        self.blocked_hosts = None
        self.isolated_hosts = None
        
        # Attack types and their impact
        self.attack_types = {
            'port_scan': {'detection_difficulty': 0.2, 'damage': 0.1, 'duration': 3},
            'ddos': {'detection_difficulty': 0.4, 'damage': 0.7, 'duration': 5},
            'malware': {'detection_difficulty': 0.6, 'damage': 0.5, 'duration': 8},
            'data_exfiltration': {'detection_difficulty': 0.8, 'damage': 0.9, 'duration': 4},
            'brute_force': {'detection_difficulty': 0.3, 'damage': 0.4, 'duration': 6}
        }
        
        # Load or create attack patterns
        self.attack_patterns = self._load_attack_patterns()
        
        # Performance metrics
        self.total_damage = 0
        self.successful_mitigations = 0
        self.false_positives = 0
        
        self.reset()
    
    def reset(self, seed=None, options=None):
        """Reset the environment to an initial state."""
        super().reset(seed=seed)
        
        # Reset step count and metrics
        self.step_count = 0
        self.total_damage = 0
        self.successful_mitigations = 0
        self.false_positives = 0
        
        # Initialize host status (0: normal, 1: under attack, 2: compromised)
        self.hosts_status = np.zeros(self.num_hosts, dtype=int)
        
        # Initialize empty list of current attacks
        self.current_attacks = []
        
        # Reset blocked and isolated hosts
        self.blocked_hosts = set()
        self.isolated_hosts = set()
        
        # Generate initial state
        self.state = self._generate_state()
        
        # Information dictionary
        info = {
            "hosts_status": self.hosts_status.copy(),
            "active_attacks": len(self.current_attacks),
            "blocked_hosts": list(self.blocked_hosts),
            "isolated_hosts": list(self.isolated_hosts)
        }
        
        if self.render_mode == 'console':
            self.render()
        
        return self.state, info
    
    def step(self, action):
        """
        Take an action in the environment.
        
        Args:
            action: The action to take
            
        Returns:
            Tuple of (next_state, reward, terminated, truncated, info)
        """
        # Increment step counter
        self.step_count += 1
        
        # Process action
        reward = self._process_action(action)
        
        # Update environment (simulate network and attacks)
        self._update_environment()
        
        # Generate new state
        self.state = self._generate_state()
        
        # Check if episode is done
        terminated = self.step_count >= self.max_steps
        truncated = False
        
        # Generate info dictionary
        info = {
            "hosts_status": self.hosts_status.copy(),
            "active_attacks": len(self.current_attacks),
            "blocked_hosts": list(self.blocked_hosts),
            "isolated_hosts": list(self.isolated_hosts),
            "total_damage": self.total_damage,
            "successful_mitigations": self.successful_mitigations,
            "false_positives": self.false_positives
        }
        
        if self.render_mode == 'console':
            self.render()
        
        return self.state, reward, terminated, truncated, info
    
    def _process_action(self, action):
        """Process agent's action and return reward."""
        reward = 0
        
        # Action 0: Do nothing
        if action == 0:
            # Small negative reward for doing nothing
            reward -= 0.01
            
            # Check if there are active attacks that could have been mitigated
            for attack in self.current_attacks:
                if attack['active']:
                    # Penalty for missing an active attack
                    reward -= 0.1 * self.attack_types[attack['type']]['damage']
        
        # Actions 1-N: Block traffic from host i
        elif 1 <= action <= self.num_hosts:
            host_id = action - 1
            
            # Check if host is already blocked
            if host_id in self.blocked_hosts:
                # Penalty for redundant action
                reward -= 0.05
            else:
                self.blocked_hosts.add(host_id)
                
                # Check if blocking mitigates an attack
                mitigated = False
                for attack in self.current_attacks:
                    if attack['active'] and (attack['source'] == host_id or attack['target'] == host_id):
                        mitigated = True
                        attack['active'] = False
                        self.successful_mitigations += 1
                        # Reward for successful mitigation
                        reward += 1.0 * self.attack_types[attack['type']]['damage']
                
                # If no attack was mitigated, it's a false positive
                if not mitigated:
                    self.false_positives += 1
                    # Penalty for false positive
                    reward -= 0.2
        
        # Actions N+1-2N: Isolate host i
        elif self.num_hosts + 1 <= action <= 2 * self.num_hosts:
            host_id = action - self.num_hosts - 1
            
            # Check if host is already isolated
            if host_id in self.isolated_hosts:
                # Penalty for redundant action
                reward -= 0.05
            else:
                # Remove from blocked if it was blocked
                if host_id in self.blocked_hosts:
                    self.blocked_hosts.remove(host_id)
                
                self.isolated_hosts.add(host_id)
                
                # Check if isolation mitigates an attack
                mitigated = False
                for attack in self.current_attacks:
                    if attack['active'] and (attack['source'] == host_id or attack['target'] == host_id):
                        mitigated = True
                        attack['active'] = False
                        self.successful_mitigations += 1
                        # Higher reward for isolation (more impactful action)
                        reward += 0.8 * self.attack_types[attack['type']]['damage']
                
                # If no attack was mitigated, it's a false positive with higher penalty
                if not mitigated:
                    self.false_positives += 1
                    # Higher penalty for unnecessary isolation
                    reward -= 0.3
        
        # Actions 2N+1-3N: Reset host i
        elif 2 * self.num_hosts + 1 <= action <= 3 * self.num_hosts:
            host_id = action - 2 * self.num_hosts - 1
            
            # Resetting a host removes it from blocked and isolated
            if host_id in self.blocked_hosts:
                self.blocked_hosts.remove(host_id)
            if host_id in self.isolated_hosts:
                self.isolated_hosts.remove(host_id)
            
            # Check if reset mitigates an attack
            mitigated = False
            for attack in self.current_attacks:
                if attack['active'] and (attack['source'] == host_id or attack['target'] == host_id):
                    mitigated = True
                    attack['active'] = False
                    self.successful_mitigations += 1
                    # Reward for successful mitigation but with downtime penalty
                    reward += 0.6 * self.attack_types[attack['type']]['damage']
            
            # If no attack was mitigated, it's a significant false positive
            if not mitigated:
                self.false_positives += 1
                # Higher penalty for unnecessary reset (causes more disruption)
                reward -= 0.5
            
            # Reset host status
            self.hosts_status[host_id] = 0
        
        # Action 3N+1: Block all external traffic
        elif action == 3 * self.num_hosts + 1:
            # Block all hosts
            self.blocked_hosts = set(range(self.num_hosts))
            
            # Mitigate all active attacks
            active_attack_count = 0
            for attack in self.current_attacks:
                if attack['active']:
                    active_attack_count += 1
                    attack['active'] = False
                    self.successful_mitigations += 1
            
            # If there were active attacks, reward proportional to count
            if active_attack_count > 0:
                reward += 0.5 * active_attack_count
            else:
                # Major penalty for blocking all traffic without active attacks
                self.false_positives += 1
                reward -= 1.0
        
        return reward
    
    def _update_environment(self):
        """Update environment state by simulating network activity and attacks."""
        # Update existing attacks
        for attack in self.current_attacks:
            if attack['active']:
                attack['duration'] -= 1
                
                # Check if source or target is blocked/isolated
                source_blocked = attack['source'] in self.blocked_hosts
                source_isolated = attack['source'] in self.isolated_hosts
                target_blocked = attack['target'] in self.blocked_hosts
                target_isolated = attack['target'] in self.isolated_hosts
                
                # If either end is blocked or isolated, attack is not effective
                if source_blocked or source_isolated or target_blocked or target_isolated:
                    # Attack still exists but is not causing damage
                    pass
                else:
                    # Attack causes damage
                    damage = self.attack_types[attack['type']]['damage'] / 10  # Scale damage per step
                    self.total_damage += damage
                    
                    # Update host status based on attack progress
                    if self.hosts_status[attack['target']] < 2:  # Not yet fully compromised
                        # Chance to escalate status based on attack progress
                        if random.random() < 0.2:  # 20% chance each step
                            self.hosts_status[attack['target']] += 1
                
                # Check if attack has ended
                if attack['duration'] <= 0:
                    attack['active'] = False
        
        # Clean up expired attacks
        self.current_attacks = [a for a in self.current_attacks if a['active']]
        
        # Chance to generate new attacks
        if random.random() < self.attack_probability:
            self._generate_attack()
    
    def _generate_attack(self):
        """Generate a new random attack."""
        # Select attack type
        attack_type = random.choice(list(self.attack_types.keys()))
        
        # Select source and target hosts
        valid_hosts = [i for i in range(self.num_hosts) if i not in self.isolated_hosts]
        if not valid_hosts:
            return  # No valid hosts to attack
            
        source = random.choice(valid_hosts)
        
        # External attack (source is the same as target)
        if random.random() < 0.5 and len(valid_hosts) > 1:
            valid_targets = [i for i in valid_hosts if i != source]
            target = random.choice(valid_targets)
        else:
            target = source  # Self-attack (e.g., insider or compromised host)
        
        # Create attack instance
        attack = {
            'type': attack_type,
            'source': source,
            'target': target,
            'duration': self.attack_types[attack_type]['duration'],
            'active': True,
            'detected': False,
            'detection_score': random.random()  # Used for anomaly detection
        }
        
        self.current_attacks.append(attack)
    
    def _generate_state(self):
        """Generate observation state based on current environment."""
        state = []
        
        # Generate features for each host
        for host_id in range(self.num_hosts):
            # Base traffic and statistics
            traffic_volume = max(0, np.random.normal(10, 2))
            connection_count = max(0, np.random.normal(5, 1))
            packet_size_mean = max(0, np.random.normal(100, 10))
            packet_size_std = max(0, np.random.normal(20, 5))
            suspicious_ratio = 0.01  # Base suspicion level
            is_flagged = 0  # Not flagged by default
            
            # Adjust based on host status
            if self.hosts_status[host_id] > 0:
                # Anomalous traffic for hosts under attack/compromised
                traffic_volume *= (1 + self.hosts_status[host_id] * 0.5)
                connection_count *= (1 + self.hosts_status[host_id] * 0.3)
                suspicious_ratio = 0.1 * self.hosts_status[host_id]
                
                if self.hosts_status[host_id] == 2:  # Compromised
                    is_flagged = 1
            
            # Adjust based on active attacks
            for attack in self.current_attacks:
                if attack['active'] and (attack['source'] == host_id or attack['target'] == host_id):
                    attack_impact = self.attack_types[attack['type']]['detection_difficulty'] 
                    
                    # Different attacks have different signatures
                    if attack['type'] == 'port_scan':
                        connection_count *= (1 + 2 * (1 - attack_impact))
                        packet_size_mean *= 0.7
                        packet_size_std *= 0.5
                    elif attack['type'] == 'ddos':
                        traffic_volume *= (1 + 3 * (1 - attack_impact))
                        connection_count *= (1 + 0.5 * (1 - attack_impact))
                    elif attack['type'] == 'malware':
                        suspicious_ratio += (1 - attack_impact) * 0.3
                        if random.random() < 0.7 * (1 - attack_impact):
                            is_flagged = 1
                    elif attack['type'] == 'data_exfiltration':
                        packet_size_mean *= (1 + 0.5 * (1 - attack_impact))
                        packet_size_std *= (1 + 1.0 * (1 - attack_impact))
                        traffic_volume *= (1 + 0.2 * (1 - attack_impact))
                    elif attack['type'] == 'brute_force':
                        connection_count *= (1 + 1.0 * (1 - attack_impact))
                        traffic_volume *= (1 + 0.1 * (1 - attack_impact))
            
            # Adjust for blocked or isolated hosts
            if host_id in self.blocked_hosts:
                traffic_volume *= 0.1
                connection_count *= 0.1
            if host_id in self.isolated_hosts:
                traffic_volume = 0
                connection_count = 0
            
            # Add host features to state
            state.extend([traffic_volume, connection_count, packet_size_mean, 
                          packet_size_std, suspicious_ratio, is_flagged])
        
        # Global features
        total_traffic = sum(state[i] for i in range(0, len(state), 6))  # Sum of all traffic volumes
        total_alerts = sum(1 for attack in self.current_attacks if attack['detected'])
        time_since_last_incident = 10  # Placeholder value
        
        state.extend([total_traffic, total_alerts, time_since_last_incident])
        
        return np.array(state, dtype=np.float32)
    
    def _load_attack_patterns(self):
        """Load or create attack patterns for simulation."""
        # In a real implementation, this would load real attack signatures
        # For now, we'll create a simple mock pattern dictionary
        patterns = {
            'port_scan': {
                'signature': 'Multiple connection attempts to different ports',
                'indicators': ['high connection count', 'low packet size', 'multiple destinations']
            },
            'ddos': {
                'signature': 'Massive traffic increase to single target',
                'indicators': ['very high traffic volume', 'similar packet sizes', 'single destination']
            },
            'malware': {
                'signature': 'Unusual process behavior and communication',
                'indicators': ['suspicious process activity', 'unusual connections', 'periodic beaconing']
            },
            'data_exfiltration': {
                'signature': 'Large data transfers to external locations',
                'indicators': ['large packet sizes', 'unusual destination', 'high bandwidth usage']
            },
            'brute_force': {
                'signature': 'Repeated authentication attempts',
                'indicators': ['many failed logins', 'repeated similar requests', 'authentication errors']
            }
        }
        return patterns
    
    def render(self):
        """Render the environment to the console."""
        if self.render_mode != 'console':
            return
        
        print(f"\n--- Step {self.step_count} ---")
        print(f"Active Attacks: {len(self.current_attacks)}")
        print(f"Blocked Hosts: {sorted(list(self.blocked_hosts))}")
        print(f"Isolated Hosts: {sorted(list(self.isolated_hosts))}")
        print(f"Total Damage: {self.total_damage:.2f}")
        print(f"Successful Mitigations: {self.successful_mitigations}")
        print(f"False Positives: {self.false_positives}")
        
        # Print host status
        print("\nHost Status:")
        for i, status in enumerate(self.hosts_status):
            status_text = "Normal"
            if status == 1:
                status_text = "Under Attack"
            elif status == 2:
                status_text = "Compromised"
            print(f"  Host {i}: {status_text}")
        
        # Print active attacks
        if self.current_attacks:
            print("\nActive Attacks:")
            for i, attack in enumerate(self.current_attacks):
                if attack['active']:
                    print(f"  Attack {i}: {attack['type']} from Host {attack['source']} to Host {attack['target']}, " 
                          f"Duration: {attack['duration']}")
    
    def close(self):
        """Close the environment and release resources."""
        pass
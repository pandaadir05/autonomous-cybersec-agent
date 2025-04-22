"""
Configuration module for training and simulation environments.
"""

from typing import Dict
import os

# Configuration for training
training_config = {
    'num_episodes': 1000,
    'max_steps': 500,
    'log_frequency': 10
}

# Environment configuration
env_config = {
    'num_hosts': 10,
    'max_steps': 500,
    'attack_probability': 0.1
}

# Agent configuration
agent_config = {
    'state_size': 64,  # Base state size + anomaly features
    'action_size': 32,  # Based on environment
    'hidden_layers': [128, 64],
    'learning_rate': 1e-4,
    'batch_size': 64,
    'buffer_size': 10000,
    'gamma': 0.99,
    'tau': 1e-3,
    'update_every': 4,
    'epsilon_start': 1.0,
    'epsilon_min': 0.01,
    'epsilon_decay': 0.995
}

# Feature extraction configuration
feature_config = {
    'time_window': 60,
    'host_features': True,
    'flow_features': True,
    'packet_features': True,
    'scaling_method': 'standard'
}

# Anomaly detection configuration
anomaly_config = {
    'methods': ['autoencoder', 'isolation_forest'],
    'ensemble_weights': [0.7, 0.3],
    'detection_threshold': 0.8,
    'encoding_dims': [32, 16, 8],
    'should_scale': True,
    'batch_size': 32,
    'epochs': 30,
    'learning_rate': 0.001
}

# Paths
paths = {
    'models': 'models',
    'logs': 'logs',
    'data': 'data'
}

# Create directories
for path in paths.values():
    os.makedirs(path, exist_ok=True)

def get_full_config() -> Dict:
    """Get the complete configuration as a dictionary."""
    return {
        'training_config': training_config,
        'env_config': env_config,
        'agent_config': agent_config,
        'feature_config': feature_config,
        'anomaly_config': anomaly_config,
        'paths': paths
    }

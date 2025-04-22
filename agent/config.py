"""
Configuration management for the Autonomous Cybersecurity Defense Agent.
"""

import logging
import os
from pathlib import Path
from typing import Dict, Any, Optional

import yaml
from yaml.parser import ParserError

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "system": {
        "name": "Autonomous Cybersecurity Defense Agent",
        "health_check_interval": 120,  # seconds
    },
    "detection": {
        "interval": 60,  # seconds
        "enabled_modules": ["network", "system", "log_analysis"],
        "thresholds": {
            "network_anomaly": 0.8,
            "system_anomaly": 0.7,
        }
    },
    "response": {
        "auto_response": True,
        "max_severity": 3,  # Maximum severity level for auto-response (1-5)
        "notification": {
            "email": False,
            "slack": False,
            "webhook": False
        }
    },
    "analytics": {
        "interval": 300,  # seconds
        "retention_days": 30,
        "ml_enabled": False
    },
    "logging": {
        "level": "INFO",
        "file": "logs/agent.log",
        "max_size_mb": 10,
        "backup_count": 5
    }
}

def load_config(config_path: Path) -> Dict[str, Any]:
    """
    Load configuration from a YAML file.
    
    Args:
        config_path: Path to the configuration file
        
    Returns:
        Dictionary containing configuration values
    """
    config = DEFAULT_CONFIG.copy()
    
    try:
        if config_path.exists():
            logger.info(f"Loading configuration from {config_path}")
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                
            if user_config:
                # Deep update the default config with user config
                _deep_update(config, user_config)
        else:
            logger.warning(f"Configuration file not found at {config_path}, using defaults")
            
            # Create directory if it doesn't exist
            config_dir = config_path.parent
            if not config_dir.exists():
                config_dir.mkdir(parents=True, exist_ok=True)
                
            # Write default config
            with open(config_path, 'w') as f:
                yaml.dump(config, f, default_flow_style=False)
                
            logger.info(f"Created default configuration at {config_path}")
                
    except (ParserError, IOError) as e:
        logger.error(f"Error loading configuration: {e}", exc_info=True)
        
    return config

def _deep_update(target: Dict, source: Dict) -> None:
    """
    Deep update target dict with source dict.
    For each key in source, if the key exists in target and both values are dicts, 
    recursively update the nested dicts. Otherwise, update the key in target with the value from source.
    
    Args:
        target: Target dictionary to be updated
        source: Source dictionary with values to update
    """
    for key, value in source.items():
        if isinstance(value, dict) and key in target and isinstance(target[key], dict):
            _deep_update(target[key], value)
        else:
            target[key] = value
            
def get_env_config() -> Dict[str, Any]:
    """
    Get configuration values from environment variables.
    
    Returns:
        Dictionary containing configuration values from environment
    """
    env_config = {}
    
    # Map of environment variables to config paths (dot notation)
    env_mappings = {
        "AGENT_LOG_LEVEL": "logging.level",
        "AGENT_DETECTION_INTERVAL": "detection.interval",
        "AGENT_AUTO_RESPONSE": "response.auto_response",
        "AGENT_NOTIFICATION_EMAIL": "response.notification.email",
    }
    
    for env_var, config_path in env_mappings.items():
        if env_var in os.environ:
            value = os.environ[env_var]
            
            # Convert boolean strings to actual booleans
            if value.lower() in ("true", "yes", "1"):
                value = True
            elif value.lower() in ("false", "no", "0"):
                value = False
            # Convert numeric strings to int/float if applicable
            elif value.isdigit():
                value = int(value)
            elif value.replace(".", "", 1).isdigit() and value.count(".") == 1:
                value = float(value)
                
            # Build nested dict from dot notation
            parts = config_path.split(".")
            current = env_config
            for part in parts[:-1]:
                if part not in current:
                    current[part] = {}
                current = current[part]
            current[parts[-1]] = value
    
    return env_config

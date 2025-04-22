"""
Configuration management for the agent.
"""

import os
import logging
from typing import Dict, List, Any, Optional
import yaml

class Config:
    """
    Configuration manager for the agent.
    Provides access to configuration values with support for defaults.
    """
    
    def __init__(self, config_dict: Dict[str, Any]):
        """
        Initialize the configuration manager.
        
        Args:
            config_dict: Configuration dictionary
        """
        self.logger = logging.getLogger(__name__)
        self._config = config_dict
        
    def get(self, key: str, default=None) -> Any:
        """
        Get a configuration value.
        Supports dot notation for nested keys (e.g., "section.subsection.key").
        
        Args:
            key: Configuration key
            default: Default value if key doesn't exist
            
        Returns:
            Configuration value or default
        """
        if "." not in key:
            return self._config.get(key, default)
            
        # Handle nested keys
        parts = key.split(".")
        value = self._config
        
        for part in parts:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return default
                
        return value
        
    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get a configuration section.
        
        Args:
            section: Section name
            
        Returns:
            Section dictionary or empty dict
        """
        return self._config.get(section, {})
        
    def update(self, new_config: Dict[str, Any]) -> None:
        """
        Update the configuration.
        
        Args:
            new_config: New configuration dictionary
        """
        self._deep_update(self._config, new_config)
        self.logger.info("Configuration updated")
    
    def apply_profile(self, profile_name: str) -> None:
        """
        Apply a configuration profile by loading and merging profile-specific settings.
        
        Args:
            profile_name: Name of the profile to apply (corresponds to a YAML file in config/profiles/)
        """
        profile_path = f"config/profiles/{profile_name}.yaml"
        
        try:
            with open(profile_path, 'r') as f:
                profile_config = yaml.safe_load(f)
                
            if profile_config:
                self.update(profile_config)
                self.logger.info(f"Applied configuration profile: {profile_name}")
            else:
                self.logger.warning(f"Profile {profile_name} is empty")
                
        except FileNotFoundError:
            self.logger.error(f"Configuration profile not found: {profile_path}")
        except Exception as e:
            self.logger.error(f"Error applying profile {profile_name}: {e}")
        
    def _deep_update(self, original: Dict[str, Any], update: Dict[str, Any]) -> None:
        """
        Recursively update a dictionary.
        
        Args:
            original: Original dictionary
            update: Dictionary with updates
        """
        for key, value in update.items():
            if key in original and isinstance(original[key], dict) and isinstance(value, dict):
                self._deep_update(original[key], value)
            else:
                original[key] = value

def init_config(config_path: Optional[str] = None) -> Config:
    """
    Initialize configuration from a file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Config object
    """
    logger = logging.getLogger(__name__)
    
    # Default configuration path
    if config_path is None:
        config_path = "config/config.yaml"
        
    config_dict = {}
    
    # Load configuration from file
    try:
        with open(config_path, "r") as f:
            config_dict = yaml.safe_load(f)
        logger.info(f"Loaded configuration from {config_path}")
    except Exception as e:
        logger.error(f"Failed to load configuration from {config_path}: {e}")
        
    return Config(config_dict)

def get_agent_config() -> Dict[str, Any]:
    """
    Get the agent configuration section.
    
    Returns:
        Agent configuration dictionary
    """
    # This is a simple implementation; in a real system, this would use init_config
    config_path = "config/config.yaml"
    
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        return config
    except Exception as e:
        logging.error(f"Failed to load configuration: {e}")
        return {}

"""
Configuration utilities for the Autonomous Cybersecurity Defense Agent.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List, Union

# Setup logger
logger = logging.getLogger(__name__)

class Config:
    """Configuration manager for the agent."""
    
    def __init__(self, config_data: Dict[str, Any]):
        """
        Initialize with configuration dictionary.
        
        Args:
            config_data: Configuration dictionary
        """
        self.config = config_data
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value by path.
        
        Args:
            key_path: Path to configuration value (e.g. "agent.detection.interval")
            default: Default value if path doesn't exist
            
        Returns:
            Configuration value or default
        """
        parts = key_path.split('.')
        curr = self.config
        
        for part in parts:
            if isinstance(curr, dict) and part in curr:
                curr = curr[part]
            else:
                return default
                
        return curr
    
    def get_section(self, section_key: str) -> Dict[str, Any]:
        """
        Get an entire configuration section.
        
        Args:
            section_key: Section key name
            
        Returns:
            Configuration section dictionary (or empty dict if not found)
        """
        return self.config.get(section_key, {})
    
    def set(self, key_path: str, value: Any) -> None:
        """
        Set a configuration value.
        
        Args:
            key_path: Path to configuration value
            value: New value to set
        """
        parts = key_path.split('.')
        curr = self.config
        
        # Navigate to the deepest dict
        for i, part in enumerate(parts[:-1]):
            if part not in curr or not isinstance(curr[part], dict):
                curr[part] = {}
            curr = curr[part]
            
        # Set the value
        curr[parts[-1]] = value
    
    def merge(self, other_config: Dict[str, Any]) -> None:
        """
        Merge another configuration dictionary into this one.
        
        Args:
            other_config: Configuration dictionary to merge
        """
        def _deep_merge(source, update):
            for key, value in update.items():
                if isinstance(value, dict) and key in source and isinstance(source[key], dict):
                    _deep_merge(source[key], value)
                else:
                    source[key] = value
        
        _deep_merge(self.config, other_config)
    
    def get_all(self) -> Dict[str, Any]:
        """
        Get entire configuration dictionary.
        
        Returns:
            Complete configuration dictionary
        """
        return self.config
    
    def validate(self, schema: Dict[str, Any]) -> List[str]:
        """
        Validate the configuration against a schema.
        
        Args:
            schema: Schema dictionary
            
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        
        def _validate_section(schema_section, config_section, path=""):
            for key, value_spec in schema_section.items():
                full_path = f"{path}.{key}" if path else key
                
                # Check if required field is present
                if value_spec.get("required", False) and key not in config_section:
                    errors.append(f"Required field '{full_path}' is missing")
                    continue
                
                # Skip if not present and not required
                if key not in config_section:
                    continue
                
                # Check type
                if "type" in value_spec:
                    expected_type = value_spec["type"]
                    if expected_type == "dict":
                        if not isinstance(config_section[key], dict):
                            errors.append(f"Field '{full_path}' should be a dictionary")
                        elif "children" in value_spec:
                            _validate_section(value_spec["children"], config_section[key], full_path)
                    elif expected_type == "list":
                        if not isinstance(config_section[key], list):
                            errors.append(f"Field '{full_path}' should be a list")
                    elif expected_type == "int":
                        if not isinstance(config_section[key], int):
                            errors.append(f"Field '{full_path}' should be an integer")
                    elif expected_type == "float":
                        if not isinstance(config_section[key], (int, float)):
                            errors.append(f"Field '{full_path}' should be a number")
                    elif expected_type == "bool":
                        if not isinstance(config_section[key], bool):
                            errors.append(f"Field '{full_path}' should be a boolean")
                    elif expected_type == "str":
                        if not isinstance(config_section[key], str):
                            errors.append(f"Field '{full_path}' should be a string")
                
                # Check enum values
                if "enum" in value_spec and config_section[key] not in value_spec["enum"]:
                    errors.append(f"Field '{full_path}' must be one of: {', '.join(value_spec['enum'])}")
                
                # Check range
                if "min" in value_spec and config_section[key] < value_spec["min"]:
                    errors.append(f"Field '{full_path}' must be >= {value_spec['min']}")
                if "max" in value_spec and config_section[key] > value_spec["max"]:
                    errors.append(f"Field '{full_path}' must be <= {value_spec['max']}")
        
        _validate_section(schema, self.config)
        return errors


def load_config(config_path: Union[str, Path]) -> Dict[str, Any]:
    """
    Load configuration from a YAML file.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    config_path = Path(config_path)
    
    if not config_path.exists():
        logger.error(f"Config file not found: {config_path}")
        return {}
    
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
            logger.info(f"Loaded configuration from {config_path}")
            return config
    except Exception as e:
        logger.error(f"Error loading config from {config_path}: {e}")
        return {}


def load_config_with_profile(
    config_path: Union[str, Path], 
    profile: Optional[str] = None
) -> Dict[str, Any]:
    """
    Load configuration with optional profile overlay.
    
    Args:
        config_path: Path to base configuration file
        profile: Optional profile name to load
        
    Returns:
        Merged configuration dictionary
    """
    # Load base config
    base_config = load_config(config_path)
    
    # Return if no profile specified
    if not profile:
        return base_config
    
    # Load profile config
    config_dir = Path(config_path).parent
    profile_path = config_dir / f"profiles/{profile}.yaml"
    
    if not profile_path.exists():
        logger.warning(f"Profile config not found: {profile_path}")
        return base_config
    
    try:
        profile_config = load_config(profile_path)
        
        # Merge configs
        def deep_merge(source, overlay):
            """Deep merge two dictionaries."""
            for key, value in overlay.items():
                if key in source and isinstance(source[key], dict) and isinstance(value, dict):
                    deep_merge(source[key], value)
                else:
                    source[key] = value
        
        # Create a copy of base config and merge profile into it
        merged_config = base_config.copy()
        deep_merge(merged_config, profile_config)
        
        logger.info(f"Loaded and merged profile '{profile}' from {profile_path}")
        return merged_config
        
    except Exception as e:
        logger.error(f"Error loading profile config from {profile_path}: {e}")
        return base_config


def apply_environment_variables(config: Dict[str, Any], prefix: str = "AGENT_") -> Dict[str, Any]:
    """
    Apply environment variable overrides to configuration.
    
    Args:
        config: Configuration dictionary
        prefix: Environment variable prefix to look for
        
    Returns:
        Updated configuration dictionary
    """
    result = config.copy()
    
    # Find all env vars with the prefix
    for env_key, env_value in os.environ.items():
        if not env_key.startswith(prefix):
            continue
            
        # Remove prefix and convert to lowercase
        config_key = env_key[len(prefix):].lower()
        
        # Convert dots/underscores to nested keys
        key_parts = config_key.replace('__', '.').replace('_', '.').split('.')
        
        # Update nested config
        curr = result
        for i, part in enumerate(key_parts[:-1]):
            if part not in curr:
                curr[part] = {}
            elif not isinstance(curr[part], dict):
                # Convert to dict if it's not already
                curr[part] = {}
            curr = curr[part]
        
        # Set the value (with appropriate type conversion)
        env_value = env_value.strip()
        if env_value.lower() == 'true':
            curr[key_parts[-1]] = True
        elif env_value.lower() == 'false':
            curr[key_parts[-1]] = False
        elif env_value.isdigit():
            curr[key_parts[-1]] = int(env_value)
        elif env_value.replace('.', '', 1).isdigit() and env_value.count('.') == 1:
            curr[key_parts[-1]] = float(env_value)
        else:
            curr[key_parts[-1]] = env_value
    
    return result


def get_agent_config() -> Config:
    """Get config instance using default paths."""
    config_path = os.environ.get("AGENT_CONFIG_PATH", "config/config.yaml")
    profile = os.environ.get("AGENT_PROFILE", None)
    
    # Load base config and profile
    config_data = load_config_with_profile(config_path, profile)
    
    # Apply environment variables
    config_data = apply_environment_variables(config_data)
    
    return Config(config_data)


def init_config(config_path: str = None, profile: str = None) -> Config:
    """
    Initialize configuration from file and environment.
    
    Args:
        config_path: Optional path to config file 
        profile: Optional profile name
        
    Returns:
        Config instance
    """
    # Use provided path or environment/default
    if not config_path:
        config_path = os.environ.get("AGENT_CONFIG_PATH", "config/config.yaml")
    
    # Use provided profile or environment
    if not profile:
        profile = os.environ.get("AGENT_PROFILE", None)
    
    # Load config with profile
    config_data = load_config_with_profile(config_path, profile)
    
    # Apply environment variables
    config_data = apply_environment_variables(config_data)
    
    return Config(config_data)

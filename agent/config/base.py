"""
Configuration management for the Autonomous Cybersecurity Defense Agent.
"""
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import yaml
import json
from yaml.parser import ParserError

from agent.config.schema import AgentConfig, EnvironmentConfig
from agent.config.defaults import (
    DEFAULT_AGENT_CONFIG, 
    DEFAULT_ENV_CONFIG,
    DEFAULT_PATHS, 
    CONFIG_PROFILES, 
    ENV_VAR_MAPPINGS
)

logger = logging.getLogger(__name__)

class ConfigManager:
    """Configuration manager for the agent."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to the configuration file
        """
        self.config_path = config_path or DEFAULT_PATHS["config_file"]
        self._config_data = {}
        self._agent_config = None
        self._env_config = None
        self.reload()
    
    def reload(self) -> None:
        """Reload the configuration from file and environment variables."""
        # Start with default config
        self._config_data = {
            "agent": DEFAULT_AGENT_CONFIG.copy(),
            "environment": DEFAULT_ENV_CONFIG.copy()
        }
        
        # Load from file
        self._load_from_file()
        
        # Apply profile-specific settings
        self._apply_profile()
        
        # Override with environment variables
        self._load_from_env()
        
        # Validate configuration
        self._validate_config()
        
        logger.info(f"Configuration loaded successfully")
    
    def _load_from_file(self) -> None:
        """Load configuration from file."""
        try:
            if self.config_path.exists():
                logger.info(f"Loading configuration from {self.config_path}")
                with open(self.config_path, 'r') as f:
                    file_config = yaml.safe_load(f)
                
                if file_config:
                    # Update config with file values
                    if "agent" in file_config:
                        self._deep_update(self._config_data["agent"], file_config["agent"])
                    
                    if "environment" in file_config:
                        self._deep_update(self._config_data["environment"], file_config["environment"])
            else:
                logger.warning(f"Configuration file not found at {self.config_path}, using defaults")
                
                # Create directory if it doesn't exist
                config_dir = self.config_path.parent
                if not config_dir.exists():
                    config_dir.mkdir(parents=True, exist_ok=True)
                
                # Write default config
                with open(self.config_path, 'w') as f:
                    yaml.dump(self._config_data, f, default_flow_style=False)
                
                logger.info(f"Created default configuration at {self.config_path}")
        
        except (ParserError, IOError) as e:
            logger.error(f"Error loading configuration: {e}", exc_info=True)
    
    def _apply_profile(self) -> None:
        """Apply profile-specific settings."""
        profile = self._config_data["agent"].get("profile", "default")
        if profile in CONFIG_PROFILES:
            logger.info(f"Applying configuration profile: {profile}")
            profile_config = CONFIG_PROFILES[profile]
            self._deep_update(self._config_data["agent"], profile_config)
        else:
            logger.warning(f"Unknown profile '{profile}', using default settings")
    
    def _load_from_env(self) -> None:
        """Load configuration from environment variables."""
        for env_var, config_path in ENV_VAR_MAPPINGS.items():
            if env_var in os.environ:
                value = os.environ[env_var]
                
                # Convert string value to appropriate type
                value = self._convert_env_value(value)
                
                # Handle special case for lists
                if env_var == "AGENT_EMAIL_RECIPIENTS" and isinstance(value, str):
                    value = [email.strip() for email in value.split(",")]
                
                # Update config with env value
                parts = config_path.split(".")
                current = self._config_data["agent"]
                for i, part in enumerate(parts):
                    if i == len(parts) - 1:
                        current[part] = value
                    else:
                        if part not in current:
                            current[part] = {}
                        current = current[part]
                
                logger.debug(f"Applied environment variable {env_var} to {config_path}")
    
    def _convert_env_value(self, value: str) -> Any:
        """Convert string environment variable value to appropriate type."""
        # Boolean values
        if value.lower() in ("true", "yes", "1"):
            return True
        elif value.lower() in ("false", "no", "0"):
            return False
        
        # Numeric values
        try:
            if value.isdigit():
                return int(value)
            elif value.replace(".", "", 1).isdigit() and value.count(".") == 1:
                return float(value)
        except (ValueError, AttributeError):
            pass
        
        # JSON parsing (for complex values)
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            pass
        
        # Default: return as string
        return value
    
    def _validate_config(self) -> None:
        """Validate configuration schema."""
        try:
            self._agent_config = AgentConfig(**self._config_data["agent"])
            self._env_config = EnvironmentConfig(**self._config_data["environment"])
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            raise ValueError(f"Configuration validation error: {e}")
    
    def _deep_update(self, target: Dict, source: Dict) -> None:
        """Recursively update a nested dictionary."""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_update(target[key], value)
            else:
                target[key] = value
    
    def save(self) -> None:
        """Save current configuration to file."""
        try:
            # Create directory if it doesn't exist
            config_dir = self.config_path.parent
            if not config_dir.exists():
                config_dir.mkdir(parents=True, exist_ok=True)
            
            # Write config to file
            with open(self.config_path, 'w') as f:
                yaml.dump(self._config_data, f, default_flow_style=False)
            
            logger.info(f"Configuration saved to {self.config_path}")
        
        except IOError as e:
            logger.error(f"Error saving configuration: {e}", exc_info=True)
    
    @property
    def agent(self) -> AgentConfig:
        """Get validated agent configuration."""
        return self._agent_config
    
    @property
    def environment(self) -> EnvironmentConfig:
        """Get validated environment configuration."""
        return self._env_config
    
    def get_raw_config(self) -> Dict:
        """Get raw configuration dictionary."""
        return self._config_data
    
    def generate_example_config(self, path: Optional[Path] = None) -> None:
        """Generate example configuration file with comments."""
        example_path = path or Path("config/example_config.yaml")
        
        # Create example config with comments
        example_config = {}
        
        # Agent section
        example_config["agent"] = DEFAULT_AGENT_CONFIG.copy()
        
        # Environment section
        example_config["environment"] = DEFAULT_ENV_CONFIG.copy()
        
        # Add documentation on profiles
        example_config["_profiles"] = {
            "available": list(CONFIG_PROFILES.keys()),
            "description": "Use 'profile' in the agent section to select a configuration profile"
        }
        
        # Write to file with comments
        try:
            # Create directory if it doesn't exist
            example_dir = example_path.parent
            if not example_dir.exists():
                example_dir.mkdir(parents=True, exist_ok=True)
            
            with open(example_path, 'w') as f:
                f.write("# Autonomous Cybersecurity Defense Agent - Example Configuration\n")
                f.write("# This file shows all available configuration options with default values\n\n")
                
                yaml.dump(example_config, f, default_flow_style=False)
            
            logger.info(f"Example configuration written to {example_path}")
        
        except IOError as e:
            logger.error(f"Error writing example configuration: {e}", exc_info=True)

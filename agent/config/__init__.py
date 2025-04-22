"""
Configuration module for the Autonomous Cybersecurity Defense Agent.
"""
from pathlib import Path
from typing import Dict, Any, Optional

from agent.config.base import ConfigManager
from agent.config.schema import AgentConfig, EnvironmentConfig
from agent.config.defaults import DEFAULT_AGENT_CONFIG, DEFAULT_ENV_CONFIG, ENV_VAR_MAPPINGS

# Global configuration manager instance
_config_manager = None

def init_config(config_path: Optional[Path] = None) -> ConfigManager:
    """
    Initialize configuration manager.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        ConfigManager instance
    """
    global _config_manager
    _config_manager = ConfigManager(config_path)
    return _config_manager

def get_config() -> ConfigManager:
    """
    Get the configuration manager instance.
    
    Returns:
        ConfigManager instance
    """
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager

def reload_config() -> None:
    """Reload configuration from disk and environment variables."""
    get_config().reload()

def get_agent_config() -> AgentConfig:
    """
    Get agent configuration.
    
    Returns:
        AgentConfig object
    """
    return get_config().agent

def get_env_config() -> EnvironmentConfig:
    """
    Get environment configuration.
    
    Returns:
        EnvironmentConfig object
    """
    return get_config().environment

def save_config() -> None:
    """Save current configuration to disk."""
    get_config().save()

def generate_example_config(path: Optional[Path] = None) -> None:
    """
    Generate example configuration file.
    
    Args:
        path: Output path for example configuration
    """
    get_config().generate_example_config(path)

__all__ = [
    'init_config',
    'get_config',
    'reload_config',
    'get_agent_config',
    'get_env_config',
    'save_config',
    'generate_example_config',
    'AgentConfig',
    'EnvironmentConfig'
]

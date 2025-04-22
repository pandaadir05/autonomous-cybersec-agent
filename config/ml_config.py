"""
Configuration settings for machine learning models in the cybersecurity agent.
"""

import os
from pathlib import Path
from typing import Dict, Any, List
import json

class MLConfig:
    """
    Configuration manager for machine learning models.
    """
    
    def __init__(self, config_file: str = None):
        """
        Initialize the ML configuration.
        
        Args:
            config_file: Path to the configuration file
        """
        self.config_file = config_file or os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "config", "ml_models.json"
        )
        self.config = self._load_config()
        
        # Create models directory if it doesn't exist
        self.models_dir = Path(self.config.get("models_directory", "models"))
        self.models_dir.mkdir(exist_ok=True, parents=True)
    
    def _load_config(self) -> Dict[str, Any]:
        """
        Load configuration from file.
        
        Returns:
            Configuration dictionary
        """
        default_config = {
            "models_directory": "models",
            "active_models": ["anomaly_detector", "threat_classifier"],
            "anomaly_detector": {
                "type": "isolation_forest",
                "file": "anomaly_detector.pkl",
                "threshold": 0.85,
                "features": [
                    "bytes_in", "bytes_out", "packets_in", "packets_out",
                    "avg_packet_size", "connection_duration"
                ],
                "hyperparameters": {
                    "contamination": 0.1,
                    "max_samples": 100,
                    "random_state": 42
                }
            },
            "threat_classifier": {
                "type": "random_forest",
                "file": "threat_classifier.pkl",
                "threshold": 0.7,
                "features": [
                    "bytes_in", "bytes_out", "packets_in", "packets_out",
                    "port", "protocol", "src_entropy", "dst_entropy"
                ],
                "hyperparameters": {
                    "n_estimators": 100,
                    "max_depth": 10,
                    "random_state": 42
                }
            },
            "behavior_analyzer": {
                "type": "lstm",
                "file": "behavior_analyzer.h5",
                "sequence_length": 10,
                "features": [
                    "process_cpu", "process_memory", "open_files",
                    "network_connections", "api_calls"
                ],
                "hyperparameters": {
                    "units": 64,
                    "dropout": 0.2,
                    "batch_size": 32,
                    "epochs": 50
                }
            }
        }
        
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            else:
                # Create default configuration file
                os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
                with open(self.config_file, 'w') as f:
                    json.dump(default_config, f, indent=2)
                return default_config
        except Exception as e:
            print(f"Error loading ML configuration: {e}")
            return default_config
    
    def save_config(self) -> bool:
        """
        Save configuration to file.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error saving ML configuration: {e}")
            return False
    
    def get_model_config(self, model_name: str) -> Dict[str, Any]:
        """
        Get configuration for a specific model.
        
        Args:
            model_name: Name of the model
        
        Returns:
            Model configuration dictionary
        """
        return self.config.get(model_name, {})
    
    def get_model_path(self, model_name: str) -> str:
        """
        Get the full path to a model file.
        
        Args:
            model_name: Name of the model
        
        Returns:
            Path to the model file
        """
        model_config = self.get_model_config(model_name)
        model_file = model_config.get("file", f"{model_name}.pkl")
        return str(self.models_dir / model_file)
    
    def is_model_active(self, model_name: str) -> bool:
        """
        Check if a model is active.
        
        Args:
            model_name: Name of the model
        
        Returns:
            True if the model is active, False otherwise
        """
        active_models = self.config.get("active_models", [])
        return model_name in active_models
    
    def get_active_models(self) -> List[str]:
        """
        Get list of active models.
        
        Returns:
            List of active model names
        """
        return self.config.get("active_models", [])
    
    def update_model_config(self, model_name: str, config_updates: Dict[str, Any]) -> bool:
        """
        Update configuration for a specific model.
        
        Args:
            model_name: Name of the model
            config_updates: Dictionary of configuration updates
        
        Returns:
            True if successful, False otherwise
        """
        if model_name not in self.config:
            self.config[model_name] = {}
        
        self.config[model_name].update(config_updates)
        return self.save_config()
    
    def activate_model(self, model_name: str) -> bool:
        """
        Activate a model.
        
        Args:
            model_name: Name of the model
        
        Returns:
            True if successful, False otherwise
        """
        active_models = self.config.get("active_models", [])
        if model_name not in active_models:
            active_models.append(model_name)
            self.config["active_models"] = active_models
            return self.save_config()
        return True
    
    def deactivate_model(self, model_name: str) -> bool:
        """
        Deactivate a model.
        
        Args:
            model_name: Name of the model
        
        Returns:
            True if successful, False otherwise
        """
        active_models = self.config.get("active_models", [])
        if model_name in active_models:
            active_models.remove(model_name)
            self.config["active_models"] = active_models
            return self.save_config()
        return True

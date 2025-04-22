"""
Anomaly detection model for network traffic analysis.
"""

import os
import logging
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple
import pickle
from sklearn.ensemble import IsolationForest
import joblib

class AnomalyDetector:
    """
    Machine learning model for detecting network traffic anomalies.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the anomaly detector.
        
        Args:
            config: Configuration dictionary
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        
        # Default configuration
        self.threshold = self.config.get("threshold", 0.85)
        self.model_type = self.config.get("type", "isolation_forest")
        self.model = None
        self.model_file = self.config.get("file", "anomaly_detector.pkl")
        self.feature_names = None
    
    def train(self, data: pd.DataFrame, feature_columns: List[str] = None) -> Dict[str, Any]:
        """
        Train the anomaly detection model.
        
        Args:
            data: DataFrame containing training data
            feature_columns: List of column names to use as features
        
        Returns:
            Training metrics
        """
        try:
            self.logger.info("Training anomaly detection model")
            
            # Select features
            if feature_columns:
                features = data[feature_columns]
                self.feature_names = feature_columns
            else:
                features = data
                self.feature_names = list(data.columns)
            
            # Initialize the model based on configuration
            if self.model_type == "isolation_forest":
                hyperparams = self.config.get("hyperparameters", {})
                self.model = IsolationForest(
                    contamination=hyperparams.get("contamination", 0.1),
                    max_samples=hyperparams.get("max_samples", 100),
                    random_state=hyperparams.get("random_state", 42),
                    n_jobs=-1
                )
            else:
                self.logger.error(f"Unsupported model type: {self.model_type}")
                return {"error": f"Unsupported model type: {self.model_type}"}
            
            # Fit the model
            self.model.fit(features)
            
            # Calculate training metrics
            predictions = self.model.predict(features)
            anomaly_scores = self.model.decision_function(features)
            
            # Convert predictions: -1 for anomalies, 1 for normal
            anomaly_count = sum(1 for p in predictions if p == -1)
            normal_count = sum(1 for p in predictions if p == 1)
            
            metrics = {
                "anomaly_count": anomaly_count,
                "normal_count": normal_count,
                "anomaly_ratio": anomaly_count / len(features) if len(features) > 0 else 0,
                "avg_anomaly_score": np.mean(anomaly_scores),
                "min_score": np.min(anomaly_scores),
                "max_score": np.max(anomaly_scores)
            }
            
            self.logger.info(f"Anomaly detection model trained: {metrics}")
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error training anomaly detection model: {e}")
            return {"error": str(e)}
    
    def detect(self, data: np.ndarray) -> Dict[str, Any]:
        """
        Detect anomalies in the provided data.
        
        Args:
            data: Input features for anomaly detection
        
        Returns:
            Detection results
        """
        if self.model is None:
            self.logger.error("Anomaly detection model not trained or loaded")
            return {"error": "Model not initialized"}
        
        try:
            # Get raw scores (-1 for anomalies, closer to -1 means more anomalous)
            raw_score = self.model.decision_function(data)
            
            # Convert to a probability-like score (0 to 1, higher means more anomalous)
            # Normalize the scores to 0-1 range where 1 is most anomalous
            anomaly_score = 1 - (raw_score - np.min(raw_score)) / (np.max(raw_score) - np.min(raw_score) + 1e-10)
            
            # Determine if it's an anomaly based on threshold
            is_anomaly = anomaly_score > self.threshold
            
            return {
                "is_anomaly": is_anomaly,
                "anomaly_probability": float(anomaly_score),
                "anomaly_score": anomaly_score,
                "detection_threshold": self.threshold
            }
            
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {e}")
            return {
                "error": str(e),
                "is_anomaly": False,
                "anomaly_probability": 0.0,
                "detection_threshold": self.threshold
            }
    
    def save(self, filepath: str = None) -> bool:
        """
        Save the trained model to a file.
        
        Args:
            filepath: Path to save the model file
        
        Returns:
            True if successful, False otherwise
        """
        if self.model is None:
            self.logger.error("Cannot save - model not trained")
            return False
        
        filepath = filepath or self.model_file
        
        try:
            os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
            
            # Save the model
            joblib.dump({
                "model": self.model,
                "threshold": self.threshold,
                "model_type": self.model_type,
                "feature_names": self.feature_names,
                "config": self.config
            }, filepath)
            
            self.logger.info(f"Anomaly detection model saved to {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving model: {e}")
            return False
    
    def load(self, filepath: str = None) -> bool:
        """
        Load a trained model from a file.
        
        Args:
            filepath: Path to the model file
        
        Returns:
            True if successful, False otherwise
        """
        filepath = filepath or self.model_file
        
        try:
            if not os.path.exists(filepath):
                self.logger.error(f"Model file not found: {filepath}")
                return False
            
            # Load the model
            model_data = joblib.load(filepath)
            
            self.model = model_data["model"]
            self.threshold = model_data.get("threshold", self.threshold)
            self.model_type = model_data.get("model_type", self.model_type)
            self.feature_names = model_data.get("feature_names")
            self.config = model_data.get("config", self.config)
            
            self.logger.info(f"Anomaly detection model loaded from {filepath}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            return False
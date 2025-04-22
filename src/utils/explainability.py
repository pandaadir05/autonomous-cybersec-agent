"""
Explainability module for the Lesh agent's machine learning models.
Provides tools for interpreting model decisions and anomaly detections.
"""

import logging
import numpy as np
import time
from typing import Dict, List, Any, Optional
try:
    import shap
except ImportError:
    # Create a fallback for when shap isn't available
    class ShapMock:
        def __init__(self):
            self.Explainer = self._MockExplainer
            
        class _MockExplainer:
            def __init__(self, *args, **kwargs):
                pass
                
            def shap_values(self, *args, **kwargs):
                return np.zeros((1, 10))
    
    shap = ShapMock()
    logging.warning("SHAP library not found. Using mock implementation. Install with: pip install shap")

class AnomalyExplainer:
    """Provides explanations for detected anomalies."""
    
    def __init__(self):
        """Initialize the explainer."""
        self.logger = logging.getLogger(__name__)
        self.models = {}  # Would hold trained models in a real implementation
        self.explainers = {}  # Would hold SHAP explainers for each model
        self.anomaly_store = {}  # Store of anomalies for explanation
        
        self.logger.info("Anomaly explainer initialized")
    
    def explain(self, anomaly_id: str, num_features: int = 5) -> Dict[str, Any]:
        """
        Explain why an anomaly was detected.
        
        Args:
            anomaly_id: ID of the anomaly to explain
            num_features: Number of top features to include
            
        Returns:
            Explanation dictionary with feature contributions
        """
        self.logger.info(f"Generating explanation for anomaly: {anomaly_id}")
        
        # In a real implementation, this would:
        # 1. Look up the anomaly in storage
        # 2. Use SHAP to explain the model's decision
        # 3. Format the results
        
        # For now, we'll simulate an explanation
        try:
            # Simulated explanation
            explanation = {
                "anomaly_id": anomaly_id,
                "timestamp": time.time(),
                "top_features": [
                    {"name": "connection_count", "importance": 0.85, "value": 124, "normal_range": "0-30"},
                    {"name": "packet_rate", "importance": 0.72, "value": 500, "normal_range": "0-200"},
                    {"name": "entropy", "importance": 0.64, "value": 7.8, "normal_range": "0-5.5"},
                    {"name": "unique_ports", "importance": 0.59, "value": 45, "normal_range": "1-10"},
                    {"name": "connection_duration", "importance": 0.38, "value": 0.5, "normal_range": "5-600"}
                ][:num_features],
                "explanation_text": "This connection was flagged as anomalous primarily due to an unusually high number of connections and packet rate."
            }
            
            return explanation
            
        except Exception as e:
            self.logger.error(f"Error generating explanation: {e}")
            return {
                "anomaly_id": anomaly_id,
                "error": "Failed to generate explanation",
                "reason": str(e)
            }
    
    def add_model(self, model_name: str, model) -> bool:
        """
        Add a model to the explainer.
        
        Args:
            model_name: Name of the model
            model: Trained model instance
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.models[model_name] = model
            
            # Create a SHAP explainer for the model
            # This is a simplified example - in reality would depend on model type
            self.explainers[model_name] = shap.Explainer(model)
            
            self.logger.info(f"Added model '{model_name}' to explainer")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to add model '{model_name}' to explainer: {e}")
            return False
    
    def store_anomaly(self, anomaly_id: str, data: Dict[str, Any], model_name: str) -> bool:
        """
        Store anomaly data for later explanation.
        
        Args:
            anomaly_id: Unique ID for the anomaly
            data: Data that triggered the anomaly
            model_name: Name of the model that detected the anomaly
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.anomaly_store[anomaly_id] = {
                "data": data,
                "model_name": model_name,
                "timestamp": time.time()
            }
            
            # Remove old entries if store gets too large
            if len(self.anomaly_store) > 1000:
                oldest_key = min(self.anomaly_store.keys(), 
                                key=lambda k: self.anomaly_store[k]["timestamp"])
                del self.anomaly_store[oldest_key]
                
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store anomaly {anomaly_id}: {e}")
            return False

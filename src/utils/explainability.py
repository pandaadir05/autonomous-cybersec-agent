import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from typing import Dict, List, Union, Tuple, Any, Optional
import shap
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import logging
import os

logger = logging.getLogger(__name__)


class AnomalyExplainer:
    """
    A class for explaining anomaly detection results using various techniques.
    Provides interpretability for security analysts.
    """
    
    def __init__(self, feature_names: List[str] = None):
        """
        Initialize the anomaly explainer.
        
        Args:
            feature_names: Optional list of feature names for better explanations
        """
        self.feature_names = feature_names or []
        self.surrogate_model = None
        
    def explain_by_contribution(self, features: np.ndarray, anomaly_scores: np.ndarray) -> Dict[str, Any]:
        """
        Explain which features contributed most to the anomaly score.
        
        Args:
            features: The feature vectors that were analyzed
            anomaly_scores: The anomaly scores for each sample
        
        Returns:
            Dictionary with feature contributions
        """
        if len(self.feature_names) != features.shape[1]:
            feature_names = [f"feature_{i}" for i in range(features.shape[1])]
        else:
            feature_names = self.feature_names
        
        # Train a simple surrogate model to explain the anomalies
        # Convert scores to binary classification for surrogate model
        y = (anomaly_scores > 0.7).astype(int)
        
        # Only proceed if we have both anomalies and normal samples
        if len(np.unique(y)) < 2:
            return {"error": "Need both anomalies and normal samples for explanation"}
        
        # Train a surrogate random forest classifier
        self.surrogate_model = RandomForestClassifier(n_estimators=50)
        self.surrogate_model.fit(features, y)
        
        # Get feature importances
        importances = self.surrogate_model.feature_importances_
        indices = np.argsort(importances)[::-1]
        
        # Create explanation
        explanation = {
            "feature_importance": [
                {"feature": feature_names[i], "importance": float(importances[i])}
                for i in indices
            ],
            "top_features": [feature_names[i] for i in indices[:min(5, len(indices))]]
        }
        
        return explanation
        
    def explain_with_shap(self, features: np.ndarray, model) -> Dict[str, Any]:
        """
        Use SHAP values to explain predictions.
        
        Args:
            features: Feature vectors to explain
            model: The model to explain (must be compatible with SHAP)
            
        Returns:
            Dictionary with SHAP explanations
        """
        try:
            # Use appropriate explainer based on model type
            if hasattr(model, "predict_proba"):
                explainer = shap.TreeExplainer(model)
            else:
                explainer = shap.KernelExplainer(model.predict, features[:100])
                
            shap_values = explainer.shap_values(features)
            
            # Generate summary plot
            if len(self.feature_names) == features.shape[1]:
                feature_names = self.feature_names
            else:
                feature_names = [f"feature_{i}" for i in range(features.shape[1])]
            
            # Calculate mean absolute SHAP values for each feature
            mean_shap = np.abs(shap_values).mean(axis=0)
            feature_importance = [(feature_names[i], float(mean_shap[i])) 
                                for i in range(len(feature_names))]
            
            # Sort by importance
            feature_importance.sort(key=lambda x: x[1], reverse=True)
            
            return {
                "shap_values": shap_values,
                "feature_importance": feature_importance,
                "top_features": [item[0] for item in feature_importance[:5]]
            }
        except Exception as e:
            logger.error(f"SHAP explanation error: {str(e)}")
            return {"error": f"SHAP explanation failed: {str(e)}"}
    
    def visualize_anomaly(self, features: np.ndarray, anomaly_scores: np.ndarray, 
                        save_path: str = None) -> str:
        """
        Generate visualization for anomaly detection results.
        
        Args:
            features: Feature vectors that were analyzed
            anomaly_scores: Anomaly scores for each sample
            save_path: Optional path to save the visualization
            
        Returns:
            Path to saved visualization if save_path provided, otherwise None
        """
        if len(features) == 0:
            return None
            
        # Create a color map based on anomaly scores
        colors = plt.cm.viridis(anomaly_scores)
        
        # Create visualization based on dimensionality
        if features.shape[1] > 10:
            # Use dimensionality reduction for high-dimensional data
            from sklearn.decomposition import PCA
            pca = PCA(n_components=2)
            reduced_features = pca.fit_transform(features)
            
            plt.figure(figsize=(10, 8))
            plt.scatter(reduced_features[:, 0], reduced_features[:, 1], 
                     c=anomaly_scores, cmap='viridis', alpha=0.7)
            plt.colorbar(label='Anomaly Score')
            plt.title('PCA Visualization of Anomalies')
            plt.xlabel('Principal Component 1')
            plt.ylabel('Principal Component 2')
        else:
            # Use pairplot for lower dimensional data
            # Convert to dataframe for seaborn
            df = pd.DataFrame(features)
            if len(self.feature_names) == features.shape[1]:
                df.columns = self.feature_names
            
            df['anomaly_score'] = anomaly_scores
            
            # Select a subset of features if too many
            if features.shape[1] <= 5:
                sns.pairplot(df, hue='anomaly_score', palette='viridis')
            else:
                # Find top features by variance
                variances = np.var(features, axis=0)
                top_indices = np.argsort(variances)[-5:]  # Top 5 by variance
                cols = [df.columns[i] for i in top_indices]
                cols.append('anomaly_score')
                sns.pairplot(df[cols], hue='anomaly_score', palette='viridis')
        
        if save_path:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            plt.savefig(save_path)
            plt.close()
            return save_path
        
        plt.show()
        return None

import numpy as np
import pandas as pd
import torch
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from typing import Dict, List, Tuple, Union, Optional
import joblib
import os


class FeatureExtractor:
    """
    Extract and preprocess network traffic features for the security agent.
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize the feature extractor.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Feature extraction parameters
        self.time_window = self.config.get('time_window', 60)  # seconds
        self.host_features = self.config.get('host_features', True)
        self.flow_features = self.config.get('flow_features', True)
        self.packet_features = self.config.get('packet_features', True)
        
        # Preprocessing
        self.scaler = None
        self.scaling_method = self.config.get('scaling_method', 'standard')  # 'standard', 'minmax', or None
        
        # Feature names
        self.feature_names = []
    
    def extract_features(self, raw_data: Union[pd.DataFrame, np.ndarray, Dict]) -> np.ndarray:
        """
        Extract features from raw network data.
        
        In a real implementation, this would parse pcap files or network logs.
        For this project, we'll simulate feature extraction from formatted data.
        
        Args:
            raw_data: Raw network data
            
        Returns:
            Numpy array of extracted features
        """
        # Convert dictionary to dataframe if needed
        if isinstance(raw_data, dict):
            raw_data = pd.DataFrame([raw_data])
        elif isinstance(raw_data, np.ndarray) and raw_data.ndim == 1:
            raw_data = pd.DataFrame([raw_data])
        elif isinstance(raw_data, np.ndarray) and raw_data.ndim > 1:
            raw_data = pd.DataFrame(raw_data)
        
        # Initialize features list
        features = []
        feature_names = []
        
        # Extract host-based features if available and enabled
        if self.host_features:
            if 'host_traffic_volume' in raw_data.columns:
                features.append(raw_data['host_traffic_volume'].values.reshape(-1, 1))
                feature_names.append('host_traffic_volume')
            
            if 'host_connection_count' in raw_data.columns:
                features.append(raw_data['host_connection_count'].values.reshape(-1, 1))
                feature_names.append('host_connection_count')
            
            if 'host_packet_rate' in raw_data.columns:
                features.append(raw_data['host_packet_rate'].values.reshape(-1, 1))
                feature_names.append('host_packet_rate')
        
        # Extract flow-based features if available and enabled
        if self.flow_features:
            if 'flow_duration' in raw_data.columns:
                features.append(raw_data['flow_duration'].values.reshape(-1, 1))
                feature_names.append('flow_duration')
            
            if 'flow_packet_count' in raw_data.columns:
                features.append(raw_data['flow_packet_count'].values.reshape(-1, 1))
                feature_names.append('flow_packet_count')
            
            if 'flow_bytes_per_second' in raw_data.columns:
                features.append(raw_data['flow_bytes_per_second'].values.reshape(-1, 1))
                feature_names.append('flow_bytes_per_second')
        
        # Extract packet-based features if available and enabled
        if self.packet_features:
            if 'packet_size_mean' in raw_data.columns:
                features.append(raw_data['packet_size_mean'].values.reshape(-1, 1))
                feature_names.append('packet_size_mean')
            
            if 'packet_size_std' in raw_data.columns:
                features.append(raw_data['packet_size_std'].values.reshape(-1, 1))
                feature_names.append('packet_size_std')
            
            if 'packet_interarrival_time' in raw_data.columns:
                features.append(raw_data['packet_interarrival_time'].values.reshape(-1, 1))
                feature_names.append('packet_interarrival_time')
        
        # If no predefined features were found, try to use all numeric columns
        if not features:
            numeric_data = raw_data.select_dtypes(include=[np.number])
            if not numeric_data.empty:
                features = [numeric_data[col].values.reshape(-1, 1) for col in numeric_data.columns]
                feature_names = list(numeric_data.columns)
        
        # Combine features
        if features:
            combined_features = np.hstack(features)
            self.feature_names = feature_names
            return combined_features
        else:
            raise ValueError("No valid features found in the input data")
    
    def fit_scaler(self, features: np.ndarray):
        """
        Fit the scaler to the training data.
        
        Args:
            features: Training feature data
        """
        if self.scaling_method == 'standard':
            self.scaler = StandardScaler()
        elif self.scaling_method == 'minmax':
            self.scaler = MinMaxScaler()
        else:
            return  # No scaling
            
        self.scaler.fit(features)
    
    def transform(self, features: np.ndarray) -> np.ndarray:
        """
        Apply scaling transformation to features.
        
        Args:
            features: Feature data to transform
            
        Returns:
            Transformed features
        """
        if self.scaler is not None:
            return self.scaler.transform(features)
        return features
    
    def fit_transform(self, features: np.ndarray) -> np.ndarray:
        """
        Fit the scaler and transform the features.
        
        Args:
            features: Feature data to fit and transform
            
        Returns:
            Transformed features
        """
        self.fit_scaler(features)
        return self.transform(features)
    
    def save(self, directory: str):
        """
        Save the feature extractor configuration.
        
        Args:
            directory: Directory to save configuration to
        """
        os.makedirs(directory, exist_ok=True)
        
        # Save scaler if it exists
        if self.scaler is not None:
            joblib.dump(self.scaler, os.path.join(directory, 'feature_scaler.pkl'))
        
        # Save configuration
        config = {
            'time_window': self.time_window,
            'host_features': self.host_features,
            'flow_features': self.flow_features,
            'packet_features': self.packet_features,
            'scaling_method': self.scaling_method,
            'feature_names': self.feature_names
        }
        np.save(os.path.join(directory, 'feature_extractor_config.npy'), config)
        
        print(f"Feature extractor configuration saved to {directory}")
    
    def load(self, directory: str):
        """
        Load feature extractor configuration.
        
        Args:
            directory: Directory to load configuration from
        """
        # Load scaler if it exists
        scaler_path = os.path.join(directory, 'feature_scaler.pkl')
        if os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)
        
        # Load configuration
        config_path = os.path.join(directory, 'feature_extractor_config.npy')
        if os.path.exists(config_path):
            config = np.load(config_path, allow_pickle=True).item()
            self.time_window = config.get('time_window', self.time_window)
            self.host_features = config.get('host_features', self.host_features)
            self.flow_features = config.get('flow_features', self.flow_features)
            self.packet_features = config.get('packet_features', self.packet_features)
            self.scaling_method = config.get('scaling_method', self.scaling_method)
            self.feature_names = config.get('feature_names', self.feature_names)
            
            print(f"Feature extractor configuration loaded from {directory}")
        else:
            print(f"No configuration found at {directory}")
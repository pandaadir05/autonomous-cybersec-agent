import os
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import LocalOutlierFactor
from sklearn.ensemble import IsolationForest as SklearnIForest
from sklearn.cluster import DBSCAN
from sklearn.svm import OneClassSVM
import joblib
from typing import Dict, List, Tuple, Any, Union, Optional
import random
import logging

logger = logging.getLogger(__name__)


class AutoEncoder(nn.Module):
    """
    Autoencoder neural network for anomaly detection.
    Compresses input data into a lower-dimensional latent space and then reconstructs it.
    High reconstruction error indicates potential anomalies.
    """
    
    def __init__(self, input_dim, encoding_dims=[64, 32, 16]):
        """
        Initialize the autoencoder model.
        
        Args:
            input_dim: Dimension of input features
            encoding_dims: Dimensions of encoder layers
        """
        super(AutoEncoder, self).__init__()
        
        # Build encoder layers
        encoder_layers = []
        in_features = input_dim
        
        for dim in encoding_dims:
            encoder_layers.append(nn.Linear(in_features, dim))
            encoder_layers.append(nn.ReLU())
            in_features = dim
        
        self.encoder = nn.Sequential(*encoder_layers)
        
        # Build decoder layers (reverse of encoder)
        decoder_layers = []
        encoding_dims.reverse()
        in_features = encoding_dims[0]
        
        for i, dim in enumerate(encoding_dims[1:]):
            decoder_layers.append(nn.Linear(in_features, dim))
            decoder_layers.append(nn.ReLU())
            in_features = dim
        
        # Final reconstruction layer
        decoder_layers.append(nn.Linear(in_features, input_dim))
        
        self.decoder = nn.Sequential(*decoder_layers)
    
    def forward(self, x):
        """Forward pass through the autoencoder."""
        encoded = self.encoder(x)
        decoded = self.decoder(encoded)
        return decoded
    
    def encode(self, x):
        """Encode input to latent representation."""
        return self.encoder(x)


class IsolationForest:
    """
    Simple implementation of Isolation Forest algorithm.
    Used as an alternative anomaly detection method.
    """
    
    def __init__(self, n_estimators=100, max_samples='auto', contamination=0.1):
        """
        Initialize Isolation Forest.
        
        Args:
            n_estimators: Number of isolation trees
            max_samples: Number of samples to draw for each tree
            contamination: Expected proportion of anomalies
        """
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.trees = []
        self.threshold = None
    
    def fit(self, X):
        """
        Fit isolation forest to data.
        
        Args:
            X: Training data
        """
        # Use scikit-learn if available
        try:
            from sklearn.ensemble import IsolationForest as SKIsolationForest
            self.model = SKIsolationForest(
                n_estimators=self.n_estimators,
                max_samples=self.max_samples,
                contamination=self.contamination,
                random_state=42
            )
            self.model.fit(X)
        except ImportError:
            # Simple implementation (not as efficient)
            # Just store data and use distance-based anomaly scoring
            self.X_train = X
    
    def score_samples(self, X):
        """
        Score samples (higher score = more anomalous).
        
        Args:
            X: Data to score
            
        Returns:
            Anomaly scores
        """
        try:
            # Use scikit-learn model if available
            return -self.model.score_samples(X)
        except AttributeError:
            # Simple distance-based scoring
            from sklearn.neighbors import NearestNeighbors
            nbrs = NearestNeighbors(n_neighbors=5).fit(self.X_train)
            distances, _ = nbrs.kneighbors(X)
            return np.mean(distances, axis=1)
    
    def predict(self, X):
        """
        Predict if samples are anomalies.
        
        Args:
            X: Data to predict
            
        Returns:
            1 for anomalies, -1 for normal samples
        """
        scores = self.score_samples(X)
        if self.threshold is None:
            # Set threshold based on contamination
            self.threshold = np.percentile(scores, 100 * (1 - self.contamination))
        return np.where(scores > self.threshold, 1, -1)


class AnomalyDetector:
    """
    Multi-method anomaly detector that combines multiple techniques for robust detection.
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize the anomaly detector with multiple detection methods.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Available detection methods
        self.supported_methods = ['autoencoder', 'isolation_forest', 'lof', 'dbscan', 'ocsvm']
        self.methods = self.config.get('methods', ['autoencoder', 'isolation_forest'])
        
        # Validate methods
        self.methods = [m for m in self.methods if m in self.supported_methods]
        if not self.methods:
            self.methods = ['autoencoder', 'isolation_forest']
            
        # Ensemble weights for combining methods
        default_weights = [1.0] * len(self.methods)
        self.ensemble_weights = self.config.get('ensemble_weights', default_weights)
        
        # Ensure weights match the number of methods
        if len(self.ensemble_weights) != len(self.methods):
            self.ensemble_weights = [1.0] * len(self.methods)
        
        # Detection threshold (score above this is considered anomalous)
        self.detection_threshold = self.config.get('detection_threshold', 0.7)
        
        # Model parameters
        self.input_dim = None
        self.autoencoder = None
        self.optimizer = None
        self.scaler = None
        
        # Anomaly detection models
        self.isolation_forest = None
        self.lof = None
        self.dbscan = None
        self.ocsvm = None
        
        # Reconstruction error threshold for autoencoder
        self.reconstruction_threshold = 1.0
        
        # Store a history of anomaly scores for adaptive thresholding
        self.anomaly_history = []
        
        # Initialize models based on methods
        if 'isolation_forest' in self.methods:
            n_estimators = self.config.get('n_estimators', 100)
            contamination = self.config.get('contamination', 0.1)
            random_state = self.config.get('random_state', 42)
            self.isolation_forest = SklearnIForest(
                n_estimators=n_estimators,
                contamination=contamination,
                random_state=random_state
            )
            
        if 'lof' in self.methods:
            n_neighbors = self.config.get('n_neighbors', 20)
            contamination = self.config.get('contamination', 0.1)
            self.lof = LocalOutlierFactor(
                n_neighbors=n_neighbors,
                contamination=contamination,
                novelty=True
            )
            
        if 'dbscan' in self.methods:
            eps = self.config.get('dbscan_eps', 0.5)
            min_samples = self.config.get('dbscan_min_samples', 5)
            self.dbscan = DBSCAN(
                eps=eps,
                min_samples=min_samples,
                n_jobs=-1
            )
            self.dbscan_training_data = None
        
        if 'ocsvm' in self.methods:
            nu = self.config.get('ocsvm_nu', 0.1)
            kernel = self.config.get('ocsvm_kernel', 'rbf')
            gamma = self.config.get('ocsvm_gamma', 'scale')
            self.ocsvm = OneClassSVM(
                nu=nu,
                kernel=kernel,
                gamma=gamma
            )

    def fit(self, data: np.ndarray):
        """
        Train all enabled anomaly detection methods on the given data.
        
        Args:
            data: Training data (n_samples, n_features)
        """
        # Store input dimension
        self.input_dim = data.shape[1]
        
        # Scale data if not already scaled
        scaled_data = data
        if self.config.get('scale_input', True):
            self.scaler = StandardScaler()
            scaled_data = self.scaler.fit_transform(data)
            
        logger.info(f"Training anomaly detection models on {data.shape[0]} samples with {data.shape[1]} features")
        
        # Train autoencoder if enabled
        if 'autoencoder' in self.methods:
            # Convert data to tensor
            tensor_data = torch.FloatTensor(scaled_data).to(torch.device("cuda:0" if torch.cuda.is_available() else "cpu"))
            dataset = TensorDataset(tensor_data, tensor_data)
            dataloader = DataLoader(dataset, batch_size=self.config.get('batch_size', 32), shuffle=True)
            
            self.autoencoder = AutoEncoder(self.input_dim, self.config.get('encoding_dims', [64, 32, 16]))
            self.optimizer = optim.Adam(self.autoencoder.parameters(), lr=self.config.get('learning_rate', 0.001))
            criterion = nn.MSELoss()
            
            self.autoencoder.train()
            for epoch in range(self.config.get('epochs', 50)):
                running_loss = 0.0
                for inputs, _ in dataloader:
                    self.optimizer.zero_grad()
                    outputs = self.autoencoder(inputs)
                    loss = criterion(outputs, inputs)
                    loss.backward()
                    self.optimizer.step()
                    running_loss += loss.item()
                
                if (epoch + 1) % 10 == 0:
                    logger.info(f"Epoch {epoch+1}, Loss: {running_loss/len(dataloader):.6f}")
            
            self.autoencoder.eval()
            with torch.no_grad():
                reconstructions = self.autoencoder(tensor_data)
                reconstruction_error = torch.mean(torch.square(reconstructions - tensor_data), dim=1)
                self.reconstruction_threshold = torch.quantile(reconstruction_error, self.config.get('reconstruction_quantile', 0.95)).item()
        
        # Train isolation forest
        if 'isolation_forest' in self.methods:
            logger.info("Training Isolation Forest model")
            self.isolation_forest.fit(scaled_data)
            
        # Train LOF
        if 'lof' in self.methods:
            logger.info("Training Local Outlier Factor model")
            self.lof.fit(scaled_data)
            
        # Train DBSCAN (or store training data for reference)
        if 'dbscan' in self.methods:
            logger.info("Fitting DBSCAN model")
            self.dbscan.fit(scaled_data)
            self.dbscan_training_data = scaled_data
            
        # Train One-Class SVM
        if 'ocsvm' in self.methods:
            logger.info("Training One-Class SVM model")
            self.ocsvm.fit(scaled_data)
            
        logger.info("Anomaly detection models training completed")

    def detect(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Detect anomalies using enabled detection methods.
        
        Args:
            features: Feature vectors to analyze (n_samples, n_features)
            
        Returns:
            Dict containing anomaly scores and detection results
        """
        # Scale features if scaler exists
        if self.scaler is not None:
            features = self.scaler.transform(features)
        
        results = {}
        
        # Autoencoder-based detection
        if 'autoencoder' in self.methods and self.autoencoder is not None:
            features_tensor = torch.FloatTensor(features).to(torch.device("cuda:0" if torch.cuda.is_available() else "cpu"))
            self.autoencoder.eval()
            with torch.no_grad():
                reconstructions = self.autoencoder(features_tensor)
                reconstruction_error = torch.mean(torch.square(reconstructions - features_tensor), dim=1)
                autoencoder_score = (reconstruction_error / self.reconstruction_threshold).clamp(0, 1).cpu().numpy()
                results['autoencoder_score'] = autoencoder_score
        
        # Isolation forest-based detection
        if 'isolation_forest' in self.methods:
            iforest_scores = -self.isolation_forest.score_samples(features)
            max_score = self.config.get('max_iforest_score', 0.8)
            iforest_score = np.minimum(iforest_scores / max_score, 1)
            results['iforest_score'] = iforest_score
        
        # LOF-based detection
        if 'lof' in self.methods:
            lof_scores = -self.lof.score_samples(features)
            max_lof_score = self.config.get('max_lof_score', 3.0)
            lof_score = np.minimum(lof_scores / max_lof_score, 1)
            results['lof_score'] = lof_score
        
        # DBSCAN-based detection
        if 'dbscan' in self.methods:
            labels = self.dbscan.fit_predict(features)
            from sklearn.metrics.pairwise import euclidean_distances
            train_labels = self.dbscan.labels_
            cluster_centers = {}
            for label in np.unique(train_labels):
                if label != -1:
                    mask = train_labels == label
                    cluster_centers[label] = np.mean(self.dbscan_training_data[mask], axis=0)
            dbscan_scores = np.ones(features.shape[0])
            if cluster_centers:
                centers = np.array(list(cluster_centers.values()))
                distances = euclidean_distances(features, centers)
                min_distances = np.min(distances, axis=1)
                max_dist = self.config.get('max_dbscan_distance', 5.0)
                dbscan_scores = np.minimum(min_distances / max_dist, 1)
            dbscan_scores[labels == -1] = 1.0
            results['dbscan_score'] = dbscan_scores
        
        # One-Class SVM detection
        if 'ocsvm' in self.methods:
            decision_scores = self.ocsvm.decision_function(features)
            max_score = self.config.get('max_ocsvm_score', 1.0)
            ocsvm_scores = np.minimum(1 - (decision_scores / max_score), 1)
            results['ocsvm_score'] = ocsvm_scores
        
        # Combine scores using ensemble weights
        anomaly_score = 0
        weight_sum = 0
        
        for method, weight in zip(self.methods, self.ensemble_weights):
            if method == 'autoencoder' and 'autoencoder_score' in results:
                anomaly_score += weight * results['autoencoder_score']
                weight_sum += weight
            elif method == 'isolation_forest' and 'iforest_score' in results:
                anomaly_score += weight * results['iforest_score']
                weight_sum += weight
            elif method == 'lof' and 'lof_score' in results:
                anomaly_score += weight * results['lof_score']
                weight_sum += weight
            elif method == 'dbscan' and 'dbscan_score' in results:
                anomaly_score += weight * results['dbscan_score']
                weight_sum += weight
            elif method == 'ocsvm' and 'ocsvm_score' in results:
                anomaly_score += weight * results['ocsvm_score']
                weight_sum += weight
        
        if weight_sum > 0:
            anomaly_score /= weight_sum
        
        is_anomaly = anomaly_score > self.detection_threshold
        
        self.anomaly_history.append(float(np.mean(anomaly_score)))
        if len(self.anomaly_history) > 100:
            self.anomaly_history.pop(0)
        
        return {
            'anomaly_score': anomaly_score,
            'is_anomaly': is_anomaly,
            'anomaly_probability': float(anomaly_score.mean()),
            'reconstruction_error': results.get('autoencoder_score', None),
            'isolation_forest_score': results.get('iforest_score', None),
            'lof_score': results.get('lof_score', None),
            'dbscan_score': results.get('dbscan_score', None),
            'ocsvm_score': results.get('ocsvm_score', None),
            'detection_threshold': self.detection_threshold
        }

    def save(self, directory: str):
        """
        Save the anomaly detector configuration and models.
        
        Args:
            directory: Directory to save models to
        """
        os.makedirs(directory, exist_ok=True)
        
        config = {
            'methods': self.methods,
            'ensemble_weights': self.ensemble_weights,
            'detection_threshold': self.detection_threshold,
            'input_dim': self.input_dim,
            'supported_methods': self.supported_methods
        }
        
        np.save(os.path.join(directory, 'anomaly_detector_config.npy'), config)
        
        if self.scaler is not None:
            joblib.dump(self.scaler, os.path.join(directory, 'anomaly_detector_scaler.pkl'))
        
        if self.autoencoder is not None:
            torch.save({
                'model_state_dict': self.autoencoder.state_dict(),
                'optimizer_state_dict': self.optimizer.state_dict() if self.optimizer else None,
                'reconstruction_threshold': self.reconstruction_threshold
            }, os.path.join(directory, 'autoencoder_model.pth'))
        
        if self.isolation_forest is not None:
            joblib.dump(self.isolation_forest, os.path.join(directory, 'isolation_forest_model.pkl'))
        
        if self.lof is not None:
            joblib.dump(self.lof, os.path.join(directory, 'lof_model.pkl'))
        
        if self.dbscan is not None:
            joblib.dump(self.dbscan, os.path.join(directory, 'dbscan_model.pkl'))
            if self.dbscan_training_data is not None:
                np.save(os.path.join(directory, 'dbscan_training_data.npy'), self.dbscan_training_data)
        
        if self.ocsvm is not None:
            joblib.dump(self.ocsvm, os.path.join(directory, 'ocsvm_model.pkl'))
        
        logger.info(f"Anomaly detector models and configuration saved to {directory}")

    def load(self, directory: str):
        """
        Load anomaly detector models and configuration.
        
        Args:
            directory: Directory to load from
        """
        config_path = os.path.join(directory, 'anomaly_detector_config.npy')
        if os.path.exists(config_path):
            config = np.load(config_path, allow_pickle=True).item()
            self.methods = config.get('methods', self.methods)
            self.ensemble_weights = config.get('ensemble_weights', self.ensemble_weights)
            self.detection_threshold = config.get('detection_threshold', self.detection_threshold)
            self.input_dim = config.get('input_dim')
        
        scaler_path = os.path.join(directory, 'anomaly_detector_scaler.pkl')
        if os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)
        
        if 'autoencoder' in self.methods:
            autoencoder_path = os.path.join(directory, 'autoencoder_model.pth')
            if os.path.exists(autoencoder_path):
                checkpoint = torch.load(autoencoder_path, map_location=torch.device("cuda:0" if torch.cuda.is_available() else "cpu"))
                self.autoencoder = AutoEncoder(self.input_dim, self.config.get('encoding_dims', [64, 32, 16]))
                self.autoencoder.load_state_dict(checkpoint['model_state_dict'])
                if checkpoint.get('optimizer_state_dict'):
                    self.optimizer = optim.Adam(self.autoencoder.parameters(), lr=self.config.get('learning_rate', 0.001))
                    self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
                self.reconstruction_threshold = checkpoint.get('reconstruction_threshold', 1.0)
        
        if 'isolation_forest' in self.methods:
            iforest_path = os.path.join(directory, 'isolation_forest_model.pkl')
            if os.path.exists(iforest_path):
                self.isolation_forest = joblib.load(iforest_path)
        
        if 'lof' in self.methods:
            lof_path = os.path.join(directory, 'lof_model.pkl')
            if os.path.exists(lof_path):
                self.lof = joblib.load(lof_path)
        
        if 'dbscan' in self.methods:
            dbscan_path = os.path.join(directory, 'dbscan_model.pkl')
            if os.path.exists(dbscan_path):
                self.dbscan = joblib.load(dbscan_path)
            dbscan_training_data_path = os.path.join(directory, 'dbscan_training_data.npy')
            if os.path.exists(dbscan_training_data_path):
                self.dbscan_training_data = np.load(dbscan_training_data_path)
        
        if 'ocsvm' in self.methods:
            ocsvm_path = os.path.join(directory, 'ocsvm_model.pkl')
            if os.path.exists(ocsvm_path):
                self.ocsvm = joblib.load(ocsvm_path)
        
        logger.info(f"Anomaly detector models and configuration loaded from {directory}")
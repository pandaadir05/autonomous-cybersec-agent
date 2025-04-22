#!/usr/bin/env python3
"""
Script to train and save machine learning models for the Autonomous Cybersecurity Agent.
"""

import os
import argparse
import logging
import pandas as pd
import numpy as np
from pathlib import Path

from src.models.anomaly_detector import AnomalyDetector
from config.ml_config import MLConfig

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger("model_training")

def generate_synthetic_data(num_samples=1000, anomaly_ratio=0.1):
    """
    Generate synthetic data for model training.
    
    Args:
        num_samples: Number of samples to generate
        anomaly_ratio: Proportion of anomalies in the dataset
        
    Returns:
        Pandas DataFrame with synthetic data
    """
    # Number of normal and anomalous samples
    n_normal = int(num_samples * (1 - anomaly_ratio))
    n_anomaly = num_samples - n_normal
    
    # Generate normal traffic
    normal_data = {
        "bytes_in": np.random.normal(5000, 1000, n_normal),
        "bytes_out": np.random.normal(3000, 800, n_normal),
        "packets_in": np.random.normal(50, 10, n_normal),
        "packets_out": np.random.normal(30, 8, n_normal),
        "avg_packet_size": np.random.normal(100, 20, n_normal),
        "connection_duration": np.random.normal(5, 2, n_normal),
        "port": np.random.choice([80, 443, 22, 25, 53], n_normal),
        "protocol": np.random.choice([6, 17], n_normal),  # TCP and UDP
        "src_entropy": np.random.normal(4, 1, n_normal),
        "dst_entropy": np.random.normal(4, 1, n_normal),
        "is_anomaly": [0] * n_normal
    }
    
    # Generate anomalous traffic
    anomaly_data = {
        "bytes_in": np.random.normal(15000, 5000, n_anomaly),
        "bytes_out": np.random.normal(10000, 3000, n_anomaly),
        "packets_in": np.random.normal(150, 50, n_anomaly),
        "packets_out": np.random.normal(100, 40, n_anomaly),
        "avg_packet_size": np.random.normal(200, 50, n_anomaly),
        "connection_duration": np.random.normal(1, 0.5, n_anomaly),
        "port": np.random.choice([4444, 5555, 6666, 7777, 8888], n_anomaly),
        "protocol": np.random.choice([6, 17, 1], n_anomaly),  # TCP, UDP, ICMP
        "src_entropy": np.random.normal(7, 1, n_anomaly),
        "dst_entropy": np.random.normal(2, 0.5, n_anomaly),
        "is_anomaly": [1] * n_anomaly
    }
    
    # Combine and shuffle data
    df_normal = pd.DataFrame(normal_data)
    df_anomaly = pd.DataFrame(anomaly_data)
    df = pd.concat([df_normal, df_anomaly], ignore_index=True)
    df = df.sample(frac=1).reset_index(drop=True)  # Shuffle
    
    return df

def train_anomaly_detector(data, ml_config, save_path):
    """
    Train and save the anomaly detection model.
    
    Args:
        data: Training data as DataFrame
        ml_config: ML configuration manager
        save_path: Path to save the trained model
    """
    logger.info("Training anomaly detection model...")
    
    # Get model configuration
    model_config = ml_config.get_model_config("anomaly_detector")
    feature_columns = model_config.get("features", [])
    
    if not feature_columns:
        feature_columns = [col for col in data.columns if col != "is_anomaly"]
    
    # Initialize the model
    model = AnomalyDetector(model_config)
    
    # Train the model
    train_metrics = model.train(data, feature_columns)
    
    logger.info(f"Training completed with metrics: {train_metrics}")
    
    # Save the model
    model_path = os.path.join(save_path, model_config.get("file", "anomaly_detector.pkl"))
    if model.save(model_path):
        logger.info(f"Model saved to {model_path}")
    else:
        logger.error("Failed to save model")
    
    # Test the model
    test_detection(model, data, feature_columns)

def test_detection(model, data, feature_columns):
    """
    Test the trained model with some sample data.
    
    Args:
        model: Trained model
        data: Test data as DataFrame
        feature_columns: Features to use for testing
    """
    logger.info("Testing model with sample data...")
    
    # Select features
    features = data[feature_columns].values
    
    # Select some samples
    normal_sample = features[data['is_anomaly'] == 0][0:1]
    anomaly_sample = features[data['is_anomaly'] == 1][0:1]
    
    # Run detection on samples
    normal_result = model.detect(normal_sample)
    anomaly_result = model.detect(anomaly_sample)
    
    logger.info(f"Normal sample detection: {normal_result}")
    logger.info(f"Anomaly sample detection: {anomaly_result}")

def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Train machine learning models")
    parser.add_argument("--data", help="Path to training data file (CSV)")
    parser.add_argument("--samples", type=int, default=10000, help="Number of synthetic samples if no data file")
    parser.add_argument("--anomaly-ratio", type=float, default=0.1, help="Ratio of anomalies in synthetic data")
    args = parser.parse_args()
    
    # Set up ML config
    ml_config = MLConfig()
    
    # Create models directory if it doesn't exist
    models_dir = ml_config.models_dir
    models_dir.mkdir(exist_ok=True, parents=True)
    
    # Load or generate data
    if args.data and os.path.exists(args.data):
        logger.info(f"Loading data from {args.data}")
        data = pd.read_csv(args.data)
    else:
        logger.info(f"Generating synthetic data with {args.samples} samples")
        data = generate_synthetic_data(args.samples, args.anomaly_ratio)
    
    # Train models
    train_anomaly_detector(data, ml_config, models_dir)
    
    logger.info("Model training complete!")

if __name__ == "__main__":
    main()

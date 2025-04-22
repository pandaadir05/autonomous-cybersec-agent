import os
import numpy as np
import torch
import mlflow
from tqdm import tqdm
import wandb
from datetime import datetime

from src.environments.network_env import NetworkSecurityEnv
from src.models.dqn_agent import DQNAgent
from src.models.anomaly_detector import AnomalyDetector
from src.utils.data_preprocessor import FeatureExtractor
from config import config

def train():
    """Main training loop for the autonomous cybersecurity agent."""
    
    # Initialize MLflow
    mlflow.set_experiment("cybersec_agent_training")
    
    # Initialize W&B
    wandb.init(project="autonomous-cybersec-agent")
    
    # Create environment
    env = NetworkSecurityEnv(config=config.env_config)
    
    # Initialize feature extractor
    feature_extractor = FeatureExtractor(config=config.feature_config)
    
    # Initialize anomaly detector
    anomaly_detector = AnomalyDetector(config=config.anomaly_config)
    
    # Initialize agent
    agent = DQNAgent(
        state_size=config.agent_config['state_size'],
        action_size=config.agent_config['action_size'],
        config=config.agent_config
    )
    
    # Training loop
    scores = []
    recent_scores = []
    best_avg_score = float('-inf')
    
    for episode in tqdm(range(config.training_config['num_episodes']), desc="Training"):
        state, _ = env.reset()
        score = 0
        
        # Episode loop
        for step in range(config.training_config['max_steps']):
            # Extract features
            features = feature_extractor.extract_features(state)
            
            # Get anomaly scores
            anomaly_info = anomaly_detector.detect(features)
            
            # Combine state with anomaly information
            enhanced_state = np.concatenate([state, [anomaly_info['anomaly_probability']]])
            
            # Select action
            action = agent.act(enhanced_state)
            
            # Take action
            next_state, reward, terminated, truncated, info = env.step(action)
            
            # Store experience
            agent.step(enhanced_state, action, reward, 
                      np.concatenate([next_state, [anomaly_info['anomaly_probability']]]), 
                      terminated)
            
            # Update state and score
            state = next_state
            score += reward
            
            if terminated or truncated:
                break
        
        # Track scores
        scores.append(score)
        recent_scores.append(score)
        if len(recent_scores) > 100:
            recent_scores.pop(0)
        avg_score = np.mean(recent_scores)
        
        # Logging
        if episode % config.training_config['log_frequency'] == 0:
            metrics = {
                'episode': episode,
                'score': score,
                'average_score': avg_score,
                'epsilon': agent.epsilon,
                'total_damage': info['total_damage'],
                'successful_mitigations': info['successful_mitigations'],
                'false_positives': info['false_positives']
            }
            wandb.log(metrics)
            mlflow.log_metrics(metrics)
        
        # Save best models
        if avg_score > best_avg_score:
            best_avg_score = avg_score
            agent.save(os.path.join(config.paths['models'], 'best_agent.pth'))
            anomaly_detector.save(os.path.join(config.paths['models'], 'best_anomaly_detector'))
    
    # Save final models
    agent.save(os.path.join(config.paths['models'], 'final_agent.pth'))
    anomaly_detector.save(os.path.join(config.paths['models'], 'final_anomaly_detector'))
    
    # Close wandb run
    wandb.finish()

if __name__ == "__main__":
    train()

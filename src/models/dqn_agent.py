import numpy as np
import random
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from collections import deque, namedtuple
import os
from typing import Dict, List, Tuple, Any

class QNetwork(nn.Module):
    """Neural network for approximating Q-values."""
    
    def __init__(self, state_size: int, action_size: int, hidden_layers: List[int] = [128, 64]):
        """
        Initialize the Q-Network.
        
        Args:
            state_size: Dimension of each state
            action_size: Dimension of each action
            hidden_layers: List with the size of each hidden layer
        """
        super(QNetwork, self).__init__()
        
        # Create network architecture
        layers = []
        # Input layer
        layers.append(nn.Linear(state_size, hidden_layers[0]))
        layers.append(nn.ReLU())
        
        # Hidden layers
        for i in range(len(hidden_layers) - 1):
            layers.append(nn.Linear(hidden_layers[i], hidden_layers[i + 1]))
            layers.append(nn.ReLU())
        
        # Output layer
        layers.append(nn.Linear(hidden_layers[-1], action_size))
        
        # Combine all layers
        self.network = nn.Sequential(*layers)
    
    def forward(self, state):
        """Forward pass through the network."""
        return self.network(state)


class ReplayBuffer:
    """Fixed-size buffer to store experience tuples."""
    
    def __init__(self, buffer_size: int, batch_size: int, device: torch.device):
        """
        Initialize a ReplayBuffer object.
        
        Args:
            buffer_size: Maximum size of buffer
            batch_size: Size of each training batch
            device: Device (cpu/cuda) to store tensors
        """
        self.memory = deque(maxlen=buffer_size)
        self.batch_size = batch_size
        self.experience = namedtuple("Experience", field_names=["state", "action", "reward", "next_state", "done"])
        self.device = device
    
    def add(self, state, action, reward, next_state, done):
        """Add a new experience to memory."""
        e = self.experience(state, action, reward, next_state, done)
        self.memory.append(e)
    
    def sample(self):
        """Randomly sample a batch of experiences from memory."""
        experiences = random.sample(self.memory, k=self.batch_size)
        
        states = torch.from_numpy(np.vstack([e.state for e in experiences if e is not None])).float().to(self.device)
        actions = torch.from_numpy(np.vstack([e.action for e in experiences if e is not None])).long().to(self.device)
        rewards = torch.from_numpy(np.vstack([e.reward for e in experiences if e is not None])).float().to(self.device)
        next_states = torch.from_numpy(np.vstack([e.next_state for e in experiences if e is not None])).float().to(self.device)
        dones = torch.from_numpy(np.vstack([e.done for e in experiences if e is not None]).astype(np.uint8)).float().to(self.device)
  
        return (states, actions, rewards, next_states, dones)
    
    def __len__(self):
        """Return the current size of internal memory."""
        return len(self.memory)


class DQNAgent:
    """Agent implementing Deep Q-Learning to make network security decisions."""
    
    def __init__(self, state_size: int, action_size: int, config: Dict = None):
        """
        Initialize a DQN Agent.
        
        Args:
            state_size: Dimension of each state
            action_size: Dimension of each action
            config: Configuration dictionary
        """
        self.config = config or {}
        
        # Environment parameters
        self.state_size = state_size
        self.action_size = action_size
        
        # Set up device
        self.device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        
        # Q-Network parameters
        self.hidden_layers = self.config.get('hidden_layers', [128, 64])
        self.lr = self.config.get('learning_rate', 5e-4)
        
        # Create Q-Networks (local and target)
        self.qnetwork_local = QNetwork(state_size, action_size, self.hidden_layers).to(self.device)
        self.qnetwork_target = QNetwork(state_size, action_size, self.hidden_layers).to(self.device)
        self.optimizer = optim.Adam(self.qnetwork_local.parameters(), lr=self.lr)
        
        # Replay memory
        self.batch_size = self.config.get('batch_size', 64)
        self.buffer_size = self.config.get('buffer_size', 10000)
        self.memory = ReplayBuffer(self.buffer_size, self.batch_size, self.device)
        
        # Learning parameters
        self.gamma = self.config.get('gamma', 0.99)        # discount factor
        self.tau = self.config.get('tau', 1e-3)           # for soft update of target network
        self.update_every = self.config.get('update_every', 4)  # how often to update the network
        
        # Exploration parameters
        self.epsilon = self.config.get('epsilon_start', 1.0)
        self.epsilon_min = self.config.get('epsilon_min', 0.01)
        self.epsilon_decay = self.config.get('epsilon_decay', 0.995)
        
        # Initialize time step (for updating every self.update_every steps)
        self.t_step = 0
    
    def step(self, state, action, reward, next_state, done):
        """
        Save experience in replay memory and use random sample from buffer to learn.
        
        Args:
            state: Current state
            action: Performed action
            reward: Received reward
            next_state: Next state
            done: Whether the episode is done
        """
        # Save experience in replay memory
        self.memory.add(state, action, reward, next_state, done)
        
        # Learn every self.update_every time steps
        self.t_step = (self.t_step + 1) % self.update_every
        if self.t_step == 0 and len(self.memory) > self.batch_size:
            experiences = self.memory.sample()
            self._learn(experiences)
    
    def act(self, state, eval_mode=False):
        """
        Return action for given state as per current policy.
        
        Args:
            state: Current state
            eval_mode: Whether to use evaluation mode (no exploration)
            
        Returns:
            Action to take
        """
        # Convert state to torch tensor
        state = torch.from_numpy(state).float().unsqueeze(0).to(self.device)
        
        # Set evaluation mode
        self.qnetwork_local.eval()
        
        with torch.no_grad():
            action_values = self.qnetwork_local(state)
        
        # Set back to training mode
        self.qnetwork_local.train()
        
        # Epsilon-greedy action selection
        if not eval_mode and random.random() < self.epsilon:
            return random.choice(np.arange(self.action_size))
        else:
            return np.argmax(action_values.cpu().data.numpy())
    
    def _learn(self, experiences):
        """
        Update value parameters using batch of experience tuples.
        
        Args:
            experiences: Tuple of (state, action, reward, next_state, done)
        """
        states, actions, rewards, next_states, dones = experiences
        
        # Get max predicted Q values for next states from target model
        Q_targets_next = self.qnetwork_target(next_states).detach().max(1)[0].unsqueeze(1)
        
        # Compute Q targets for current states
        Q_targets = rewards + (self.gamma * Q_targets_next * (1 - dones))
        
        # Get expected Q values from local model
        Q_expected = self.qnetwork_local(states).gather(1, actions)
        
        # Compute loss
        loss = F.mse_loss(Q_expected, Q_targets)
        
        # Minimize the loss
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
        
        # Update target network
        self._soft_update()
        
        # Update epsilon
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
    
    def _soft_update(self):
        """Soft update target network parameters."""
        for target_param, local_param in zip(self.qnetwork_target.parameters(), self.qnetwork_local.parameters()):
            target_param.data.copy_(self.tau * local_param.data + (1.0 - self.tau) * target_param.data)
    
    def save(self, path):
        """
        Save the agent's model and parameters.
        
        Args:
            path: Path to save the model
        """
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        torch.save({
            'qnetwork_local_state_dict': self.qnetwork_local.state_dict(),
            'qnetwork_target_state_dict': self.qnetwork_target.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'epsilon': self.epsilon,
            'config': self.config
        }, path)
        
        print(f"Model saved to {path}")
    
    def load(self, path):
        """
        Load the agent's model and parameters.
        
        Args:
            path: Path to load the model from
        """
        if os.path.isfile(path):
            checkpoint = torch.load(path, map_location=self.device)
            self.qnetwork_local.load_state_dict(checkpoint['qnetwork_local_state_dict'])
            self.qnetwork_target.load_state_dict(checkpoint['qnetwork_target_state_dict'])
            self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
            self.epsilon = checkpoint['epsilon']
            
            print(f"Model loaded from {path}")
        else:
            print(f"No model found at {path}")
import os
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from typing import Dict, List, Tuple, Optional, Any
import json
from datetime import datetime, timedelta
import matplotlib.dates as mdates

class NetworkVisualizer:
    """
    Visualization tools for network security data and agent behavior.
    """
    
    def __init__(self, output_dir: str = 'visualizations'):
        """
        Initialize the visualizer.
        
        Args:
            output_dir: Directory to save visualizations
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        
        # Set style
        sns.set_theme(style="darkgrid")
        plt.rcParams['figure.figsize'] = (12, 8)
    
    def plot_training_history(self, metrics_file: str, save: bool = True):
        """
        Plot training metrics history.
        
        Args:
            metrics_file: Path to metrics CSV file
            save: Whether to save the plot
        """
        try:
            # Load metrics
            df = pd.read_csv(metrics_file)
            
            # Plot rewards
            fig, axs = plt.subplots(2, 2, figsize=(15, 10))
            
            # Plot episode rewards
            axs[0, 0].plot(df['step'], df['score'], 'b-')
            axs[0, 0].plot(df['step'], df['average_score'], 'r-', linewidth=2)
            axs[0, 0].set_title('Agent Rewards')
            axs[0, 0].set_xlabel('Episode')
            axs[0, 0].set_ylabel('Reward')
            axs[0, 0].legend(['Episode Reward', 'Moving Average'])
            
            # Plot epsilon decay
            if 'epsilon' in df.columns:
                axs[0, 1].plot(df['step'], df['epsilon'], 'g-')
                axs[0, 1].set_title('Exploration Rate (Epsilon)')
                axs[0, 1].set_xlabel('Episode')
                axs[0, 1].set_ylabel('Epsilon')
            
            # Plot total damage
            if 'total_damage' in df.columns:
                axs[1, 0].plot(df['step'], df['total_damage'], 'r-')
                axs[1, 0].set_title('Total Damage')
                axs[1, 0].set_xlabel('Episode')
                axs[1, 0].set_ylabel('Cumulative Damage')
            
            # Plot mitigations and false positives
            if 'successful_mitigations' in df.columns and 'false_positives' in df.columns:
                axs[1, 1].plot(df['step'], df['successful_mitigations'], 'g-')
                axs[1, 1].plot(df['step'], df['false_positives'], 'r-')
                axs[1, 1].set_title('Agent Performance')
                axs[1, 1].set_xlabel('Episode')
                axs[1, 1].set_ylabel('Count')
                axs[1, 1].legend(['Successful Mitigations', 'False Positives'])
            
            plt.tight_layout()
            
            if save:
                plt.savefig(os.path.join(self.output_dir, 'training_history.png'), dpi=300)
                print(f"Training history plot saved to {self.output_dir}/training_history.png")
            
            plt.show()
            
        except Exception as e:
            print(f"Error plotting training history: {e}")
    
    def plot_network_state(self, hosts_status: List[int], 
                          blocked_hosts: List[int], 
                          isolated_hosts: List[int],
                          active_attacks: List[Dict] = None,
                          save: bool = True):
        """
        Visualize the current state of the network.
        
        Args:
            hosts_status: Status of each host (0: normal, 1: attacked, 2: compromised)
            blocked_hosts: List of blocked host IDs
            isolated_hosts: List of isolated host IDs
            active_attacks: List of active attacks
            save: Whether to save the visualization
        """
        # Create figure
        fig, ax = plt.subplots(figsize=(12, 10))
        
        # Number of hosts
        n = len(hosts_status)
        
        # Create a circular layout
        angles = np.linspace(0, 2*np.pi, n, endpoint=False)
        
        # Calculate node positions
        radius = 5
        x = radius * np.cos(angles)
        y = radius * np.sin(angles)
        
        # Set up colors based on status
        colors = []
        for i, status in enumerate(hosts_status):
            if i in isolated_hosts:
                colors.append('black')  # Isolated hosts
            elif i in blocked_hosts:
                colors.append('gray')   # Blocked hosts
            elif status == 0:
                colors.append('green')  # Normal hosts
            elif status == 1:
                colors.append('orange') # Under attack
            else:
                colors.append('red')    # Compromised
        
        # Plot nodes
        ax.scatter(x, y, s=700, c=colors, edgecolors='black', zorder=10)
        
        # Add host labels
        for i, (xi, yi) in enumerate(zip(x, y)):
            ax.text(xi, yi, f"H{i}", fontsize=12, ha='center', va='center', 
                   color='white', fontweight='bold', zorder=20)
        
        # Draw connections for attacks
        if active_attacks:
            for attack in active_attacks:
                src = attack.get('source', 0)
                tgt = attack.get('target', 0)
                if src != tgt:  # Only if source and target are different
                    src_x, src_y = x[src], y[src]
                    tgt_x, tgt_y = x[tgt], y[tgt]
                    
                    # Draw arrow
                    ax.arrow(src_x, src_y, (tgt_x - src_x) * 0.8, (tgt_y - src_y) * 0.8, 
                            head_width=0.3, head_length=0.3, fc='red', ec='red', zorder=5,
                            length_includes_head=True)
                    
                    # Add attack type label
                    mid_x = (src_x + tgt_x) / 2
                    mid_y = (src_y + tgt_y) / 2
                    ax.text(mid_x, mid_y, attack.get('type', 'attack'), fontsize=8,
                           color='red', fontweight='bold', ha='center', va='center',
                           bbox=dict(facecolor='white', alpha=0.7, boxstyle='round'))
        
        # Add a legend
        legend_elements = [
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='green', markersize=15, label='Normal'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='orange', markersize=15, label='Under Attack'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='red', markersize=15, label='Compromised'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='gray', markersize=15, label='Blocked'),
            plt.Line2D([0], [0], marker='o', color='w', markerfacecolor='black', markersize=15, label='Isolated')
        ]
        ax.legend(handles=legend_elements, loc='upper right')
        
        # Set title and remove axes
        ax.set_title('Network State Visualization')
        ax.axis('off')
        
        # Equal aspect ratio
        ax.set_aspect('equal')
        
        if save:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.output_dir, f'network_state_{timestamp}.png')
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            print(f"Network state visualization saved to {filename}")
        
        plt.show()
    
    def plot_anomaly_scores(self, scores: List[float], threshold: float = None,
                          timestamps: List[Any] = None, save: bool = True):
        """
        Plot anomaly scores over time.
        
        Args:
            scores: List of anomaly scores
            threshold: Detection threshold
            timestamps: List of timestamps (optional)
            save: Whether to save the plot
        """
        plt.figure(figsize=(14, 6))
        
        x_values = timestamps if timestamps is not None else np.arange(len(scores))
        
        # Plot anomaly scores
        plt.plot(x_values, scores, 'b-', linewidth=2)
        
        # Plot threshold if provided
        if threshold is not None:
            plt.axhline(y=threshold, color='r', linestyle='--', label=f'Threshold ({threshold:.2f})')
        
        # Highlight anomalies
        if threshold is not None:
            anomalies = np.where(np.array(scores) > threshold)[0]
            if len(anomalies) > 0:
                anomaly_scores = [scores[i] for i in anomalies]
                anomaly_times = [x_values[i] for i in anomalies]
                plt.scatter(anomaly_times, anomaly_scores, c='red', s=50, label='Anomalies')
        
        plt.title('Anomaly Detection Scores')
        plt.ylabel('Anomaly Score')
        
        if timestamps is not None:
            plt.xlabel('Time')
            plt.gcf().autofmt_xdate()
        else:
            plt.xlabel('Time Step')
        
        plt.grid(True)
        plt.legend()
        
        if save:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.output_dir, f'anomaly_scores_{timestamp}.png')
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            print(f"Anomaly scores plot saved to {filename}")
        
        plt.show()
    
    def plot_alert_distribution(self, alerts_file: str, save: bool = True):
        """
        Visualize the distribution of security alerts.
        
        Args:
            alerts_file: Path to alerts JSON file
            save: Whether to save the visualization
        """
        try:
            # Load alerts
            with open(alerts_file, 'r') as f:
                alerts = json.load(f)
            
            if not alerts:
                print("No alerts to visualize.")
                return
            
            # Convert to DataFrame
            df = pd.DataFrame(alerts)
            
            # Set up the plots
            fig, axs = plt.subplots(2, 2, figsize=(15, 12))
            
            # Plot 1: Alert types distribution
            if 'detection_type' in df.columns:
                type_counts = df['detection_type'].value_counts()
                ax = sns.barplot(x=type_counts.index, y=type_counts.values, ax=axs[0, 0])
                ax.set_title('Distribution of Alert Types')
                ax.set_xlabel('Alert Type')
                ax.set_ylabel('Count')
                plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
            
            # Plot 2: Severity distribution
            if 'severity_level' in df.columns:
                severity_order = ['LOW', 'MEDIUM', 'HIGH']
                severity_counts = df['severity_level'].value_counts().reindex(severity_order).fillna(0)
                ax = sns.barplot(x=severity_counts.index, y=severity_counts.values, ax=axs[0, 1],
                               palette=['green', 'orange', 'red'])
                ax.set_title('Distribution of Alert Severities')
                ax.set_xlabel('Severity')
                ax.set_ylabel('Count')
            
            # Plot 3: Alerts over time
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                df['date'] = df['timestamp'].dt.date
                date_counts = df.groupby('date').size()
                ax = date_counts.plot(kind='line', ax=axs[1, 0], marker='o')
                ax.set_title('Alerts Over Time')
                ax.set_xlabel('Date')
                ax.set_ylabel('Number of Alerts')
                ax.grid(True)
            
            # Plot 4: Source/Target Heatmap
            if 'source' in df.columns and 'target' in df.columns:
                # Convert source and target to strings and create cross-tabulation
                df['source_str'] = df['source'].astype(str)
                df['target_str'] = df['target'].astype(str)
                
                # Count source-target pairs
                source_target_counts = df.groupby(['source_str', 'target_str']).size().unstack(fill_value=0)
                
                # Plot heatmap
                sns.heatmap(source_target_counts, annot=True, fmt='d', cmap='YlOrRd', ax=axs[1, 1])
                axs[1, 1].set_title('Source-Target Relationship Heatmap')
                axs[1, 1].set_xlabel('Target')
                axs[1, 1].set_ylabel('Source')
            
            plt.tight_layout()
            
            if save:
                filename = os.path.join(self.output_dir, 'alert_distribution.png')
                plt.savefig(filename, dpi=300, bbox_inches='tight')
                print(f"Alert distribution plot saved to {filename}")
            
            plt.show()
            
        except Exception as e:
            print(f"Error plotting alert distribution: {e}")

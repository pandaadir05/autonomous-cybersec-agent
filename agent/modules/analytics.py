"""
Analytics module for the Autonomous Cybersecurity Defense Agent.
"""

import logging
import time
import os
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from .threat_detection import Threat


class AnalyticsEngine:
    """Analytics engine for security data processing and insights."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the analytics engine.
        
        Args:
            config: Configuration dictionary for analytics
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        
        # Set up data storage
        self.data_dir = self.config.get('data_dir', 'data/analytics')
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Track analytics metrics
        self.last_processed_time = 0
        self.threat_history = []
        self.max_history_size = self.config.get('max_history_size', 10000)
        
        # Retention policy
        self.retention_days = self.config.get('retention_days', 30)
        
        # ML configuration
        self.ml_enabled = self.config.get('ml_enabled', False)
        if self.ml_enabled:
            self._initialize_ml_models()
    
    def record_threats(self, threats: List[Threat]) -> None:
        """
        Record threats for later analysis.
        
        Args:
            threats: List of detected threats
        """
        # Add threats to history with timestamp
        for threat in threats:
            self.threat_history.append({
                'id': threat.id,
                'type': threat.type,
                'source': threat.source,
                'severity': threat.severity,
                'confidence': threat.confidence,
                'timestamp': threat.timestamp,
                'resolved': threat.resolved,
                'resolution_time': threat.resolution_time,
                'details': threat.details
            })
        
        # Trim history if needed
        if len(self.threat_history) > self.max_history_size:
            self.threat_history = self.threat_history[-self.max_history_size:]
        
        # Log the recording
        self.logger.debug(f"Recorded {len(threats)} threats for analytics")
    
    def process_analytics(self) -> Dict[str, Any]:
        """
        Process analytics on recorded threat data.
        
        Returns:
            Dictionary of analytics results
        """
        self.last_processed_time = time.time()
        
        if not self.threat_history:
            self.logger.info("No threat history available for analytics")
            return {}
        
        # Convert to dataframe for analysis
        df = pd.DataFrame(self.threat_history)
        
        # Basic analytics
        results = {
            'total_threats': len(df),
            'resolved_threats': df['resolved'].sum(),
            'unresolved_threats': len(df) - df['resolved'].sum(),
            'threat_types': df['type'].value_counts().to_dict(),
            'severity_distribution': df['severity'].value_counts().to_dict()
        }
        
        # Time-based analysis (if timestamps available)
        if 'timestamp' in df.columns and not df['timestamp'].isna().all():
            # Convert to datetime for time analysis
            df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
            
            # Threats per day
            df['date'] = df['datetime'].dt.date
            threats_per_day = df.groupby('date').size()
            results['threats_per_day'] = threats_per_day.to_dict()
            
            # Response time analysis (for resolved threats)
            resolved_df = df[df['resolved'] & ~df['resolution_time'].isna()]
            if not resolved_df.empty:
                resolved_df['response_time'] = resolved_df['resolution_time'] - resolved_df['timestamp']
                results['avg_response_time'] = resolved_df['response_time'].mean()
                results['median_response_time'] = resolved_df['response_time'].median()
        
        # Run ML analysis if enabled
        if self.ml_enabled:
            ml_results = self._run_ml_analysis(df)
            results.update(ml_results)
        
        # Store results
        self._store_results(results)
        
        return results
    
    def cleanup_old_data(self) -> None:
        """Clean up data older than the retention period."""
        if not self.threat_history:
            return
            
        cutoff_time = time.time() - (self.retention_days * 24 * 60 * 60)
        
        # Filter threats newer than cutoff
        old_count = len(self.threat_history)
        self.threat_history = [
            threat for threat in self.threat_history 
            if threat['timestamp'] > cutoff_time
        ]
        
        removed_count = old_count - len(self.threat_history)
        if removed_count > 0:
            self.logger.info(f"Removed {removed_count} threats older than {self.retention_days} days")
        
        # Also clean up old result files
        self._cleanup_old_files()
    
    def _initialize_ml_models(self) -> None:
        """Initialize machine learning models for analytics."""
        self.logger.info("Initializing ML models for analytics")
        
        try:
            # Here you would initialize ML models
            # For now, we'll just log that it would happen
            self.logger.info("ML models would be initialized here")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize ML models: {e}", exc_info=True)
            self.ml_enabled = False
    
    def _run_ml_analysis(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Run machine learning analysis on threat data.
        
        Args:
            df: DataFrame of threat data
            
        Returns:
            Dictionary of ML analysis results
        """
        results = {}
        
        try:
            # Here you would run actual ML analysis
            # For now, we'll add placeholder results
            results['ml_threat_clusters'] = 3
            results['ml_anomaly_score'] = 0.15
            
        except Exception as e:
            self.logger.error(f"Error in ML analysis: {e}", exc_info=True)
        
        return results
    
    def _store_results(self, results: Dict[str, Any]) -> None:
        """
        Store analytics results to disk.
        
        Args:
            results: Analytics results to store
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.data_dir, f"analytics_{timestamp}.json")
            
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
                
            self.logger.debug(f"Analytics results saved to {filename}")
            
        except Exception as e:
            self.logger.error(f"Failed to store analytics results: {e}", exc_info=True)
    
    def _cleanup_old_files(self) -> None:
        """Remove analytics files older than the retention period."""
        try:
            cutoff_time = time.time() - (self.retention_days * 24 * 60 * 60)
            
            count = 0
            for filename in os.listdir(self.data_dir):
                if filename.startswith("analytics_") and filename.endswith(".json"):
                    filepath = os.path.join(self.data_dir, filename)
                    
                    if os.path.getmtime(filepath) < cutoff_time:
                        os.remove(filepath)
                        count += 1
            
            if count > 0:
                self.logger.info(f"Removed {count} old analytics files")
                
        except Exception as e:
            self.logger.error(f"Error cleaning up old files: {e}", exc_info=True)
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get the status of the analytics engine.
        
        Returns:
            Dictionary with status information
        """
        return {
            "last_processed_time": self.last_processed_time,
            "recorded_threats": len(self.threat_history),
            "ml_enabled": self.ml_enabled,
            "retention_days": self.retention_days
        }

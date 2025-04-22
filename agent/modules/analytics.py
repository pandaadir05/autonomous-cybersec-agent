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
import matplotlib.pyplot as plt
import threading

class AnalyticsEngine:
    """Analytics engine for security data processing and insights."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the analytics engine.
        
        Args:
            config: Analytics configuration
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        
        # Set data storage directory
        self.data_dir = self.config.get("data_dir", "data/analytics")
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Set up data retention policy
        self.retention_days = self.config.get("retention_days", 30)
        
        # Set up analysis interval
        self.analysis_interval = self.config.get("interval", 300)  # 5 minutes default
        
        # Initialize data structures
        self.threat_data = pd.DataFrame()
        self.response_data = pd.DataFrame()
        self.threat_history = []
        self.max_history_size = self.config.get('max_history_size', 10000)
        
        # Load existing data
        self._load_data()
        
        # Runtime variables
        self._running = False
        self._analysis_thread = None
        self.last_processed_time = None
        self.last_analysis_time = None
        
        # ML configuration
        self.ml_enabled = self.config.get('ml_enabled', False)
        if self.ml_enabled:
            self._initialize_ml_models()
    
    def start(self):
        """Start the analytics engine."""
        if self._running:
            return
            
        self.logger.info("Starting analytics engine")
        self._running = True
        
        # Start background analysis thread
        self._start_analysis_thread()
        
        self.logger.info("Analytics engine started")
        
    def stop(self):
        """Stop the analytics engine."""
        if not self._running:
            return
            
        self.logger.info("Stopping analytics engine")
        self._running = False
        
        # Wait for analysis thread to complete
        if self._analysis_thread and self._analysis_thread.is_alive():
            self._analysis_thread.join(timeout=5.0)
            
        self.logger.info("Analytics engine stopped")
    
    def _start_analysis_thread(self):
        """Start the background thread for periodic analytics processing."""
        self._analysis_thread = threading.Thread(
            target=self._analysis_loop,
            daemon=True,
            name="AnalyticsThread"
        )
        self._analysis_thread.start()
    
    def _analysis_loop(self):
        """Background loop for periodic analytics processing."""
        while self._running:
            try:
                # Run analytics processing
                self.process_analytics()
                
                # Clean up old data
                self.cleanup_old_data()
                
                # Sleep for the configured interval
                time.sleep(self.analysis_interval)
            except Exception as e:
                self.logger.error(f"Error in analytics loop: {e}")
                time.sleep(60)  # Sleep on error
        
    def record_threats(self, threats: List[Dict[str, Any]], responses: List[Dict[str, Any]] = None):
        """
        Record threat and response data for analysis.
        
        Args:
            threats: List of threats
            responses: List of response results (optional)
        """
        try:
            # Process threat data
            for threat in threats:
                threat_row = {
                    "id": threat["id"],
                    "type": threat["type"],
                    "source": threat["source"],
                    "severity": threat["severity"],
                    "confidence": threat["confidence"],
                    "timestamp": threat["timestamp"],
                    "resolved": threat.get("resolved", False)
                }
                
                # Add to dataframe
                self.threat_data = pd.concat([
                    self.threat_data,
                    pd.DataFrame([threat_row])
                ], ignore_index=True)
                
                # Also add to history list
                self.threat_history.append(threat_row)
                
            # Process response data if provided
            if responses:
                for response in responses:
                    response_row = {
                        "action": response["action"],
                        "success": response["success"],
                        "timestamp": time.time(),
                        "threat_id": response.get("threat_id", "unknown"),
                        "details": str(response.get("details", {}))
                    }
                    
                    # Add to dataframe
                    self.response_data = pd.concat([
                        self.response_data,
                        pd.DataFrame([response_row])
                    ], ignore_index=True)
            
            # Trim history if needed
            if len(self.threat_history) > self.max_history_size:
                self.threat_history = self.threat_history[-self.max_history_size:]
            
            # Save data periodically
            self._save_data()
            
        except Exception as e:
            self.logger.error(f"Error recording analytics data: {e}", exc_info=True)
    
    def _load_data(self):
        """Load existing data from files."""
        try:
            threat_file = os.path.join(self.data_dir, "threat_data.csv")
            response_file = os.path.join(self.data_dir, "response_data.csv")
            
            if os.path.exists(threat_file):
                self.threat_data = pd.read_csv(threat_file)
                self.logger.info(f"Loaded {len(self.threat_data)} threat records from {threat_file}")
                
                # Also populate threat history from the dataframe
                self.threat_history = self.threat_data.to_dict('records')
                if len(self.threat_history) > self.max_history_size:
                    self.threat_history = self.threat_history[-self.max_history_size:]
            
            if os.path.exists(response_file):
                self.response_data = pd.read_csv(response_file)
                self.logger.info(f"Loaded {len(self.response_data)} response records from {response_file}")
                
        except Exception as e:
            self.logger.error(f"Error loading analytics data: {e}", exc_info=True)
    
    def _save_data(self):
        """Save data to files."""
        try:
            threat_file = os.path.join(self.data_dir, "threat_data.csv")
            response_file = os.path.join(self.data_dir, "response_data.csv")
            
            self.threat_data.to_csv(threat_file, index=False)
            self.response_data.to_csv(response_file, index=False)
            
        except Exception as e:
            self.logger.error(f"Error saving analytics data: {e}", exc_info=True)
            
    def process_analytics(self) -> Dict[str, Any]:
        """
        Process analytics on recorded threat data.
        
        Returns:
            Dictionary of analytics results
        """
        self.last_processed_time = time.time()
        
        if self.threat_data.empty:
            self.logger.info("No threat data available for analytics")
            return {}
        
        results = {}
        
        try:
            # Basic threat statistics
            results['total_threats'] = len(self.threat_data)
            results['resolved_threats'] = int(self.threat_data['resolved'].sum())
            results['unresolved_threats'] = results['total_threats'] - results['resolved_threats']
            
            # Threat types distribution
            results['threat_types'] = self.threat_data['type'].value_counts().to_dict()
            
            # Severity distribution
            results['severity_distribution'] = self.threat_data['severity'].value_counts().to_dict()
            
            # Time-based analysis
            if 'timestamp' in self.threat_data.columns:
                # Convert timestamp to datetime
                self.threat_data['datetime'] = pd.to_datetime(self.threat_data['timestamp'], unit='s')
                
                # Group by day
                self.threat_data['date'] = self.threat_data['datetime'].dt.date
                threats_by_day = self.threat_data.groupby('date').size()
                results['threats_by_day'] = {str(key): int(val) for key, val in zip(threats_by_day.index, threats_by_day.values)}
                
                # Recent trend (last 7 days)
                today = datetime.now().date()
                dates = [(today - timedelta(days=i)).strftime('%Y-%m-%d') for i in range(7)]
                dates.reverse()  # Oldest first
                
                trend_data = []
                for date_str in dates:
                    date_obj = datetime.strptime(date_str, '%Y-%m-%d').date()
                    if date_obj in threats_by_day.index:
                        trend_data.append(int(threats_by_day[date_obj]))
                    else:
                        trend_data.append(0)
                        
                results['recent_trend'] = {
                    'dates': dates,
                    'counts': trend_data
                }
            
            # Source analysis
            top_sources = self.threat_data['source'].value_counts().head(10)
            results['top_sources'] = {str(key): int(val) for key, val in zip(top_sources.index, top_sources.values)}
            
            # Response analysis
            if not self.response_data.empty:
                results['total_responses'] = len(self.response_data)
                results['successful_responses'] = int(self.response_data['success'].sum())
                results['response_types'] = self.response_data['action'].value_counts().to_dict()
                
                # Join threat and response data to calculate response times
                if 'threat_id' in self.response_data.columns:
                    # TODO: Implement response time analysis
                    pass
            
            # Generate visualizations
            self._generate_visualizations()
            
            # Run ML analysis if enabled
            if self.ml_enabled:
                ml_results = self._run_ml_analysis()
                results.update(ml_results)
            
            # Store results
            self._store_results(results)
            self.last_analysis_time = time.time()
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error processing analytics: {e}", exc_info=True)
            return {"error": str(e)}
    
    def generate_threat_report(self, days: int = 7) -> Dict[str, Any]:
        """
        Generate a report of threat activity.
        
        Args:
            days: Number of days to include in the report
            
        Returns:
            Dictionary with report data
        """
        try:
            # Filter data for the time period
            if self.threat_data.empty:
                return {
                    "period_days": days,
                    "total_threats": 0,
                    "message": "No threat data available for the period"
                }
                
            # Convert timestamp to datetime if not already done
            if 'datetime' not in self.threat_data.columns:
                self.threat_data['datetime'] = pd.to_datetime(self.threat_data['timestamp'], unit='s')
            
            start_time = datetime.now() - timedelta(days=days)
            period_data = self.threat_data[self.threat_data['datetime'] >= start_time]
            
            if period_data.empty:
                return {
                    "period_days": days,
                    "total_threats": 0,
                    "message": "No threat data available for the period"
                }
                
            # Generate report statistics
            report = {
                "period_days": days,
                "start_date": start_time.strftime("%Y-%m-%d"),
                "end_date": datetime.now().strftime("%Y-%m-%d"),
                "total_threats": len(period_data),
                "by_severity": {},
                "by_type": {},
                "top_sources": [],
                "daily_counts": []
            }
            
            # Count by severity
            severity_counts = period_data["severity"].value_counts().to_dict()
            for severity in range(1, 6):  # 1-5 scale
                report["by_severity"][str(severity)] = severity_counts.get(severity, 0)
                
            # Count by type
            type_counts = period_data["type"].value_counts().to_dict()
            report["by_type"] = type_counts
            
            # Top sources
            top_sources = period_data["source"].value_counts().head(10).to_dict()
            report["top_sources"] = [{"source": k, "count": v} for k, v in top_sources.items()]
            
            # Daily counts
            period_data["date"] = period_data["datetime"].dt.date
            daily_counts = period_data.groupby("date").size().reset_index(name="count")
            report["daily_counts"] = [
                {"date": row["date"].strftime("%Y-%m-%d"), "count": int(row["count"])} 
                for _, row in daily_counts.iterrows()
            ]
            
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating threat report: {e}", exc_info=True)
            return {
                "period_days": days,
                "total_threats": 0,
                "error": str(e)
            }
    
    def generate_visualizations(self, output_dir: str = "reports") -> List[str]:
        """
        Generate visualization charts for threat data.
        
        Args:
            output_dir: Directory to save visualizations
            
        Returns:
            List of generated file paths
        """
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            if self.threat_data.empty:
                self.logger.warning("No threat data available for visualizations")
                return []
            
            generated_files = []
            timestamp = datetime.now().strftime("%Y%m%d_%H%M")
            
            # 1. Threat counts by type
            fig, ax = plt.subplots(figsize=(10, 6))
            threat_counts = self.threat_data['type'].value_counts()
            threat_counts.plot(kind='bar', ax=ax)
            ax.set_title('Threats by Type')
            ax.set_ylabel('Count')
            ax.set_xlabel('Threat Type')
            plt.tight_layout()
            
            file_path = os.path.join(output_dir, f"threat_types_{timestamp}.png")
            plt.savefig(file_path)
            plt.close(fig)
            generated_files.append(file_path)
            
            # 2. Threats by severity
            fig, ax = plt.subplots(figsize=(8, 8))
            severity_counts = self.threat_data['severity'].value_counts().sort_index()
            severity_counts.plot(kind='pie', autopct='%1.1f%%', ax=ax)
            ax.set_title('Threats by Severity')
            plt.tight_layout()
            
            file_path = os.path.join(output_dir, f"threat_severity_{timestamp}.png")
            plt.savefig(file_path)
            plt.close(fig)
            generated_files.append(file_path)
            
            # 3. Threats over time
            if 'datetime' not in self.threat_data.columns:
                self.threat_data['datetime'] = pd.to_datetime(self.threat_data['timestamp'], unit='s')
                
            self.threat_data['date'] = self.threat_data['datetime'].dt.date
            daily_counts = self.threat_data.groupby('date').size()
            
            fig, ax = plt.subplots(figsize=(12, 6))
            daily_counts.plot(kind='line', marker='o', ax=ax)
            ax.set_title('Threats Over Time')
            ax.set_ylabel('Number of Threats')
            ax.set_xlabel('Date')
            ax.grid(True)
            plt.tight_layout()
            
            file_path = os.path.join(output_dir, f"threats_over_time_{timestamp}.png")
            plt.savefig(file_path)
            plt.close(fig)
            generated_files.append(file_path)
            
            # 4. Top threat sources
            fig, ax = plt.subplots(figsize=(10, 6))
            source_counts = self.threat_data['source'].value_counts().head(10)
            source_counts.plot(kind='barh', ax=ax)
            ax.set_title('Top Threat Sources')
            ax.set_ylabel('Source')
            ax.set_xlabel('Count')
            plt.tight_layout()
            
            file_path = os.path.join(output_dir, f"top_sources_{timestamp}.png")
            plt.savefig(file_path)
            plt.close(fig)
            generated_files.append(file_path)
            
            return generated_files
            
        except Exception as e:
            self.logger.error(f"Error generating visualizations: {e}", exc_info=True)
            return []
            
    def _generate_visualizations(self):
        """Generate standard visualizations and save them."""
        try:
            reports_dir = os.path.join(self.data_dir, "reports")
            self.generate_visualizations(reports_dir)
        except Exception as e:
            self.logger.error(f"Error in automatic visualization: {e}", exc_info=True)
    
    def cleanup_old_data(self) -> None:
        """Clean up data older than the retention period."""
        if self.threat_data.empty:
            return
            
        try:
            # Calculate cutoff timestamp
            cutoff_time = time.time() - (self.retention_days * 24 * 60 * 60)
            
            # Filter out old records
            old_count = len(self.threat_data)
            self.threat_data = self.threat_data[self.threat_data['timestamp'] > cutoff_time]
            
            # Also clean up response data
            if not self.response_data.empty:
                self.response_data = self.response_data[self.response_data['timestamp'] > cutoff_time]
                
            # Clean up threat history
            self.threat_history = [
                threat for threat in self.threat_history 
                if threat['timestamp'] > cutoff_time
            ]
            
            # Save updated data
            self._save_data()
            
            cleaned_count = old_count - len(self.threat_data)
            if cleaned_count > 0:
                self.logger.info(f"Removed {cleaned_count} records older than {self.retention_days} days")
            
            # Clean up old files
            self._cleanup_old_files()
            
        except Exception as e:
            self.logger.error(f"Error cleaning up old data: {e}", exc_info=True)
    
    def _initialize_ml_models(self) -> None:
        """Initialize machine learning models for analytics."""
        try:
            self.logger.info("Initializing ML models for analytics")
            # In a real implementation, this would initialize actual ML models
            # For now, we'll just set a flag that it's ready
            self.logger.info("ML models initialized")
        except Exception as e:
            self.logger.error(f"Failed to initialize ML models: {e}", exc_info=True)
            self.ml_enabled = False
    
    def _run_ml_analysis(self) -> Dict[str, Any]:
        """
        Run machine learning analysis on threat data.
        
        Returns:
            Dictionary with ML analysis results
        """
        results = {}
        
        try:
            # This would perform actual ML analysis in a real implementation
            # Here we'll just return placeholder results
            results['ml_analysis'] = {
                'anomaly_score': 0.3,
                'trend_prediction': 'increasing',
                'estimated_attack_probability': 0.15,
                'cluster_analysis': {
                    'num_clusters': 3,
                    'largest_cluster_size': 12
                }
            }
        except Exception as e:
            self.logger.error(f"Error in ML analysis: {e}", exc_info=True)
            results['ml_error'] = str(e)
            
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
            
            # Also clean up old reports
            reports_dir = os.path.join(self.data_dir, "reports")
            if os.path.exists(reports_dir):
                for filename in os.listdir(reports_dir):
                    if filename.endswith(".png"):
                        filepath = os.path.join(reports_dir, filename)
                        
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
            "running": self._running,
            "last_processed_time": self.last_processed_time or 0,
            "last_analysis_time": self.last_analysis_time or 0,
            "recorded_threats": len(self.threat_data) if not self.threat_data.empty else 0,
            "ml_enabled": self.ml_enabled,
            "retention_days": self.retention_days
        }

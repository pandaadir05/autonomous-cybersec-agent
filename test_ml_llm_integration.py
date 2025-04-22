#!/usr/bin/env python3
"""
Test script to demonstrate integration of ML and LLM for cybersecurity.
"""

import os
import sys
import json
import time
import logging
import numpy as np
import pandas as pd
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("ml_llm_test")

# Import ML components
sys.path.append(str(Path(__file__).parent))
from src.models.anomaly_detector import AnomalyDetector
from agent.modules.detection.anomaly import NetworkAnomalyDetector
from agent.modules.detection.malware import MalwareDetector
from agent.modules.detection.compliance import ComplianceChecker

# The OpenAI API Key for LLM integration
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

class ThreatAnalyzer:
    """Class to integrate ML detection with LLM analysis."""
    
    def __init__(self):
        """Initialize the analyzer."""
        self.logger = logging.getLogger("ThreatAnalyzer")
        
        # Initialize ML components
        self.anomaly_detector_ml = AnomalyDetector()
        self.anomaly_detector = NetworkAnomalyDetector(config={})
        self.malware_detector = MalwareDetector(config={})
        self.compliance_checker = ComplianceChecker(config={})
        
        # Try to load trained model if available
        try:
            model_path = Path("models/anomaly_detector.pkl")
            if model_path.exists():
                self.anomaly_detector_ml.load(str(model_path))
                self.logger.info("Loaded trained anomaly detection model")
            else:
                self.logger.warning("No trained model found, will use statistical detection")
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
    
    def generate_test_network_data(self):
        """Generate synthetic network data for testing."""
        # Normal traffic pattern
        if random.random() < 0.8:  # 80% normal traffic
            connections = []
            for _ in range(random.randint(3, 8)):
                local_port = random.randint(49152, 65535)
                remote_port = random.choice([80, 443, 8080, 22])
                remote_ip = f"192.168.1.{random.randint(1, 254)}"
                connections.append({
                    "local": f"127.0.0.1:{local_port}",
                    "remote": f"{remote_ip}:{remote_port}"
                })
            
            return {
                "connections": connections,
                "bytes_per_second": random.randint(1000, 100000),
                "packets_per_second": random.randint(10, 200)
            }
        else:  # 20% anomalous traffic
            connections = []
            # Generate a spike in connections
            for _ in range(random.randint(50, 100)):
                local_port = random.randint(49152, 65535)
                remote_port = random.choice([80, 443, 8080, 22, 3389, 5900])
                remote_ip = f"203.0.113.{random.randint(1, 254)}"  # Test net
                connections.append({
                    "local": f"127.0.0.1:{local_port}",
                    "remote": f"{remote_ip}:{remote_port}"
                })
            
            return {
                "connections": connections,
                "bytes_per_second": random.randint(500000, 2000000),
                "packets_per_second": random.randint(1000, 5000)
            }
    
    def analyze_with_ml(self, network_data):
        """Analyze network data using ML models."""
        # Use the statistical anomaly detector
        anomalies = self.anomaly_detector.analyze(network_data)
        
        # Convert to feature format and use ML anomaly detector if loaded
        if hasattr(self.anomaly_detector_ml, 'model') and self.anomaly_detector_ml.model:
            features = np.array([[
                len(network_data["connections"]),
                network_data["bytes_per_second"], 
                network_data["packets_per_second"],
                network_data["bytes_per_second"] / (len(network_data["connections"]) or 1),
                network_data["packets_per_second"] / (len(network_data["connections"]) or 1)
            ]])
            
            ml_results = self.anomaly_detector_ml.detect(features)
            if ml_results.get("is_anomaly"):
                if not anomalies:
                    anomalies.append({
                        "type": "ml_detected_anomaly",
                        "source": "network",
                        "severity": 3,
                        "confidence": float(ml_results.get("anomaly_probability", 0.5)),
                        "details": {
                            "description": "ML model detected network anomaly",
                            "anomaly_score": float(ml_results.get("anomaly_probability", 0)),
                            "threshold": float(ml_results.get("detection_threshold", 0))
                        }
                    })
                else:
                    # Enhance existing anomalies with ML confidence
                    for anomaly in anomalies:
                        anomaly["details"]["ml_confidence"] = float(ml_results.get("anomaly_probability", 0.5))
        
        return anomalies
    
    def analyze_with_llm(self, anomalies, network_data):
        """Analyze threats using LLM for enhanced understanding."""
        if not OPENAI_API_KEY:
            self.logger.warning("No OpenAI API key provided, skipping LLM analysis")
            return "LLM analysis not available: No API key provided"
            
        if not anomalies:
            return "No anomalies detected that require LLM analysis."
        
        try:
            headers = {
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json"
            }
            
            # Format the input for the LLM
            context = {
                "network_data": {
                    "connection_count": len(network_data["connections"]),
                    "sample_connections": network_data["connections"][:5] if len(network_data["connections"]) > 5 else network_data["connections"],
                    "bytes_per_second": network_data["bytes_per_second"],
                    "packets_per_second": network_data["packets_per_second"]
                },
                "detected_anomalies": anomalies
            }
            
            prompt = f"""
            As a cybersecurity expert, analyze the following network traffic anomalies and provide:
            1. A security assessment of the detected threats
            2. Possible attack vectors being used
            3. Recommended response actions
            
            Network Data: {json.dumps(context["network_data"])}
            
            Detected Anomalies: {json.dumps(context["detected_anomalies"])}
            
            Provide your analysis in a structured format with clear recommendations.
            """
            
            data = {
                "model": "gpt-4-turbo",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.3,
                "max_tokens": 1000
            }
            
            response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data)
            response.raise_for_status()
            
            analysis = response.json()["choices"][0]["message"]["content"]
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error in LLM analysis: {e}")
            return f"Error performing LLM analysis: {str(e)}"
    
    def run_analysis(self, iterations=3):
        """Run the combined ML and LLM analysis."""
        for i in range(iterations):
            self.logger.info(f"Starting analysis iteration {i+1}...")
            
            # Generate synthetic network data
            network_data = self.generate_test_network_data()
            self.logger.info(f"Generated network data with {len(network_data['connections'])} connections")
            
            # Analyze with ML models
            start_time = time.time()
            anomalies = self.analyze_with_ml(network_data)
            ml_time = time.time() - start_time
            
            if anomalies:
                self.logger.info(f"Detected {len(anomalies)} anomalies with ML (in {ml_time:.2f}s)")
                for anomaly in anomalies:
                    self.logger.info(f"- {anomaly['type']} (severity: {anomaly['severity']}, confidence: {anomaly['confidence']:.2f})")
                
                # Analyze with LLM
                start_time = time.time()
                llm_analysis = self.analyze_with_llm(anomalies, network_data)
                llm_time = time.time() - start_time
                
                self.logger.info(f"LLM Analysis completed in {llm_time:.2f}s:")
                print("\n" + "="*80 + "\nLLM ANALYSIS:\n" + "="*80)
                print(llm_analysis)
                print("="*80 + "\n")
            else:
                self.logger.info("No anomalies detected")
            
            print("\n" + "-"*80 + "\n")
            time.sleep(2)  # Brief pause between iterations


def main():
    """Main entry point."""
    print("\n" + "="*80)
    print("AUTONOMOUS CYBERSECURITY AGENT - ML & LLM INTEGRATION TEST")
    print("="*80 + "\n")
    
    if not OPENAI_API_KEY:
        print("WARNING: No OpenAI API key provided. Set OPENAI_API_KEY environment variable for LLM integration.")
        print("Will continue with ML-only analysis...\n")
    
    analyzer = ThreatAnalyzer()
    analyzer.run_analysis(iterations=3)
    
    print("\nTest completed.")


if __name__ == "__main__":
    main()

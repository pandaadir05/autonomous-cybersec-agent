from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field
import uvicorn
import os
import json
from datetime import datetime
import logging

# Import your project modules
from src.models.anomaly_detector import AnomalyDetector
from src.utils.data_preprocessor import FeatureExtractor
from src.utils.explainability import AnomalyExplainer
from src.utils.logger import Logger

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Autonomous Cybersecurity Agent API",
    description="API for interacting with the cybersecurity defense agent",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define models for API
class NetworkTrafficData(BaseModel):
    """Data model for network traffic submission."""
    host_features: Dict[str, List[float]] = Field(default={})
    flow_features: Dict[str, List[float]] = Field(default={})
    packet_features: Dict[str, List[float]] = Field(default={})
    metadata: Dict[str, Any] = Field(default={})

class DetectionResult(BaseModel):
    """Data model for detection results."""
    timestamp: str
    is_anomaly: bool
    anomaly_probability: float
    anomaly_scores: Dict[str, float]
    details: Dict[str, Any] = {}

class AgentStatus(BaseModel):
    """Data model for agent status."""
    status: str
    uptime: float
    models_loaded: List[str]
    detection_threshold: float
    recent_anomaly_rate: float

# Global variables for the API
api_state = {
    "anomaly_detector": None,
    "feature_extractor": None,
    "explainer": None,
    "start_time": datetime.now(),
    "recent_detections": [],
}

# Background task to periodically save detections
def save_detections():
    """Background task to save detection history."""
    if len(api_state["recent_detections"]) > 0:
        try:
            os.makedirs("data/detections", exist_ok=True)
            filename = f"data/detections/detections_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(api_state["recent_detections"], f)
            api_state["recent_detections"] = []
        except Exception as e:
            logger.error(f"Failed to save detections: {e}")

# Dependency to get components
def get_components():
    """Ensures components are initialized."""
    if api_state["anomaly_detector"] is None:
        # Load models from disk
        try:
            anomaly_detector = AnomalyDetector()
            feature_extractor = FeatureExtractor()
            anomaly_detector.load("models/best_anomaly_detector")
            feature_extractor.load("models/best_feature_extractor")
            explainer = AnomalyExplainer(feature_names=feature_extractor.feature_names)
            
            # Store in state
            api_state["anomaly_detector"] = anomaly_detector
            api_state["feature_extractor"] = feature_extractor
            api_state["explainer"] = explainer
            
        except Exception as e:
            logger.error(f"Failed to load models: {e}")
            raise HTTPException(status_code=500, detail=f"Failed to initialize components: {e}")
    
    return api_state

# Routes
@app.get("/", tags=["General"])
async def root():
    """Root endpoint that provides basic API information."""
    return {
        "name": "Autonomous Cybersecurity Agent API",
        "version": "1.0.0",
        "status": "active"
    }

@app.get("/status", response_model=AgentStatus, tags=["General"])
async def get_status(components=Depends(get_components)):
    """Get the current status of the cybersecurity agent."""
    uptime = (datetime.now() - components["start_time"]).total_seconds()
    
    # Calculate recent anomaly rate
    if len(components["recent_detections"]) > 0:
        anomaly_count = sum(1 for d in components["recent_detections"] if d.get("is_anomaly", False))
        anomaly_rate = anomaly_count / len(components["recent_detections"])
    else:
        anomaly_rate = 0.0
    
    return AgentStatus(
        status="active",
        uptime=uptime,
        models_loaded=[m for m in components["anomaly_detector"].methods if m is not None],
        detection_threshold=components["anomaly_detector"].detection_threshold,
        recent_anomaly_rate=anomaly_rate
    )

@app.post("/detect", response_model=DetectionResult, tags=["Detection"])
async def detect_anomalies(data: NetworkTrafficData, background_tasks: BackgroundTasks, 
                         components=Depends(get_components)):
    """
    Detect anomalies in submitted network traffic data.
    """
    try:
        # Convert input data to DataFrame
        features_dict = {}
        features_dict.update(data.host_features)
        features_dict.update(data.flow_features)
        features_dict.update(data.packet_features)
        
        # Verify we have data
        if not features_dict:
            raise HTTPException(status_code=400, detail="No features provided")
        
        # Convert to proper format for feature extractor
        df = pd.DataFrame(features_dict)
        
        # Extract features
        features = components["feature_extractor"].extract_features(df)
        
        # Detect anomalies
        anomaly_results = components["anomaly_detector"].detect(features)
        
        # Prepare response
        result = DetectionResult(
            timestamp=datetime.now().isoformat(),
            is_anomaly=bool(anomaly_results["is_anomaly"]),
            anomaly_probability=float(anomaly_results["anomaly_probability"]),
            anomaly_scores={
                k: float(v) if v is not None else None
                for k, v in anomaly_results.items()
                if k.endswith("_score") and not isinstance(v, np.ndarray)
            },
            details={
                "detection_threshold": float(anomaly_results["detection_threshold"]),
                "feature_count": features.shape[1]
            }
        )
        
        # Store detection for history
        components["recent_detections"].append(result.dict())
        
        # Schedule background save if we have enough detections
        if len(components["recent_detections"]) >= 100:
            background_tasks.add_task(save_detections)
        
        return result
        
    except Exception as e:
        logger.error(f"Detection error: {e}")
        raise HTTPException(status_code=500, detail=f"Detection failed: {str(e)}")

@app.post("/explain", tags=["Explanation"])
async def explain_detection(data: NetworkTrafficData, components=Depends(get_components)):
    """
    Provide explanations for detected anomalies.
    """
    try:
        # Similar preprocessing as in detect endpoint
        features_dict = {}
        features_dict.update(data.host_features)
        features_dict.update(data.flow_features)
        features_dict.update(data.packet_features)
        
        if not features_dict:
            raise HTTPException(status_code=400, detail="No features provided")
        
        df = pd.DataFrame(features_dict)
        features = components["feature_extractor"].extract_features(df)
        
        # Get anomaly scores
        anomaly_results = components["anomaly_detector"].detect(features)
        anomaly_scores = anomaly_results["anomaly_score"]
        
        # Generate explanation
        explanation = components["explainer"].explain_by_contribution(
            features, anomaly_scores)
        
        # Save visualization
        vis_path = "data/visualizations"
        os.makedirs(vis_path, exist_ok=True)
        vis_file = f"anomaly_vis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        full_path = os.path.join(vis_path, vis_file)
        
        components["explainer"].visualize_anomaly(features, anomaly_scores, full_path)
        
        # Return explanation with path to visualization
        explanation["visualization_path"] = full_path
        
        return explanation
        
    except Exception as e:
        logger.error(f"Explanation error: {e}")
        raise HTTPException(status_code=500, detail=f"Explanation failed: {str(e)}")

# Run the application
def start_api(host="0.0.0.0", port=8000, reload=False):
    """Start the FastAPI server."""
    uvicorn.run("src.api.server:app", host=host, port=port, reload=reload)

if __name__ == "__main__":
    start_api(reload=True)

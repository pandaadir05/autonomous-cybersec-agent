"""
Logging utilities for the agent.
"""

import logging
import time
from typing import Dict, Any, Optional

def setup_logger(config: Dict[str, Any]) -> None:
    """
    Set up the logging system based on configuration.
    
    Args:
        config: Logging configuration
    """
    log_level = getattr(logging, config.get("level", "INFO"))
    log_file = config.get("file", "logs/agent.log")
    
    # Create log format
    log_format = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    
    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    logging.info(f"Logging initialized at level {log_level}")

def log_security_event(message: str, level: int, **kwargs) -> None:
    """
    Log a security event.
    
    Args:
        message: Log message
        level: Logging level
        **kwargs: Additional data to log
    """
    logger = logging.getLogger("security")
    
    # Add timestamp if not present
    if "timestamp" not in kwargs:
        kwargs["timestamp"] = time.time()
        
    # Format message
    full_message = f"{message} {kwargs}"
    
    # Log at appropriate level
    logger.log(level, full_message)

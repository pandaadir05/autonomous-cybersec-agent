"""
Logging utilities for the Autonomous Cybersecurity Defense Agent.
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional

def setup_logging(level: int = logging.INFO, log_file: Optional[str] = None,
                 max_size: int = 10, backup_count: int = 5) -> None:
    """
    Set up logging for the application.
    
    Args:
        level: Logging level
        log_file: Path to log file (None for console-only logging)
        max_size: Maximum size of log file in MB before rollover
        backup_count: Number of backup log files to keep
    """
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create console handler
    console = logging.StreamHandler(stream=sys.stdout)
    console.setLevel(level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console.setFormatter(formatter)
    
    # Add console handler to logger
    root_logger.addHandler(console)
    
    # Add file handler if log file is specified
    if log_file:
        # Create directory if it doesn't exist
        log_path = Path(log_file)
        if not log_path.parent.exists():
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
        # Create rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_size * 1024 * 1024,  # Convert MB to bytes
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        
    # Create special security logger for security events
    security_logger = logging.getLogger('security')
    
    # If not console only, create a separate security log file
    if log_file:
        security_log_file = str(log_path.parent / 'security.log')
        security_handler = logging.handlers.RotatingFileHandler(
            security_log_file,
            maxBytes=max_size * 1024 * 1024,
            backupCount=backup_count,
            encoding='utf-8'
        )
        security_handler.setLevel(logging.INFO)
        security_handler.setFormatter(formatter)
        security_logger.addHandler(security_handler)

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name.
    
    Args:
        name: Logger name
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)

def log_security_event(message: str, level: int = logging.INFO, **kwargs) -> None:
    """
    Log a security event with the specified level.
    
    Args:
        message: Log message
        level: Logging level
        **kwargs: Additional context information to include
    """
    logger = logging.getLogger('security')
    
    # Add kwargs as extra context
    extra_msg = ""
    if kwargs:
        extra_msg = " - " + " ".join(f"{k}={v}" for k, v in kwargs.items())
        
    logger.log(level, f"{message}{extra_msg}")

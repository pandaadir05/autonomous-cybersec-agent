"""
Logging utilities for the Autonomous Cybersecurity Defense Agent.
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional
import json
import time

def setup_logging(
    level: int = logging.INFO, 
    log_file: Optional[str] = None,
    max_size: int = 10, 
    backup_count: int = 5
) -> None:
    """
    Set up logging configuration.
    
    Args:
        level: Logging level
        log_file: Path to log file (or None for console only)
        max_size: Maximum log file size in MB
        backup_count: Number of backup log files to keep
    """
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Always add console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # Add file handler if specified
    if log_file:
        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        # Use rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_size * 1024 * 1024,  # Convert MB to bytes
            backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
    
    # Quiet down noisy loggers
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    
    # Log that logging is set up
    logging.info(f"Logging initialized (level={logging.getLevelName(level)})")


def setup_logger(
    name: str,
    level: int = logging.INFO,
    log_file: Optional[str] = None
) -> logging.Logger:
    """
    Set up a logger with the given name.
    
    Args:
        name: Name of the logger
        level: Logging level
        log_file: Optional log file path
        
    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Add console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Add file handler if specified
    if log_file:
        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
            
        # Use rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get an existing logger by name.
    
    Args:
        name: Name of the logger
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)


def log_security_event(message: str, level: int = logging.INFO, **kwargs) -> None:
    """
    Log a security event to the security log file.
    
    Args:
        message: Event message
        level: Logging level
        **kwargs: Additional event parameters
    """
    # Ensure the security log directory exists
    log_dir = "logs/security"
    os.makedirs(log_dir, exist_ok=True)
    
    # Create event dict
    event = {
        "timestamp": time.time(),
        "message": message,
        "level": logging.getLevelName(level),
    }
    event.update(kwargs)
    
    # Write to log file (append)
    log_file = f"{log_dir}/security_events.log"
    try:
        with open(log_file, "a") as f:
            f.write(json.dumps(event) + "\n")
    except Exception as e:
        logging.error(f"Failed to log security event: {e}")
        
    # Also log to main logger
    logging.log(level, f"SECURITY: {message}")


class SecurityLogger:
    """Logger specialized for security events."""
    
    def __init__(
        self, 
        log_file: str = "logs/security/security_events.log",
        console: bool = True
    ):
        """
        Initialize the security logger.
        
        Args:
            log_file: Path to log file
            console: Whether to also log to console
        """
        self.log_file = log_file
        
        # Create log directory if needed
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
            
        # Set up logging
        self.logger = logging.getLogger("security")
        self.logger.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s [SECURITY] %(levelname)s: %(message)s'
        )
        
        # Always add file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=50 * 1024 * 1024,  # 50 MB
            backupCount=10
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Add console handler if requested
        if console:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
    
    def log_event(self, event_type: str, severity: str, details: dict = None) -> None:
        """
        Log a security event.
        
        Args:
            event_type: Type of security event
            severity: Severity level (low, medium, high, critical)
            details: Additional event details
        """
        if details is None:
            details = {}
            
        # Map severity to log level
        level_map = {
            "low": logging.INFO,
            "medium": logging.WARNING,
            "high": logging.ERROR,
            "critical": logging.CRITICAL
        }
        level = level_map.get(severity.lower(), logging.WARNING)
        
        # Create structured log message
        event = {
            "timestamp": time.time(),
            "event_type": event_type,
            "severity": severity,
            "details": details
        }
        
        # Log as JSON and message
        self.logger.log(level, f"{event_type} - Severity: {severity}")
        
        # Also write structured event to log file
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logging.error(f"Failed to log security event: {e}")

"""
Configuration schema definitions with validation.
"""
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, validator


class LoggingConfig(BaseModel):
    """Logging configuration schema."""
    level: str = Field(
        default="INFO", 
        description="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)"
    )
    file: Optional[str] = Field(
        default="logs/agent.log", 
        description="Path to log file (None for console-only)"
    )
    max_size_mb: int = Field(
        default=10, 
        description="Maximum log file size in megabytes before rotation"
    )
    backup_count: int = Field(
        default=5, 
        description="Number of backup log files to keep"
    )
    security_log_file: Optional[str] = Field(
        default="logs/security.log",
        description="Path to security events log file"
    )
    
    @validator('level')
    def validate_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v.upper()


class SystemConfig(BaseModel):
    """System configuration schema."""
    name: str = Field(
        default="Autonomous Cybersecurity Defense Agent",
        description="Name of the agent instance"
    )
    health_check_interval: int = Field(
        default=120,
        description="Health check interval in seconds",
        ge=10,  # greater than or equal to 10
        le=3600  # less than or equal to 3600
    )


class NotificationConfig(BaseModel):
    """Notification configuration schema."""
    email: bool = Field(
        default=False,
        description="Enable email notifications"
    )
    email_recipients: List[str] = Field(
        default=[],
        description="List of email addresses to notify"
    )
    slack: bool = Field(
        default=False,
        description="Enable Slack notifications"
    )
    slack_webhook: Optional[str] = Field(
        default=None,
        description="Slack webhook URL for notifications"
    )
    webhook: bool = Field(
        default=False,
        description="Enable webhook notifications"
    )
    webhook_url: Optional[str] = Field(
        default=None,
        description="Webhook URL for notifications"
    )


class DetectionConfig(BaseModel):
    """Threat detection configuration schema."""
    interval: int = Field(
        default=60,
        description="Detection interval in seconds",
        ge=5,
        le=3600
    )
    enabled_modules: List[str] = Field(
        default=["network", "system", "log_analysis"],
        description="List of enabled detection modules"
    )
    thresholds: Dict[str, float] = Field(
        default={
            "network_anomaly": 0.8,
            "system_anomaly": 0.7,
            "log_anomaly": 0.75
        },
        description="Anomaly detection thresholds (0.0-1.0)"
    )


class ResponseConfig(BaseModel):
    """Incident response configuration schema."""
    auto_response: bool = Field(
        default=True,
        description="Enable automatic incident response"
    )
    max_severity: int = Field(
        default=3,
        description="Maximum severity level for auto-response (1-5)",
        ge=1,
        le=5
    )
    cooldown_period: int = Field(
        default=300,
        description="Cooldown period in seconds between similar responses",
        ge=0
    )
    notification: NotificationConfig = Field(
        default_factory=NotificationConfig,
        description="Notification settings"
    )


class AnalyticsConfig(BaseModel):
    """Analytics configuration schema."""
    interval: int = Field(
        default=300,
        description="Analytics processing interval in seconds",
        ge=60
    )
    retention_days: int = Field(
        default=30,
        description="Data retention period in days",
        ge=1
    )
    ml_enabled: bool = Field(
        default=False,
        description="Enable machine learning analytics"
    )


class AgentConfig(BaseModel):
    """Agent configuration schema."""
    system: SystemConfig = Field(
        default_factory=SystemConfig,
        description="System configuration"
    )
    detection: DetectionConfig = Field(
        default_factory=DetectionConfig,
        description="Detection configuration"
    )
    response: ResponseConfig = Field(
        default_factory=ResponseConfig,
        description="Response configuration"
    )
    analytics: AnalyticsConfig = Field(
        default_factory=AnalyticsConfig,
        description="Analytics configuration"
    )
    logging: LoggingConfig = Field(
        default_factory=LoggingConfig,
        description="Logging configuration"
    )
    profile: str = Field(
        default="default",
        description="Configuration profile name"
    )


class EnvironmentConfig(BaseModel):
    """Environment configuration schema for simulations."""
    num_hosts: int = Field(
        default=10,
        description="Number of hosts in simulated environment",
        ge=1
    )
    max_steps: int = Field(
        default=500,
        description="Maximum steps in simulation",
        ge=1
    )
    attack_probability: float = Field(
        default=0.1,
        description="Probability of attack in each step",
        ge=0.0,
        le=1.0
    )

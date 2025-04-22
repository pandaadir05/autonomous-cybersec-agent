"""
Default configuration values for the agent.
"""
from pathlib import Path

# Default agent configuration
DEFAULT_AGENT_CONFIG = {
    "system": {
        "name": "Autonomous Cybersecurity Defense Agent",
        "health_check_interval": 120,  # seconds
    },
    "detection": {
        "interval": 60,  # seconds
        "enabled_modules": ["network", "system", "log_analysis"],
        "thresholds": {
            "network_anomaly": 0.8,
            "system_anomaly": 0.7,
            "log_anomaly": 0.75
        }
    },
    "response": {
        "auto_response": True,
        "max_severity": 3,  # Maximum severity level for auto-response (1-5)
        "cooldown_period": 300,
        "notification": {
            "email": False,
            "email_recipients": [],
            "slack": False,
            "slack_webhook": None,
            "webhook": False,
            "webhook_url": None
        }
    },
    "analytics": {
        "interval": 300,  # seconds
        "retention_days": 30,
        "ml_enabled": False
    },
    "logging": {
        "level": "INFO",
        "file": "logs/agent.log",
        "max_size_mb": 10,
        "backup_count": 5,
        "security_log_file": "logs/security.log"
    },
    "profile": "default"
}

# Default simulation environment configuration
DEFAULT_ENV_CONFIG = {
    "num_hosts": 10,
    "max_steps": 500,
    "attack_probability": 0.1,
}

# Common file paths
DEFAULT_PATHS = {
    "config_file": Path("config/config.yaml"),
    "models_dir": Path("models"),
    "logs_dir": Path("logs"),
    "data_dir": Path("data")
}

# Configuration profiles
CONFIG_PROFILES = {
    "default": DEFAULT_AGENT_CONFIG,
    
    "development": {
        **DEFAULT_AGENT_CONFIG,
        "logging": {
            **DEFAULT_AGENT_CONFIG["logging"],
            "level": "DEBUG"
        }
    },
    
    "production": {
        **DEFAULT_AGENT_CONFIG,
        "detection": {
            **DEFAULT_AGENT_CONFIG["detection"],
            "interval": 30  # More frequent checks in production
        },
        "response": {
            **DEFAULT_AGENT_CONFIG["response"],
            "max_severity": 2  # More conservative auto-response in production
        }
    },
    
    "testing": {
        **DEFAULT_AGENT_CONFIG,
        "system": {
            **DEFAULT_AGENT_CONFIG["system"],
            "health_check_interval": 60
        },
        "response": {
            **DEFAULT_AGENT_CONFIG["response"],
            "auto_response": False
        }
    }
}

# Environment variable mappings (env var -> config path)
ENV_VAR_MAPPINGS = {
    "AGENT_NAME": "system.name",
    "AGENT_LOG_LEVEL": "logging.level",
    "AGENT_LOG_FILE": "logging.file",
    "AGENT_DETECTION_INTERVAL": "detection.interval",
    "AGENT_AUTO_RESPONSE": "response.auto_response",
    "AGENT_MAX_SEVERITY": "response.max_severity",
    "AGENT_EMAIL_NOTIFICATION": "response.notification.email",
    "AGENT_EMAIL_RECIPIENTS": "response.notification.email_recipients",
    "AGENT_PROFILE": "profile"
}

# 🛡️ Autonomous Cybersecurity Defense Agent

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

An intelligent agent that autonomously detects and responds to cybersecurity threats in real-time, combining traditional detection methods with machine learning.

<p align="center">
  <img src="docs/images/agent-logo.png" alt="Agent Logo" width="250"/>
</p>

## 📋 Table of Contents
- [Overview](#overview)
- [Key Features](#key-features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## 🔍 Overview

The Autonomous Cybersecurity Defense Agent is a comprehensive security solution designed to monitor, detect, and automatically respond to cyber threats with minimal human intervention. It leverages both rule-based detection and advanced machine learning to identify known and unknown threats, providing robust protection for your infrastructure.

This agent is ideal for organizations looking to strengthen their security posture while reducing the operational burden on security teams. It can operate in both autonomous and supervised modes, providing flexibility based on your security requirements.

## ✨ Key Features

### Detection Capabilities
- **Real-time network monitoring**: Deep packet inspection and traffic analysis
- **Behavioral analysis**: Detection of unusual system and user activities
- **Log analysis**: Identification of security events in system and application logs
- **Machine learning-based anomaly detection**: Identification of unknown threats using multiple algorithms
- **MITRE ATT&CK framework integration**: Detection mapped to known adversary techniques

### Response Capabilities
- **Automated threat containment**: Isolation of compromised systems
- **Connection blocking**: Prevention of malicious network traffic
- **Process termination**: Stopping of suspicious executables
- **Customizable response policies**: Tailored actions based on threat severity
- **Incident documentation**: Automatic recording of threat details and responses

### Management Features
- **Intuitive configuration system**: YAML-based configuration with validation
- **Comprehensive logging**: Detailed event tracking with rotation support
- **Notifications**: Email, Slack, and webhook integrations
- **Performance metrics**: Monitoring of agent efficiency and effectiveness
- **Interactive mode**: Command-line interface for direct control
- **Simulation mode**: Test detection and response without making system changes

## 🏗️ Architecture

The agent uses a modular architecture designed for flexibility and extensibility:

```
┌────────────────────────┐
│     Agent Core         │
└───────────┬────────────┘
            │
┌───────────┼────────────┐
│           │            │
▼           ▼            ▼
┌────────┐  ┌────────┐  ┌────────┐
│Detection│  │Response│  │Analytics│
└────┬───┘  └────┬───┘  └────┬───┘
     │           │           │
     ▼           ▼           ▼
┌──────────────────────────────┐
│            Utils             │
│ Logger, Config, Healthcheck  │
└──────────────────────────────┘
```

### Components:

- **Core**: Central orchestration and management
- **Modules**:
  - **Threat Detection**: Real-time monitoring and threat identification
  - **Response**: Automated defense mechanisms
  - **Analytics**: Data processing and insights generation
- **Utils**:
  - **Logger**: Comprehensive logging system
  - **Config**: Configuration management with validation
  - **Healthcheck**: System health monitoring

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Network access for dependency installation

### Basic Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/autonomous-cybersec-agent.git
cd autonomous-cybersec-agent
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Generate example configuration:
```bash
python -m agent.config.generate_example
```

4. Edit the configuration in `config/config.yaml` according to your needs

### Docker Installation

For containerized deployment:

```bash
# Build the Docker image
docker build -t cybersec-agent .

# Run the container
docker run -d --name cybersec-agent-instance \
  -v ./config:/app/config \
  -v ./logs:/app/logs \
  --network host \
  cybersec-agent
```

## ⚙️ Configuration

The agent uses a flexible, hierarchical configuration system with validation:

### Configuration Files

- `config/config.yaml`: Main configuration file
- `agent/config/defaults.py`: Default values
- `agent/config/schema.py`: Configuration schema with validation

### Configuration Profiles

The agent supports multiple configuration profiles for different environments:

- **default**: Standard balanced configuration
- **development**: Enhanced logging for development work
- **production**: More aggressive detection and conservative response
- **testing**: Limited response actions for testing

### Example Configuration

```yaml
# Agent configuration
agent:
  # System settings
  system:
    name: "Autonomous Cybersecurity Defense Agent"
    health_check_interval: 120  # seconds
  
  # Detection settings
  detection:
    interval: 60  # seconds
    enabled_modules:
      - network
      - system
      - log_analysis
    thresholds:
      network_anomaly: 0.8  # 0.0-1.0
      system_anomaly: 0.7   # 0.0-1.0
  
  # Response settings
  response:
    auto_response: true
    max_severity: 3  # 1-5
    cooldown_period: 300  # seconds
    notification:
      email: true
      email_recipients:
        - "admin@example.com"
  
  # Logging settings
  logging:
    level: "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    file: "logs/agent.log"
    
  # Select configuration profile
  profile: "default"
```

### Environment Variables

Configuration can be overridden using environment variables:

```bash
# Example environment variable overrides
export AGENT_NAME="Production Security Agent"
export AGENT_LOG_LEVEL="DEBUG"
export AGENT_AUTO_RESPONSE=true
export AGENT_PROFILE="production"
```

## 🚀 Usage

### Basic Usage

Run the agent with the default configuration:

```bash
python run_agent.py
```

### Command-line Options

```bash
python run_agent.py --help
```

Available options:
- `--config PATH`: Specify configuration file path
- `--verbose`: Enable verbose logging
- `--simulate`: Run in simulation mode without making system changes
- `--interactive`: Run in interactive mode with command shell
- `--profile NAME`: Use specific configuration profile

### Interactive Mode

In interactive mode, the agent provides a command-line interface:

```bash
> help
Available commands:
  status - Show agent status and statistics
  scan - Run manual threat scan
  block [IP] - Block IP address
  unblock [IP] - Unblock IP address
  reports - Show recent threat reports
  exit - Exit interactive mode
```

### API Usage

The agent can be integrated into other Python applications:

```python
from agent.core import DefenseAgent
from agent.config import init_config, get_agent_config

# Initialize configuration
config_manager = init_config("config/custom_config.yaml")
config = get_agent_config()

# Create agent instance
agent = DefenseAgent(config=config, simulation_mode=True)

# Start the agent
agent.start()

# Perform manual scan
threats = agent.scan()
print(f"Detected {len(threats)} potential threats")

# Clean shutdown
agent.shutdown()
```

## 🛠️ Development

### Project Structure

```
autonomous-cybersec-agent/
├── agent/                  # Core agent functionality
│   ├── core/               # Core agent components
│   ├── modules/            # Functional modules
│   └── utils/              # Utility functions and classes
├── src/                    # Source code for models and environments
│   ├── models/             # ML and detection models
│   ├── environments/       # Simulation environments
│   └── utils/              # Additional utilities
├── config/                 # Configuration files
├── logs/                   # Log files
├── tests/                  # Test suite
├── docs/                   # Documentation
└── README.md               # This file
```

### Running Tests

```bash
pytest tests/
```

### Code Style

This project follows the PEP 8 style guide and uses Black for formatting:

```bash
black agent/ src/ tests/
```

## 👥 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

### Development Process

1. Fork the repository
2. Create a feature branch
3. Add your changes
4. Run tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

© 2023 Autonomous Cybersecurity Defense Agent Team


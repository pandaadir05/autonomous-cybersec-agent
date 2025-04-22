# 🛡️ Lesh: Autonomous Cybersecurity Defense Agent

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

An intelligent security solution that autonomously detects and responds to cybersecurity threats in real-time, combining traditional rule-based detection methods with advanced machine learning algorithms.

<p align="center">
  <img src="docs/images/lesh-logo.png" alt="Lesh Logo" width="250"/>
</p>

## 📋 Table of Contents
- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start Guide](#-quick-start-guide)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [API Reference](#-api-reference)
- [Machine Learning Components](#-machine-learning-components)
- [Development](#-development)
- [Contributing](#-contributing)
- [License](#-license)
- [Troubleshooting](#-troubleshooting)

## 🔍 Overview

Lesh is a comprehensive security solution designed to monitor, detect, and automatically respond to cyber threats with minimal human intervention. It leverages both rule-based detection and advanced machine learning to identify known and unknown threats, providing robust protection for your infrastructure.

The agent continuously monitors network traffic, system behavior, and log files to detect suspicious activities. When threats are identified, it can automatically respond with appropriate actions based on your configuration, from blocking connections to isolating systems and sending notifications.

This agent is ideal for organizations looking to:
- Strengthen their security posture
- Reduce the operational burden on security teams
- Gain visibility into security threats
- Implement automated incident response
- Integrate security controls across systems

## ✨ Key Features

### Detection Capabilities
- **Real-time network monitoring**: Deep packet inspection and traffic analysis
- **Behavioral analysis**: Detection of unusual system and user activities
- **Log analysis**: Identification of security events in system and application logs
- **Machine learning-based anomaly detection**: Identification of unknown threats using multiple algorithms:
  - Autoencoder neural networks
  - Isolation Forest
  - Local Outlier Factor (LOF)
  - DBSCAN clustering
  - One-Class SVM
- **MITRE ATT&CK framework integration**: Detection mapped to known adversary techniques

### Response Capabilities
- **Automated threat containment**: Isolation of compromised systems
- **Connection blocking**: Prevention of malicious network traffic
- **Process termination**: Stopping of suspicious executables
- **Customizable response policies**: Tailored actions based on threat severity
- **Incident documentation**: Automatic recording of threat details and responses
- **Simulation mode**: Test detection and response without making actual system changes

### Management Features
- **Intuitive configuration system**: YAML-based configuration with validation
- **Comprehensive logging**: Detailed event tracking with rotation support
- **Notifications**: Email, Slack, and webhook integrations
- **Performance metrics**: Monitoring of agent efficiency and effectiveness
- **Interactive mode**: Command-line interface for direct control
- **Web API**: REST interface for integration with other security tools

## 🏗️ Architecture

Lesh uses a modular architecture designed for flexibility and extensibility:

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
  - Agent lifecycle management
  - Component coordination
  - State management
  
- **Modules**:
  - **Threat Detection**: Real-time monitoring and threat identification
    - Network traffic analysis
    - System activity monitoring
    - Log file scanning
    - Anomaly detection models
  
  - **Response**: Automated defense mechanisms
    - Network blocking (IP, port, protocol)
    - Process management (termination, isolation)
    - User account management
    - System isolation
    - Notifications (email, Slack, webhooks)
  
  - **Analytics**: Data processing and insights generation
    - Traffic pattern analysis
    - Threat intelligence correlation
    - Performance metrics
    - Visualization tools
    - Threat hunting support
  
- **Utils**:
  - **Logger**: Comprehensive logging system with rotation
  - **Config**: Configuration management with validation
  - **Healthcheck**: System health monitoring

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Network access for dependency installation
- Sufficient privileges for security monitoring (varies by OS)

### Basic Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/lesh.git
cd lesh
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
docker build -t lesh-agent .

# Run the container
docker run -d --name lesh-agent-instance \
  -v ./config:/app/config \
  -v ./logs:/app/logs \
  --network host \
  lesh-agent
```

### System Requirements

- **Minimum**: 2 CPU cores, 4GB RAM, 20GB disk space
- **Recommended**: 4+ CPU cores, 8GB+ RAM, 50GB+ disk space
- **Network**: Access to monitored interfaces
- **Permissions**: Administrative/root for certain detection & response capabilities

## 🚀 Quick Start Guide

Get up and running with Lesh in minutes:

1. **Install dependencies**:
```bash
pip install -r requirements.txt
```

2. **Set up configuration**:
```bash
# Copy example config file
cp config/example_config.yaml config/config.yaml
```

3. **Start the agent in development mode**:
```bash
python run_agent.py --profile development --simulate
```

4. **Access the interactive console**:
```bash
python run_agent.py --interactive
```

5. **Start the API server**:
```bash
python -m src.api.server
```

## ⚙️ Configuration

Lesh uses a flexible, hierarchical configuration system with validation:

### Configuration Files

- `config/config.yaml`: Main configuration file
- `config/profiles/*.yaml`: Environment-specific configuration profiles
- `agent/config/defaults.py`: Default values
- `agent/config/schema.py`: Configuration schema with validation

### Configuration Profiles

The agent supports multiple configuration profiles for different environments:

- **default**: Standard balanced configuration
- **development**: Enhanced logging for development work
- **production**: More aggressive detection and conservative response
- **testing**: Limited response actions for testing

To specify a profile:
```bash
python run_agent.py --profile development
```

### Example Configuration

```yaml
# Agent configuration
agent:
  # System settings
  system:
    name: "Lesh: Autonomous Cybersecurity Defense Agent"
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
export LESH_AGENT_NAME="Production Security Agent"
export LESH_LOG_LEVEL="DEBUG"
export LESH_AUTO_RESPONSE=true
export LESH_PROFILE="production"
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

In interactive mode, Lesh provides a command-line interface:

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

## 📡 API Reference

Lesh provides a REST API for integration with other tools and systems.

### Starting the API Server

```bash
python -m src.api.server
```

By default, the API server runs on `http://localhost:8000`.

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API information and status |
| `/detect` | POST | Submit traffic data for anomaly detection |
| `/explain` | POST | Get explanations for detected anomalies |
| `/status` | GET | Get agent status information |
| `/metrics` | GET | Get performance metrics |

### Example API Request

```bash
curl -X POST \
  http://localhost:8000/detect \
  -H 'Content-Type: application/json' \
  -d '{
    "host_features": {"ip": "192.168.1.5", "port": 443},
    "flow_features": {"bytes": 1528, "packets": 4},
    "packet_features": {"tcp_flags": 16, "protocol": 6}
  }'
```

## 🧠 Machine Learning Components

Lesh uses multiple machine learning techniques for anomaly detection:

### Available Models

1. **Autoencoder Neural Networks**
   - Reconstructs normal traffic and identifies anomalies by reconstruction error
   - Effective for complex patterns and high-dimensional data

2. **Isolation Forest**
   - Fast anomaly detection based on decision tree isolation
   - Requires minimal preprocessing and works well with medium-sized datasets

3. **Local Outlier Factor (LOF)**
   - Identifies anomalies based on local density deviations
   - Effective for clustered data with varying densities

4. **DBSCAN**
   - Density-based spatial clustering for anomaly detection
   - Separates normal behavior from outliers

5. **One-Class SVM**
   - Support Vector Machine for novelty detection
   - Creates a boundary around normal data

### Training the Models

To train the machine learning models:

```bash
python train.py
```

This will:
1. Create a simulated network environment
2. Generate training data with normal and anomalous traffic
3. Train each model type on this data
4. Save the trained models to the `models/` directory

### Customizing Model Parameters

Advanced users can adjust model parameters in `config/ml_config.yaml`:

```yaml
anomaly_detection:
  methods:
    - autoencoder
    - isolation_forest
    - lof
  autoencoder:
    encoding_dims: [64, 32, 16]
    learning_rate: 0.001
    epochs: 50
  isolation_forest:
    n_estimators: 100
    contamination: 0.1
```

## 🛠️ Development

### Project Structure

```
lesh/
├── agent/                  # Core agent functionality
│   ├── core/               # Core agent components
│   ├── modules/            # Functional modules
│   └── utils/              # Utility functions and classes
├── src/                    # Source code for models and environments
│   ├── models/             # ML and detection models
│   ├── environments/       # Simulation environments
│   ├── api/                # API server implementation
│   └── utils/              # Additional utilities
├── config/                 # Configuration files
│   ├── profiles/           # Environment-specific configs
│   └── example_config.yaml # Example configuration
├── logs/                   # Log files
├── models/                 # Saved ML models
├── data/                   # Data storage
│   ├── analytics/          # Analytics results
│   └── visualizations/     # Generated visualizations
├── tests/                  # Test suite
├── docs/                   # Documentation
│   ├── images/             # Documentation images including logo
└── README.md               # This file
```

### Development Environment Setup

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows
venv\Scripts\activate
# On Unix/MacOS
source venv/bin/activate

# Install dependencies including development packages
pip install -r requirements-dev.txt
```

### Running Tests

```bash
pytest tests/
```

For coverage report:
```bash
pytest --cov=agent --cov=src tests/
```

### Code Style

This project follows the PEP 8 style guide and uses Black for formatting:

```bash
black agent/ src/ tests/
```

### Building Documentation

```bash
cd docs
sphinx-build -b html . _build/html
```

## 👥 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

### Development Process

1. Fork the repository
2. Create a feature branch
3. Add your changes
4. Run tests
5. Submit a pull request

### Feature Requests and Bug Reports

Please use the GitHub issue tracker to submit feature requests and report bugs.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ❓ Troubleshooting

### Common Issues

1. **Import errors**: Make sure all dependencies are installed with `pip install -r requirements.txt`

2. **Permission issues**: Some detection and response capabilities require administrative privileges

3. **Configuration errors**: Check for syntax errors in your YAML configuration

4. **Model loading errors**: Ensure models are trained before trying to load them

### Logging

For detailed logs, increase the log level:

```yaml
# In config.yaml
logging:
  level: "DEBUG"
```

Or use the command line:
```bash
python run_agent.py --verbose
```

### Getting Help

- Check the [documentation](docs/)
- Open an issue on GitHub
- Contact the maintainers

---

© 2023 Lesh: Autonomous Cybersecurity Defense Agent


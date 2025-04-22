# 🛡️ Lesh: Autonomous Cybersecurity Defense Agent

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![Code Style: Black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

An intelligent security solution that autonomously detects and responds to cybersecurity threats in real-time, combining traditional rule-based detection methods with advanced machine learning algorithms.

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Installation](#-installation)
- [Quick Start Guide](#-quick-start-guide)
- [Configuration](#-configuration)
- [Detection Modules](#-detection-modules)
- [Dashboard](#-dashboard)
- [Machine Learning Models](#-machine-learning-models)
- [API Reference](#-api-reference)
- [Development](#-development)
- [Testing](#-testing)
- [License](#-license)
- [Troubleshooting](#-troubleshooting)

## 🔍 Overview

Lesh is a comprehensive security solution designed to monitor, detect, and automatically respond to cyber threats with minimal human intervention. It leverages both rule-based detection and advanced machine learning to identify known and unknown threats, providing robust protection for your infrastructure.

## ✨ Key Features

### Detection Capabilities

- **Network Anomaly Detection**: Identifies unusual patterns in network traffic
- **Malware Detection**: Scans for malicious software and suspicious behaviors
- **Compliance Checking**: Ensures system configurations adhere to security best practices
- **Machine Learning-based Detection**: Uses isolation forest algorithm for anomaly detection

### Response Capabilities

- **Automated threat containment**: Isolation of compromised systems
- **Connection blocking**: Prevention of malicious network traffic
- **Process termination**: Stopping of suspicious executables
- **Notification systems**: Email alerts for security incidents

### Visualization & Monitoring

- **Interactive Dashboard**: Real-time monitoring of security events
- **System Health Monitoring**: Track system resource usage
- **Security Events Timeline**: Chronological view of detected threats
- **Severity Distribution**: Visual breakdown of threat severity

## 📦 Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Basic Installation

```bash
# Clone the repository
git clone https://github.com/your-username/autonomous-cybersec-agent.git
cd autonomous-cybersec-agent

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

## 🚀 Quick Start Guide

1. **Run the complete agent with dashboard and API**:

```bash
python run.py --all
```

2. **Run only specific components**:

```bash
# Run only the dashboard
python run.py --dashboard

# Run only the API server
python run.py --api

# Run only the security agent
python run.py --agent
```

3. **Access the dashboard**:

Open your web browser and navigate to: `http://localhost:8050`

## 🔎 Detection Modules

The agent includes several detection modules:

### Network Anomaly Detection

Monitors network traffic for unusual patterns such as:
- Connection count spikes
- Bandwidth usage anomalies
- Packet rate anomalies

### Malware Detection

Scans for malicious software by:
- Checking file hashes against known malware signatures
- Analyzing file contents for suspicious patterns
- Focusing on potentially dangerous file types

### Compliance Checking

Ensures system configuration meets security best practices:
- Password policy compliance
- Firewall configuration
- System update settings
- Running services audit

## 📊 Dashboard

The dashboard provides real-time monitoring and visualization:

- **Active Threats Counter**: Number of current high-severity threats
- **Events Today**: Count of security events in the past 24 hours
- **System Health**: Overall status based on system metrics
- **Security Events Timeline**: Chronological view of detected threats
- **Event Severity Distribution**: Breakdown of threats by severity level
- **System Metrics**: CPU, memory, disk usage, and network traffic

To access the dashboard, run:

```bash
python run.py --dashboard
```

# 🛡️ LESH: Advanced Cybersecurity Dashboard

## 📊 Enhanced Cybersecurity Dashboard

The new dashboard provides real-time monitoring with advanced visualization capabilities:

- **Interactive Security Visualizations**: Dynamic threat maps, timelines, and 3D visualizations
- **Real-time Metrics**: Active threats, system health, and security event tracking  
- **Multi-tab Interface**: Organize security data into Overview, Network, System, Alerts and Advanced tabs
- **Advanced Analytics**: AI-powered threat analysis and predictive metrics

### Running the Dashboard

To run the dashboard:

```bash
# Install required dependencies first
pip install -r requirements.txt

# Start the dashboard
python run.py --dashboard

# Or run all components together
python run.py --all
```

Then open your web browser and navigate to: `http://localhost:8050`

### Dashboard Features

1. **Security Status Monitoring**: Real-time status indicators show current threat levels
2. **Threat Analysis**: View detailed breakdowns of security events by severity and type
3. **Network Visualization**: Interactive network topology map showing attack patterns
4. **System Health**: Monitor system resource usage and health metrics
5. **Alert Management**: Filter and review security alerts by severity
6. **Advanced 3D Visualization**: Explore the threat landscape in 3D with the advanced view

### Dashboard Screenshots

![Dashboard Overview](assets/dashboard_overview.png)

## 🧠 Machine Learning Models

The agent uses machine learning for advanced threat detection:

### Available Models

- **Anomaly Detector**: Identifies unusual network traffic patterns
- **Threat Classifier**: Categorizes detected anomalies by threat type
- **Behavior Analyzer**: Tracks and flags unusual system behavior

### Training the Models

To train the machine learning models:

```bash
python train_models.py
```

To train with custom data:

```bash
python train_models.py --data your_data.csv
```

### Customizing Model Parameters

Edit the ML configuration file:

```bash
nano config/ml_models.json
```

## 📡 API Reference

The agent provides a REST API for integration with other tools.

### Starting the API Server

```bash
python run.py --api
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API information and status |
| `/detect` | POST | Submit traffic data for anomaly detection |
| `/explain` | POST | Get explanations for detected anomalies |
| `/status` | GET | Get agent status information |

## 🧪 Testing

Run the test suite to ensure everything is working:

```bash
pytest tests/
```

For specific test files:

```bash
pytest tests/test_anomaly_detector.py
pytest tests/test_email_notifications.py
pytest tests/test_dashboard.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ❓ Troubleshooting

### Common Issues

1. **Import errors**: Make sure all dependencies are installed with `pip install -r requirements.txt`
2. **Permission issues**: Some detection and response capabilities require administrative privileges
3. **Dashboard not loading**: Check if the correct port (8050) is available
4. **ML models not working**: Ensure models are trained before trying to use them

### Getting Help

If you encounter any problems, please open an issue on the GitHub repository.

---


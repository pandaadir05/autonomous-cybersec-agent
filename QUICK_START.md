# Lesh: Quick Start Guide

This guide provides simple steps to get the Lesh Autonomous Cybersecurity Defense Agent up and running.

## 1. Setup

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. **Create a virtual environment**:
   ```bash
   python -m venv venv
   ```

2. **Activate the virtual environment**:
   - Windows:
     ```
     venv\Scripts\activate
     ```
   - Linux/Mac:
     ```
     source venv/bin/activate
     ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## 2. Running the Agent

### Basic Run
To run the agent with default settings:
```bash
python run_agent.py
```

### Development/Testing Mode
To run in simulation mode (won't make actual changes):
```bash
python run_agent.py --simulate --profile development
```

### Interactive Mode
To run with an interactive command line:
```bash
python run_agent.py --interactive
```

## 3. Key Commands

When running in interactive mode, you can use these commands:

- `status` - Show the agent's current status
- `scan` - Run a manual threat scan
- `block [IP]` - Block an IP address
- `reports` - View recent threat reports
- `exit` - Exit the interactive mode

## 4. Configuration

Edit the configuration file in `config/config.yaml` to adjust:
- Detection settings
- Response actions
- Notification methods
- API settings

## 5. Next Steps

- Explore the complete documentation in the README.md
- Configure detection thresholds in the config file
- Set up notification methods for alerts

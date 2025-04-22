#!/bin/bash
# Script to run different components for testing

echo "=== AUTONOMOUS CYBERSECURITY AGENT TESTING ==="
echo ""

# Setup environment
echo "Setting up environment..."
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python -m venv venv
fi

# Activate virtual environment
source venv/bin/activate || source venv/Scripts/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

# Environment variable for OpenAI API
if [ -z "$OPENAI_API_KEY" ]; then
    echo "OPENAI_API_KEY not set. LLM features will be disabled."
    echo "You can set it with: export OPENAI_API_KEY=your-key-here"
else
    echo "OPENAI_API_KEY is set. LLM features will be available."
fi

echo ""
echo "=== AVAILABLE TESTS ==="
echo "1. Run ML & LLM integration test"
echo "2. Run anomaly detector test"
echo "3. Run dashboard"
echo "4. Train ML models"
echo "5. Run full agent (detection + response)"
echo "q. Quit"

read -p "Enter your choice: " choice

case $choice in
    1)
        echo "Running ML & LLM integration test..."
        python test_ml_llm_integration.py
        ;;
    2)
        echo "Running anomaly detector test..."
        python -m tests.test_anomaly_detector
        ;;
    3)
        echo "Starting dashboard..."
        python run.py --dashboard
        ;;
    4)
        echo "Training ML models..."
        python train_models.py
        ;;
    5)
        echo "Running full agent..."
        python run.py --all
        ;;
    q|Q)
        echo "Exiting..."
        ;;
    *)
        echo "Invalid option"
        ;;
esac

echo ""
echo "Done."

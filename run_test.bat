@echo off
REM Script to run different components for testing

echo === AUTONOMOUS CYBERSECURITY AGENT TESTING ===
echo.

REM We're already in the virtual environment, so skip activation

echo.
echo === AVAILABLE TESTS ===
echo 1. Run ML ^& LLM integration test
echo 2. Run anomaly detector test
echo 3. Run dashboard
echo 4. Train ML models
echo 5. Run full agent (detection + response)
echo q. Quit

set /p choice="Enter your choice: "

if "%choice%"=="1" (
    echo Running ML ^& LLM integration test...
    python test_ml_llm_integration.py
) else if "%choice%"=="2" (
    echo Running anomaly detector test...
    python -m tests.test_anomaly_detector
) else if "%choice%"=="3" (
    echo Starting dashboard...
    python run.py --dashboard
) else if "%choice%"=="4" (
    echo Training ML models...
    python train_models.py
) else if "%choice%"=="5" (
    echo Running full agent...
    python run.py --all
) else if "%choice%"=="q" (
    echo Exiting...
) else (
    echo Invalid option
)

echo.
echo Done.
pause

@echo off
echo ============================================
echo  Parabellum IO - NIST CSF RAG Service
echo  Listening on http://localhost:5000
echo ============================================

:: Change to the rag-service directory
cd /d "%~dp0"

:: Check Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Please install Python 3.10+
    pause
    exit /b 1
)

:: Install dependencies if not already installed
echo [1/2] Installing dependencies...
pip install -r requirements.txt

:: Start the service
echo [2/2] Starting RAG service on port 5000...
python app.py

pause

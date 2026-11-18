@echo off
title PHISH-SHIELD SOC Tier-1 Threat Analyzer
echo ======================================================================
echo    Starting PHISH-SHIELD: SOC Tier-1 Threat Analyzer
echo ======================================================================
echo.

if exist ".venv\Scripts\python.exe" (
    echo [OK] Using virtual environment Python: .venv\Scripts\python.exe
    echo [INFO] Starting Uvicorn Web Server at http://127.0.0.1:8000
    echo [INFO] Press Ctrl+C to stop the server
    echo.
    start http://127.0.0.1:8000
    ".venv\Scripts\python.exe" -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
) else (
    echo [WARN] .venv\Scripts\python.exe not found. Trying system python...
    start http://127.0.0.1:8000
    python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
)

pause

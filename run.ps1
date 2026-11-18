# PHISH-SHIELD SOC Tier-1 Threat Analyzer Launcher
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "   Starting PHISH-SHIELD: SOC Tier-1 Threat Analyzer Dashboard" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

$venvPython = ".\.venv\Scripts\python.exe"

if (Test-Path $venvPython) {
    Write-Host "[OK] Using virtual environment Python: $venvPython" -ForegroundColor Green
    Write-Host "[INFO] Opening browser at http://127.0.0.1:8000" -ForegroundColor Yellow
    Start-Process "http://127.0.0.1:8000"
    Write-Host "[INFO] Server running on http://127.0.0.1:8000 (Press Ctrl+C to stop)`n" -ForegroundColor Cyan
    & $venvPython -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
} else {
    Write-Host "[WARN] .venv python not found. Trying default python in PATH..." -ForegroundColor Yellow
    Start-Process "http://127.0.0.1:8000"
    python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
}

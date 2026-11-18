# Phishing & Malicious URL Threat Analyzer

A local SOC Tier-1 triage application for analysing URLs and email messages. It combines URL heuristics, safe network inspection, DNS/WHOIS fallback data, email-header checks, MITRE ATT&CK mapping, explainable risk scoring, and SQLite history.

## Features

- Lexical URL analysis and brand/IDN/Punycode indicators
- Safe network and page inspection
- DNS and WHOIS intelligence with offline demo fallback
- Email header and attachment analysis
- 0-100 threat score with indicator breakdown
- MITRE ATT&CK technique mapping
- Defanged IOC export and JSON reports
- SOC-style dark web dashboard

## Project Structure

```text
project/
├── backend/
│   ├── main.py
│   ├── models.py
│   ├── database.py
│   └── analyzer/
├── frontend/
│   └── index.html
├── samples/
├── requirements.txt
└── README.md
```

## Setup and Run

Run these commands from the project root: the folder containing `backend/`, `frontend/`, `samples/`, and `requirements.txt`.

### Prerequisites

- Windows 10 or later
- Python 3.11 or newer

### 1. Create a virtual environment

```powershell
py -3.13 -m venv .venv
.venv\Scripts\Activate.ps1
```

If `py` is unavailable, use:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use Command Prompt instead:

```bat
.venv\Scripts\activate.bat
```

### 2. Install dependencies

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Start the server

With the virtual environment activated:

```powershell
python -m uvicorn backend.main:app --reload --port 8000
```

Alternatively, without activating the environment:

```powershell
py -3.13 -m uvicorn backend.main:app --reload --port 8000
```

Then open:

- Dashboard: <http://localhost:8000/>
- API documentation: <http://localhost:8000/docs>
- Health check: <http://localhost:8000/health>

## Verify the Installation

In another PowerShell terminal:

```powershell
Invoke-RestMethod http://localhost:8000/health
```

The response should contain `"status": "healthy"`.

## Demo Samples

The `samples/` directory contains ready-to-use test artefacts:

| Sample | Purpose |
|---|---|
| `legitimate_invoice.eml` | Normal business email that should be assessed as safe |
| `phishing_credential.eml` | Credential-harvesting phishing email |
| `punycode_url.txt` | Punycode/IDN look-alike URL |
| `ip_payload_url.txt` | Direct IP-hosted payload URL |

The dashboard includes demo-loading controls for the URL and email samples.

## Scoring

The engine sums unique indicator weights, caps the total at 100, and reports:

- `0-29`: SAFE
- `30-69`: SUSPICIOUS
- `70-100`: HIGH RISK / PHISHING

Every JSON report includes a `score_breakdown` array explaining triggered indicators and their weights.

## API

Main endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/health` | Service health |
| `GET` | `/` | Dashboard |
| `POST` | `/analyze/url` | Analyse a URL |
| `POST` | `/analyze/email/raw` | Analyse raw email text |
| `POST` | `/analyze/email/upload` | Upload an `.eml` file |
| `GET` | `/history` | Retrieve saved analyses |
| `GET` | `/report/{case_id}` | Retrieve a JSON report |

## Safe-Handling Notes

- Analysis runs locally and does not store passwords or private keys.
- HTML is parsed with BeautifulSoup; scripts are not executed.
- Submitted IOCs are defanged before display or export.
- Use this tool only with URLs and email samples you own or are authorised to analyse.

# Phishing & Malicious URL Threat Analyzer (SOC Tier‑1 Triage Tool)

## Overview
A lightweight, locally‑runnable **SOC Tier‑1 triage** application that analyses URLs and email messages for phishing, malicious infrastructure, and credential‑harvesting indicators.  It combines:
- **Lexical & heuristic URL analysis** (entropy, IP host, excessive sub‑domains, Punycode, brand‑typosquatting, risky TLDs, etc.)
- **Safe network inspection** (redirect chain, TLS certificate metadata, static HTML parsing for credential‑harvesting forms)
- **WHOIS & DNS intelligence** with graceful offline fall‑back for demo environments
- **Email header parsing** (spoofing checks, SPF/DKIM/DMARC verdicts, hop chain, attachment inspection)
- **Explainable risk scoring** (0‑100) with per‑indicator weight breakdown
- **MITRE ATT&CK mapping** and **defanged IOC export**
- **SQLite persistence** for analysis history & IOC aggregation
- **SOC‑styled dark‑mode web UI** built with Tailwind CSS and vanilla JavaScript.

The tool is designed for a cybersecurity internship evaluation – it runs entirely on the local machine, requires no external services, and ships with synthetic demo samples that work **offline**.

---

## Project Structure
```
project/
│
├─ backend/                     # FastAPI server and analysis engine
│   ├─ __init__.py
│   ├─ main.py                  # API entry point, static mounting, DB init
│   ├─ models.py                # Pydantic request/response schemas
│   ├─ database.py              # SQLite helper & schema
│   └─ analyzer/                # Core modules
│        ├─ lexical.py          # URL lexical/heuristic engine
│        ├─ network_inspector.py# Safe network & page inspection
│        ├─ whois_dns.py        # WHOIS & DNS with offline cache
│        ├─ email_parser.py     # .eml parsing & indicator extraction
│        ├─ mitre_mapper.py     # ATT&CK mapping logic
│        ├─ scoring.py          # Explainable scoring & playbook actions
│        └─ defanger.py         # Defanging utilities & report helpers
│
├─ frontend/                    # Static HTML UI (Tailwind CDN)
│   └─ index.html
│
├─ samples/                     # Synthetic demo artefacts
│   ├─ legitimate_invoice.eml
│   ├─ phishing_credential.eml
│   ├─ punycode_url.txt          # https://xn--paypl-qqa.com/login
│   └─ ip_payload_url.txt        # http://198.51.100.42/invoice.iso
│
├─ requirements.txt            # Python dependencies
└─ README.md                   # ← you are reading this!
```

---

## Setup & Run
1. **Prerequisites** – Python 3.11+ (Windows).  No internet connection is required after the initial package install.
2. **Create a virtual environment**
   ```powershell
   python -m venv .venv
   .venv\Scripts\activate
   ```
3. **Install dependencies** (the first time you run this, the sandbox will need network access to download wheels).  After the initial install you can run the tool completely offline.
   ```powershell
   pip install -r requirements.txt
   ```
4. **Start the server**
   ```powershell
   uvicorn backend.main:app --reload --port 8000
   ```
   The API will be reachable at `http://localhost:8000` and the UI at `http://localhost:8000/static/index.html` (or simply `http://localhost:8000` – FastAPI serves the static folder as the root).
5. **Open the dashboard** in a browser and begin triaging!

---

## Scoring Methodology
| Category | Example Indicator | Weight (points) |
|----------|------------------|-----------------|
| Lexical | High Shannon entropy in sub‑domain | 20 |
| Lexical | Raw IP address as host | 25 |
| Lexical | Credential‑masking `@` in URL | 25 |
| Lexical | High‑risk TLD (`.xyz`, `.tk`, …) | 20 |
| Lexical | Punycode / IDN homograph | 25‑30 |
| Lexical | Brand‑typosquatting (Levenshtein ≤2) | 25 |
| Infrastructure | WHOIS < 30‑day domain age (NRD) | 25 |
| DNS | Missing MX records (suspicious mail) | 5‑10 |
| SSL/TLS | Self‑signed or CN/SAN mismatch | 20‑25 |
| Page Content | Credential‑harvesting form posting externally | 35 |
| Page Content | Brand‑masquerading in `<title>` | 25 |
| Email | SPF/DKIM/DMARC **fail** | 20‑25 each |
| Email | From / Reply‑To / Return‑Path domain mismatch | 15‑20 |
| Email | Dangerous attachment type (`.exe`, `.iso`, `.lnk`, …) | 15‑25 |
| Network | > 3 redirects (cloaking) | 15 |
| Security Guard | SSRF‑blocked private IP | 10 |

The engine sums the unique indicator weights, caps the total at 100, and classifies:
- **0‑29** → `SAFE`
- **30‑69** → `SUSPICIOUS`
- **70‑100** → `HIGH RISK / PHISHING`

The final JSON report includes a **`score_breakdown`** array that lists every triggered heuristic with its point value, enabling analysts to see *exactly why* the score was assigned.

---

## MITRE ATT&CK Mapping
Detected indicators are automatically mapped to relevant ATT&CK techniques (see `backend/analyzer/mitre_mapper.py`).  Example mappings:
- **T1566.001** – Spearphishing Attachment (malicious `.exe` attachment)
- **T1566.002** – Spearphishing Link (phishing URL, high‑risk TLD)
- **T1583.001** – Acquire Infrastructure: Domains (newly‑registered domain)
- **T1036** – Masquerading (brand‑typosquatting, page title spoofing)
- **T1056.003** – Input Capture: Web Portal Capture (credential‑harvesting form)
- **T1204.001** – User Execution: Malicious Link
- **T1204.002** – User Execution: Malicious File
- **T1586.002** – Compromise Accounts: Email Accounts (spoofed `From`/`Return‑Path`)
- **T1598** – Phishing for Information

The JSON report contains a `mitre_mapping` array with technique IDs, names, tactics, URLs, and the specific heuristic that triggered each mapping.

---

## Defanged IOC Export & Reporting
The UI offers a **“Copy IOCs”** button that copies a newline‑delimited blocklist of defanged indicators (e.g. `hxxps://micros0ft-login[.]xyz`).  A **downloadable JSON** report (`/report/{case_id}`) can be saved or printed to PDF via the browser’s print dialog.

---

## Demo Samples & One‑Click Loading
The `samples/` folder ships four ready‑to‑use artefacts:
| Sample | Description |
|--------|------------|
| `legitimate_invoice.eml` | A normal business invoice email with a PDF attachment – should score **SAFE**. |
| `phishing_credential.eml` | Credential‑harvesting phishing email (failed SPF/DKIM/DMARC, malicious `.exe` attachment, look‑alike domain). |
| `punycode_url.txt` | URL using Punycode (`https://xn--paypl-qqa.com/login`). |
| `ip_payload_url.txt` | Direct IP‑hosted payload (`http://198.51.100.42/invoice.iso`). |

The dashboard UI provides **“Load Demo URL”** and **“Load Demo Email”** buttons that automatically populate the input fields with these samples, allowing a smooth live demo without any typing.

---

## Ethical & Safe‑Handling Notes
- **Offline‑first** – All analysis functions have an offline cache (`OFFLINE_DEMO_INTELLIGENCE`) that returns realistic WHOIS/DNS data for the synthetic domains.  This ensures the tool never crashes or leaks network traffic during a presentation.
- **No JavaScript execution** – HTML pages are parsed with BeautifulSoup only; no scripts are ever executed.
- **Defanged output** – All IOCs are automatically defanged (`hxxp://`, `[.]` for dots) to prevent accidental clicks.
- **No credential storage** – The tool never stores passwords or private keys; only hashes of attachment files are recorded for deduplication.
- **Legal use** – Use this tool only on URLs/email samples that you own or have explicit permission to analyse.

---

## 3‑Minute Live Demo Walkthrough (for evaluators)
1. **Open the UI** – `http://localhost:8000`.
2. Click **“Load Demo URL”** – the punycode URL auto‑fills.
3. Press **“Analyze URL”** – observe the JSON report showing:
   - High entropy, Punycode, risky TLD → strong lexical flags.
   - WHOIS indicates a 12‑day‑old domain (NRD). 
   - MITRE mapping to `T1583.001` and `T1566.002`.
4. Click **“Copy IOCs”** – the defanged URL appears on the clipboard.
5. Switch to the **Email tab**, click **“Load Demo Email”**, then **“Analyze Email”**.
6. The report now highlights:
   - SPF/DKIM/DMARC failures (weight 20 each).
   - Dangerous `.exe` attachment (weight 25).
   - Brand‑masquerading in the HTML body.
   - A final **HIGH RISK / PHISHING** verdict with playbook actions (block, purge, reset passwords).
7. Hit **“Refresh”** under **Analysis History** – both cases appear with a “View” link that opens the full JSON report.
8. Optionally click **“Download”** on the report page (browser → Save As) and print to PDF for documentation.

The demo showcases the end‑to‑end workflow: ingestion → automated heuristic scoring → MITRE mapping → actionable Tier‑1 playbook recommendations.

---

## Extending the Tool
- **Add new heuristics** – modify `backend/analyzer/lexical.py` and adjust weights in `scoring.py`.
- **Plug in external threat intel** – extend `whois_dns.py` with VirusTotal or Passive DNS look‑ups (requires network & API key).
- **Custom UI components** – place additional panels in `frontend/` and expose new FastAPI routes.

---

## License
MIT – feel free to fork, improve, and reuse for internal SOC tooling.

---

*Happy hunting!*#   S e c u r e P a s s X  
 
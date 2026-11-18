"""
FastAPI application entry point for the Phishing & Malicious URL Threat Analyzer.
Exposes endpoints for URL analysis, email analysis (.eml upload & raw text), and history retrieval.
"""
import uuid
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from backend.models import URLAnalysisRequest, EmailAnalysisRequest, AnalysisReportModel
from backend.analyzer.lexical import analyze_url_lexical
from backend.analyzer.network_inspector import inspect_network_and_page_safe
from backend.analyzer.whois_dns import query_whois_safe, query_dns_safe
from backend.analyzer.mitre_mapper import map_indicators_to_mitre
from backend.analyzer.scoring import calculate_threat_score, generate_tier1_playbook_actions
from backend.analyzer.defanger import defang_url, defang_ip, defang_domain, defang_email, format_ioc_blocklist, format_soc_analyst_notes
from backend.analyzer.email_parser import analyze_email_message
from backend.database import (
    init_db,
    save_analysis_record,
    get_analysis_history,
    get_analysis_by_id,
    get_all_iocs,
    clear_all_history,
)

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"
SAMPLES_DIR = BASE_DIR / "samples"

app = FastAPI(
    title="SOC Tier-1 Phishing & Malicious URL Threat Analyzer",
    description="Automated triage engine for Tier-1 SOC analysts detecting URL and email threats.",
    version="1.0.0"
)

# Mount static files and demo samples
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
if SAMPLES_DIR.exists():
    app.mount("/samples", StaticFiles(directory=SAMPLES_DIR), name="samples")

# Serve UI at root and /index.html
@app.get("/", response_class=FileResponse)
async def serve_root():
    index_file = FRONTEND_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard UI not found")
    return FileResponse(index_file)

@app.get("/index.html", response_class=FileResponse)
async def serve_index():
    index_file = FRONTEND_DIR / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard UI not found")
    return FileResponse(index_file)

@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "SOC Tier-1 Threat Analyzer",
        "version": "1.0.0",
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z"
    }

# Initialize SQLite DB on startup
@app.on_event("startup")
async def startup_event():
    init_db()

def build_report(case_id: str, analysis_type: str, target_summary: str, indicators: list, iocs: list, details: dict) -> dict:
    # Calculate score & verdict
    score, verdict, breakdown, meta = calculate_threat_score(indicators)
    # Prepare MITRE mapping
    mitre_mapped = map_indicators_to_mitre(indicators)
    # Playbook actions
    actions = generate_tier1_playbook_actions(verdict, indicators, analysis_type)
    # Timestamp
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    report = {
        "case_id": case_id,
        "timestamp": timestamp,
        "analysis_type": analysis_type,
        "target_summary": target_summary,
        "threat_score": score,
        "threat_verdict": verdict,
        "verdict_color": meta.get("verdict_color", "#e2e8f0"),
        "mitre_mapping": mitre_mapped,
        "score_breakdown": breakdown,
        "playbook_actions": actions,
        "iocs": iocs,
        "details": details
    }
    return report

@app.post("/analyze/url", response_model=AnalysisReportModel)
async def analyze_url(request: URLAnalysisRequest):
    raw_url = request.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty")

    # 1. Lexical analysis
    lexical_res = analyze_url_lexical(raw_url)
    indicators = list(lexical_res.get("indicators", []))

    # 2. WHOIS / DNS (use domain from lexical data)
    domain = lexical_res.get("registered_domain") or lexical_res.get("domain") or lexical_res.get("host")
    whois_res = {}
    dns_res = {}
    if domain:
        whois_res = query_whois_safe(domain)
        dns_res = query_dns_safe(domain)
        for ind in whois_res.get("indicators", []):
            indicators.append(ind)
        for ind in dns_res.get("indicators", []):
            indicators.append(ind)

    # 3. Network & page inspection (optional safe network)
    net_res = inspect_network_and_page_safe(raw_url, enable_live_connect=request.enable_network_inspection)
    if net_res.get("indicators"):
        indicators.extend(net_res["indicators"])

    # 4. Build IOC list
    iocs = []
    iocs.append({
        "ioc_type": "URL",
        "raw_value": raw_url,
        "defanged_value": defang_url(raw_url),
        "context": "Primary submitted URL"
    })

    if domain:
        iocs.append({
            "ioc_type": "Domain",
            "raw_value": domain,
            "defanged_value": defang_domain(domain),
            "context": "Resolved hostname / domain"
        })

    # Add resolved IP as IOC if available
    dns_records = dns_res.get("records", {})
    for a_ip in dns_records.get("A", []):
        iocs.append({
            "ioc_type": "IPv4",
            "raw_value": a_ip,
            "defanged_value": defang_ip(a_ip),
            "context": f"DNS A record for {domain}"
        })

    # Any form destination external URLs
    for form in net_res.get("forms", []):
        if form.get("is_external") and form.get("action"):
            act_url = form["action"]
            iocs.append({
                "ioc_type": "Credential-Drop-URL",
                "raw_value": act_url,
                "defanged_value": defang_url(act_url),
                "context": f"Form action target: {form.get('warning', 'External submission')}"
            })

    # 5. Assemble details dictionary
    details = {
        "indicators": indicators,
        "lexical": lexical_res,
        "network": net_res,
        "whois": whois_res,
        "dns": dns_res
    }

    case_id = str(uuid.uuid4())
    target_summary = raw_url
    report = build_report(case_id, "URL", target_summary, indicators, iocs, details)

    # Save to SQLite DB
    save_analysis_record(report)
    return report

def _process_email_payload(content: bytes or str, source_label: str) -> dict:
    email_res = analyze_email_message(content)
    indicators = list(email_res.get("indicators", []))

    # Run extracted URLs through the lexical engine
    for url_obj in email_res.get("urls", []):
        url = url_obj["url"]
        lexical_res = analyze_url_lexical(url)
        indicators.extend(lexical_res.get("indicators", []))

    # Build IOC list (Sender, Embedded URLs, Attachments, Originating IP)
    iocs = []
    sender_email = email_res["headers"].get("from_email")
    if sender_email:
        iocs.append({
            "ioc_type": "Email-Sender",
            "raw_value": sender_email,
            "defanged_value": defang_email(sender_email),
            "context": "Header From sender address"
        })

    originating_ip = email_res["headers"].get("originating_ip")
    if originating_ip:
        iocs.append({
            "ioc_type": "IPv4-Origin",
            "raw_value": originating_ip,
            "defanged_value": defang_ip(originating_ip),
            "context": "X-Originating-IP header"
        })

    for u in email_res.get("urls", []):
        iocs.append({
            "ioc_type": "URL",
            "raw_value": u["url"],
            "defanged_value": defang_url(u["url"]),
            "context": f"Body hyperlink ({u.get('anchor_text', 'link')})"
        })

    for att in email_res.get("attachments", []):
        iocs.append({
            "ioc_type": f"Attachment:{att['extension']}",
            "raw_value": att["filename"],
            "defanged_value": att["filename"],
            "context": f"Hash: {att.get('sha256', '')[:16]}... - {att.get('threat_note', '')}"
        })

    case_id = str(uuid.uuid4())
    subj = email_res["headers"].get("subject") or "(No Subject)"
    target_summary = f"{subj} [From: {sender_email or 'Unknown'}]"

    details = {
        "indicators": indicators,
        "email": email_res
    }

    report = build_report(case_id, "EMAIL", target_summary, indicators, iocs, details)
    save_analysis_record(report)
    return report

@app.post("/analyze/email", response_model=AnalysisReportModel)
async def analyze_email_file(file: UploadFile = File(...)):
    if not file.filename.lower().endswith(('.eml', '.msg', '.txt')):
        raise HTTPException(status_code=400, detail="Only .eml or text email files are accepted")
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    return _process_email_payload(content, file.filename)

@app.post("/analyze/email/raw", response_model=AnalysisReportModel)
async def analyze_email_raw(request: EmailAnalysisRequest):
    raw_text = request.raw_email.strip()
    if not raw_text:
        raise HTTPException(status_code=400, detail="Raw email content cannot be empty")
    return _process_email_payload(raw_text, "Raw Pasted Email")

@app.get("/history")
async def history(
    limit: int = Query(50, ge=1, le=200),
    verdict: str = Query("ALL"),
    type: str = Query("ALL"),
    search: Optional[str] = Query(None)
):
    hist = get_analysis_history(limit=limit, verdict_filter=verdict, type_filter=type, search=search)
    return JSONResponse(content=hist)

@app.get("/report/{case_id}")
async def get_report(case_id: str):
    report = get_analysis_by_id(case_id)
    if not report:
        raise HTTPException(status_code=404, detail="Incident report not found")
    return JSONResponse(content=report)

@app.get("/iocs")
async def iocs(limit: int = Query(200, ge=1, le=500)):
    return JSONResponse(content=get_all_iocs(limit))

@app.get("/samples/list")
async def list_samples():
    """List sample test artifacts for evaluation demo"""
    return {
        "urls": [
            {
                "id": "url-phish-brand",
                "label": "Microsoft 365 Lookalike Credential Harvester",
                "url": "https://login-micros0ft-security-portal.xyz/verify?session=abc123",
                "tags": ["Typosquatting", "NRD (4 days)", "High-Risk TLD .xyz", "Credential Form"]
            },
            {
                "id": "url-punycode",
                "label": "Punycode IDN Homograph Attack (Fake PayPal)",
                "url": "http://xn--paypl-qqa.com/signin/webapps/mpp/home",
                "tags": ["Punycode (xn--)", "Homoglyph Confusion", "Brand Masquerade"]
            },
            {
                "id": "url-ip-dropper",
                "label": "Direct Raw IP Payload Dropper (.iso / .exe)",
                "url": "http://198.51.100.42:8080/invoices/Invoice_OVERDUE_9482.iso",
                "tags": ["Raw IP Host", "Abnormal Port :8080", "Dangerous .iso Payload"]
            },
            {
                "id": "url-benign",
                "label": "Legitimate Benign Domain (Google Search)",
                "url": "https://www.google.com/search?q=cybersecurity+threat+intel",
                "tags": ["Benign", "Mature Domain (10k+ days)", "Valid SSL"]
            }
        ],
        "emails": [
            {
                "id": "eml-phish",
                "filename": "phishing_credential.eml",
                "label": "Phishing .eml - Account Verification Scam",
                "subject": "Verify your Microsoft account",
                "tags": ["SPF Fail", "DKIM Fail", "DMARC Fail", "Lookalike Domain", "Executable .exe attachment"]
            },
            {
                "id": "eml-benign",
                "filename": "legitimate_invoice.eml",
                "label": "Legitimate .eml - Vendor Invoice",
                "subject": "Your Invoice for July 2026",
                "tags": ["Safe Vendor", "Valid Invoice Attachment (.pdf)"]
            }
        ]
    }

@app.post("/history/clear")
async def clear_history():
    clear_all_history()
    return {"status": "cleared", "message": "All investigation history and IOCs purged"}

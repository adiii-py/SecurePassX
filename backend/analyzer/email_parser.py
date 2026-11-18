"""
Email Header & .eml Phishing Triage Engine
Parses RFC 822 email files and raw header text.
Extracts hops, SPF/DKIM/DMARC verdicts, sender spoofing flags,
embedded URLs (with URL masking checks), and attachments with SHA256 hashes.
"""
import email
from email import policy
import hashlib
import re
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract


# Dangerous file extensions commonly used in initial access / phishing campaigns
DANGEROUS_EXTENSIONS = {
    "iso": "Disk image container (bypasses Mark-of-the-Web)",
    "img": "Disk image container (bypasses Mark-of-the-Web)",
    "lnk": "Windows shortcut file (executes living-off-the-land commands)",
    "html": "HTML file (frequently used for local credential harvesting or SVG smuggling)",
    "htm": "HTML file (frequently used for local credential harvesting or SVG smuggling)",
    "svg": "SVG vector image (can contain embedded JavaScript for phishing smuggling)",
    "exe": "Windows executable binary",
    "dll": "Dynamic Link Library",
    "scr": "Windows Screensaver executable",
    "bat": "Batch command script",
    "cmd": "Command script",
    "ps1": "PowerShell script",
    "vbs": "VBScript script file",
    "js": "JavaScript script file",
    "wsf": "Windows Script File",
    "hta": "HTML Application (executes mshta.exe)",
    "docm": "Macro-enabled Word document",
    "xlsm": "Macro-enabled Excel spreadsheet",
    "pptm": "Macro-enabled PowerPoint presentation",
    "zip": "Archive container (may compress malicious payloads)",
    "rar": "Archive container",
    "7z": "Archive container",
    "cab": "Cabinet archive",
    "jar": "Java archive executable"
}


def parse_authentication_results(auth_header: str, received_spf: str = "") -> Dict[str, Any]:
    """
    Parse SPF, DKIM, and DMARC verdicts from Authentication-Results and Received-SPF headers.
    """
    verdicts = {
        "spf": {"status": "none", "details": "No SPF authentication record found in headers"},
        "dkim": {"status": "none", "details": "No DKIM signature verification found in headers"},
        "dmarc": {"status": "none", "details": "No DMARC policy check result found in headers"},
        "raw_header": auth_header
    }

    combined = f"{auth_header} {received_spf}".lower()

    # 1. SPF parsing
    spf_match = re.search(r"spf=([a-z]+)", combined)
    if not spf_match and received_spf:
        spf_match = re.search(r"^([a-z]+)", received_spf.strip().lower())
    if spf_match:
        val = spf_match.group(1)
        verdicts["spf"]["status"] = val
        if val == "pass":
            verdicts["spf"]["details"] = "SPF Pass: Sender IP is authorized by the domain's SPF record."
        elif val in ("fail", "hardfail"):
            verdicts["spf"]["details"] = "SPF Fail: Sender IP is explicitly unauthorized to send on behalf of this domain."
        elif val == "softfail":
            verdicts["spf"]["details"] = "SPF Softfail: Sender IP is not recognized as authorized (domain owner configured ~all)."
        elif val == "neutral":
            verdicts["spf"]["details"] = "SPF Neutral: Domain does not state whether sender IP is authorized (?all)."

    # 2. DKIM parsing
    dkim_match = re.search(r"dkim=([a-z]+)", combined)
    if dkim_match:
        val = dkim_match.group(1)
        verdicts["dkim"]["status"] = val
        if val == "pass":
            verdicts["dkim"]["details"] = "DKIM Pass: Cryptographic signature matches and message integrity is intact."
        elif val in ("fail", "badsignature", "temperror", "permerror"):
            verdicts["dkim"]["details"] = "DKIM Fail: Cryptographic signature failed verification or message body was tampered with."

    # 3. DMARC parsing
    dmarc_match = re.search(r"dmarc=([a-z]+)", combined)
    if dmarc_match:
        val = dmarc_match.group(1)
        verdicts["dmarc"]["status"] = val
        if val == "pass":
            verdicts["dmarc"]["details"] = "DMARC Pass: Domain alignment verified (SPF and/or DKIM passed with aligned domain)."
        elif val == "fail":
            verdicts["dmarc"]["details"] = "DMARC Fail: Domain alignment failed. Sender appears spoofed or unauthorized."

    # Extract action/policy if specified
    action_match = re.search(r"action=([a-z]+)", combined)
    if action_match:
        verdicts["dmarc"]["action"] = action_match.group(1)

    return verdicts


def extract_email_address_and_domain(raw_header: str) -> Tuple[str, str, str]:
    """Extract display name, email address, and registered domain from an RFC 822 header"""
    if not raw_header:
        return "", "", ""

    # Parse display name and addr
    parsed_addr = email.utils.parseaddr(raw_header)
    display_name = parsed_addr[0].strip()
    email_addr = parsed_addr[1].strip().lower()

    domain = ""
    if "@" in email_addr:
        domain = email_addr.split("@")[1].strip()

    return display_name, email_addr, domain


def parse_received_hops(received_headers: List[str]) -> List[Dict[str, Any]]:
    """
    Parse Received headers to reconstruct the mail relay hop chain.
    Headers in an email are listed in reverse order (top is final recipient MTA).
    """
    hops = []
    # Reverse to read from originating client -> intermediate relays -> final server
    ordered_headers = list(reversed(received_headers))

    for i, header in enumerate(ordered_headers, 1):
        clean_h = " ".join(header.split())
        # Try to extract 'from <host> (<ip>)' and 'by <host>'
        from_match = re.search(r"from\s+([^\s]+)(?:\s+\((?:[^\)]*?\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?[^\)]*?)\))?", clean_h, re.IGNORECASE)
        by_match = re.search(r"by\s+([^\s]+)", clean_h, re.IGNORECASE)
        time_match = re.search(r";\s*(.+)$", clean_h)

        from_host = from_match.group(1) if from_match else "Unknown"
        from_ip = from_match.group(2) if (from_match and from_match.group(2)) else ""
        by_host = by_match.group(1) if by_match else "Unknown"
        timestamp = time_match.group(1).strip() if time_match else ""

        hops.append({
            "hop_number": i,
            "from_host": from_host,
            "from_ip": from_ip,
            "by_host": by_host,
            "timestamp": timestamp,
            "is_originating": (i == 1),
            "raw": clean_h[:120] + "..." if len(clean_h) > 120 else clean_h
        })

    return hops


def extract_urls_from_body(html_body: str, text_body: str) -> List[Dict[str, Any]]:
    """
    Extract all URLs from HTML and plain text bodies, detecting deceptive URL masking.
    """
    found_urls = []
    seen = set()

    # 1. From HTML anchors (can detect text vs href masking)
    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            anchor_text = a.get_text().strip()
            if not href or href.startswith(("mailto:", "tel:", "javascript:#", "#")):
                continue

            is_masked = False
            if ("http://" in anchor_text or "https://" in anchor_text) and "://" in href:
                text_host = urlparse(anchor_text if "://" in anchor_text else "http://" + anchor_text).netloc.lower()
                href_host = urlparse(href).netloc.lower()
                if text_host and href_host and text_host != href_host:
                    is_masked = True

            if href not in seen:
                seen.add(href)
                found_urls.append({
                    "url": href,
                    "anchor_text": anchor_text,
                    "is_masked": is_masked,
                    "source": "HTML Link"
                })

    # 2. Regex search in plain text body
    url_pattern = r"https?://[^\s<>\"'()]+"
    text_matches = re.findall(url_pattern, text_body)
    for u in text_matches:
        clean_u = u.rstrip(".,;!?)")
        if clean_u not in seen:
            seen.add(clean_u)
            found_urls.append({
                "url": clean_u,
                "anchor_text": clean_u,
                "is_masked": False,
                "source": "Plain Text Body"
            })

    return found_urls


def extract_attachments_from_message(msg: email.message.EmailMessage) -> List[Dict[str, Any]]:
    """
    Extract all attachment files, extensions, MIME types, sizes, and SHA256 hashes.
    Flags dangerous or double extensions.
    """
    attachments = []

    for part in msg.walk():
        content_disposition = str(part.get("Content-Disposition", ""))
        content_type = part.get_content_type()
        filename = part.get_filename()

        if not filename and "attachment" in content_disposition.lower():
            filename = "unnamed_attachment.bin"

        if filename:
            # Clean filename
            clean_filename = email.utils.collapse_rfc2231_value(filename)
            payload = part.get_payload(decode=True) or b""
            size = len(payload)
            sha256 = hashlib.sha256(payload).hexdigest()

            # Determine extension
            ext = clean_filename.split(".")[-1].lower() if "." in clean_filename else ""
            is_dangerous = ext in DANGEROUS_EXTENSIONS
            threat_note = DANGEROUS_EXTENSIONS.get(ext, "")

            # Check for double extensions (e.g. invoice.pdf.exe or statement.xlsx.vbs)
            has_double_ext = False
            parts = clean_filename.split(".")
            if len(parts) >= 3:
                inner_ext = parts[-2].lower()
                if inner_ext in ("pdf", "docx", "xlsx", "txt", "jpg", "png") and is_dangerous:
                    has_double_ext = True
                    threat_note = f"Double extension trick detected ({inner_ext}.{ext}); disguise for executable payload"

            attachments.append({
                "filename": clean_filename,
                "extension": ext,
                "content_type": content_type,
                "size_bytes": size,
                "sha256": sha256,
                "is_dangerous": is_dangerous,
                "has_double_extension": has_double_ext,
                "threat_note": threat_note
            })

    return attachments


def analyze_email_message(raw_content: bytes or str) -> Dict[str, Any]:
    """
    Main Email Triage Analyzer.
    Parses headers, authentications, spoofing indicators, hops, body, and attachments.
    """
    indicators = []

    if isinstance(raw_content, str):
        msg = email.message_from_string(raw_content, policy=policy.default)
    else:
        msg = email.message_from_bytes(raw_content, policy=policy.default)

    # 1. Key Headers
    subject = str(msg.get("Subject", "(No Subject)"))
    date = str(msg.get("Date", ""))
    message_id = str(msg.get("Message-ID", ""))
    from_raw = str(msg.get("From", ""))
    reply_to_raw = str(msg.get("Reply-To", ""))
    return_path_raw = str(msg.get("Return-Path", ""))
    originating_ip = str(msg.get("X-Originating-IP", "")).strip("[]")
    auth_results_raw = str(msg.get("Authentication-Results", ""))
    received_spf_raw = str(msg.get("Received-SPF", ""))

    # 2. Address & Domain extraction
    from_name, from_email, from_domain = extract_email_address_and_domain(from_raw)
    reply_name, reply_email, reply_domain = extract_email_address_and_domain(reply_to_raw)
    return_name, return_email, return_domain = extract_email_address_and_domain(return_path_raw)

    from_ext = tldextract.extract(from_domain)
    from_reg_domain = from_ext.registered_domain.lower() if from_domain else ""

    # 3. Sender Spoofing & Domain Mismatch Checks
    # 3a. Display name impersonation
    if from_name:
        for brand in ["microsoft", "office 365", "google", "paypal", "apple", "amazon", "helpdesk", "it support", "security alert"]:
            if brand in from_name.lower() and from_reg_domain and brand.replace(" ", "") not in from_reg_domain:
                indicators.append({
                    "key": "email_display_name_spoofing",
                    "category": "Email Spoofing",
                    "weight": 25,
                    "description": f"Display Name Spoofing: Display name claims '{from_name}' but sending address is '{from_email}'"
                })
                break

    # 3b. From vs Reply-To Mismatch
    if reply_domain and from_reg_domain:
        reply_ext = tldextract.extract(reply_domain)
        reply_reg = reply_ext.registered_domain.lower()
        if reply_reg != from_reg_domain:
            indicators.append({
                "key": "email_reply_to_mismatch",
                "category": "Email Spoofing",
                "weight": 20,
                "description": f"Reply-To Domain Mismatch: Sender claims '{from_reg_domain}' but replies are routed to '{reply_reg}' ({reply_email})"
            })

    # 3c. From vs Return-Path (Envelope Sender) Mismatch
    if return_domain and from_reg_domain:
        return_ext = tldextract.extract(return_domain)
        return_reg = return_ext.registered_domain.lower()
        if return_reg != from_reg_domain:
            indicators.append({
                "key": "email_return_path_mismatch",
                "category": "Email Spoofing",
                "weight": 15,
                "description": f"Envelope Sender Mismatch: Header From is '{from_reg_domain}' but Return-Path points to '{return_reg}'"
            })

    # 4. Authentication Results (SPF, DKIM, DMARC)
    auth_verdicts = parse_authentication_results(auth_results_raw, received_spf_raw)

    if auth_verdicts["spf"]["status"] in ("fail", "hardfail"):
        indicators.append({
            "key": "email_spf_fail",
            "category": "Email Authentication",
            "weight": 20,
            "description": "SPF Verification FAILED: The sending IP server is not authorized to deliver email for this domain"
        })
    elif auth_verdicts["spf"]["status"] == "softfail":
        indicators.append({
            "key": "email_spf_softfail",
            "category": "Email Authentication",
            "weight": 10,
            "description": "SPF Softfail: Sending IP is not listed as an approved sender by domain policy"
        })

    if auth_verdicts["dkim"]["status"] in ("fail", "badsignature"):
        indicators.append({
            "key": "email_dkim_fail",
            "category": "Email Authentication",
            "weight": 20,
            "description": "DKIM Cryptographic Signature FAILED: Message body may have been modified or signature is forged"
        })

    if auth_verdicts["dmarc"]["status"] == "fail":
        indicators.append({
            "key": "email_dmarc_fail",
            "category": "Email Authentication",
            "weight": 25,
            "description": "DMARC Alignment FAILED: Sender identity could not be verified against the sending domain's policy"
        })

    # 5. Received Hops & Relay Timeline
    received_headers = msg.get_all("Received", [])
    hops = parse_received_hops(received_headers)

    # 6. Body extraction & URLs
    text_body = ""
    html_body = ""

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or "utf-8"
                    decoded_text = payload.decode(charset, errors="replace")
                    if ctype == "text/plain" and not text_body:
                        text_body = decoded_text
                    elif ctype == "text/html" and not html_body:
                        html_body = decoded_text
            except Exception:
                pass
    else:
        try:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                text_body = payload.decode(charset, errors="replace")
        except Exception:
            text_body = str(msg.get_payload())

    extracted_urls = extract_urls_from_body(html_body, text_body)

    # Check for masked URLs in email
    for u in extracted_urls:
        if u.get("is_masked"):
            indicators.append({
                "key": "email_masked_hyperlink",
                "category": "Deceptive Content",
                "weight": 20,
                "description": f"Deceptive Hyperlink: Visual text displays '{u['anchor_text']}' but points to malicious destination '{u['url']}'"
            })

    # 7. Attachment Security Inspection
    attachments = extract_attachments_from_message(msg)
    for att in attachments:
        if att.get("is_dangerous"):
            weight = 25 if att["extension"] in ("iso", "img", "lnk", "exe", "html", "htm") else 15
            indicators.append({
                "key": f"dangerous_attachment_{att['extension']}",
                "category": "Attachment Security",
                "weight": weight,
                "description": f"Dangerous Attachment Detected: '{att['filename']}' ({att['threat_note']})"
            })
        if att.get("has_double_extension"):
            indicators.append({
                "key": "attachment_double_extension",
                "category": "Attachment Security",
                "weight": 25,
                "description": f"Double extension obfuscation in attachment '{att['filename']}'"
            })

    return {
        "headers": {
            "subject": subject,
            "date": date,
            "message_id": message_id,
            "from_raw": from_raw,
            "from_name": from_name,
            "from_email": from_email,
            "from_domain": from_domain,
            "from_reg_domain": from_reg_domain,
            "reply_to_raw": reply_to_raw,
            "reply_email": reply_email,
            "reply_domain": reply_domain,
            "return_path_raw": return_path_raw,
            "return_email": return_email,
            "return_domain": return_domain,
            "originating_ip": originating_ip
        },
        "authentication": auth_verdicts,
        "hops": hops,
        "body_preview": text_body[:400] if text_body else (BeautifulSoup(html_body, "html.parser").get_text()[:400] if html_body else ""),
        "urls": extracted_urls,
        "attachments": attachments,
        "indicators": indicators
    }

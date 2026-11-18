"""
Defanger Module for SOC Tier-1 Triage
Safely defangs URLs, domains, IPs, and email addresses to prevent accidental execution,
auto-hyperlinking in ticketing systems, or accidental clicks by analysts.
"""
import re
from typing import List, Dict, Any


def defang_url(url: str) -> str:
    """Defang URL: replace protocol with hxxp/hxxps and dots with [.]"""
    if not url:
        return ""
    # Protocol defanging
    defanged = re.sub(r"^http://", "hxxp://", url, flags=re.IGNORECASE)
    defanged = re.sub(r"^https://", "hxxps://", defanged, flags=re.IGNORECASE)
    defanged = re.sub(r"^ftp://", "fxp://", defanged, flags=re.IGNORECASE)

    # Defang @ symbol (credential masking)
    defanged = defanged.replace("@", "[@]")

    # Defang domain dots (do not defang file extension or path dots if not desired,
    # but standard SOC practice defangs domain dots)
    # Parse authority to defang host portion
    parts = defanged.split("/", 3)
    if len(parts) >= 3:
        # parts[0] is scheme, parts[1] is '', parts[2] is authority
        authority = parts[2]
        authority_defanged = authority.replace(".", "[.]")
        defanged = f"{parts[0]}//{authority_defanged}" + ("/" + parts[3] if len(parts) > 3 else "")
    else:
        defanged = defanged.replace(".", "[.]")

    return defanged


def defang_ip(ip: str) -> str:
    """Defang IPv4 or IPv6 address"""
    if not ip:
        return ""
    return ip.replace(".", "[.]").replace(":", "[:]")


def defang_domain(domain: str) -> str:
    """Defang domain name (e.g., example[.]com)"""
    if not domain:
        return ""
    return domain.replace(".", "[.]")


def defang_email(email: str) -> str:
    """Defang email address (e.g., user[@]example[.]com)"""
    if not email:
        return ""
    parts = email.split("@")
    if len(parts) == 2:
        return f"{parts[0]}[@]{parts[1].replace('.', '[.]')}"
    return email.replace("@", "[@]").replace(".", "[.]")


def format_ioc_blocklist(iocs: List[Dict[str, Any]]) -> str:
    """Generate clean newline-delimited defanged IOC blocklist for SIEM/Firewall ingestion"""
    lines = []
    for item in iocs:
        val = item.get("defanged_value") or item.get("raw_value", "")
        ioc_type = item.get("ioc_type", "IOC")
        if val:
            lines.append(f"{val} # {ioc_type}")
    return "\n".join(lines)


def format_soc_analyst_notes(case_id: str, target: str, score: int, verdict: str, iocs: List[Dict[str, Any]]) -> str:
    """Format markdown incident response notes ready to paste into Jira / ServiceNow / TheHive"""
    lines = [
        f"### [SOC Tier-1 Triage Report] Incident Case: {case_id}",
        f"- **Target Evaluated**: `{defang_url(target) if 'http' in target else defang_domain(target)}`",
        f"- **Threat Verdict**: **{verdict.upper()}** (Score: {score}/100)",
        "- **Triage Time**: Current UTC / Analyst Live Evaluation",
        "",
        "#### Indicators of Compromise (Defanged):",
    ]
    for ioc in iocs:
        t = ioc.get("ioc_type", "IOC")
        val = ioc.get("defanged_value") or ioc.get("raw_value")
        ctx = ioc.get("context", "")
        lines.append(f"- `[{t}]` **{val}** {f'({ctx})' if ctx else ''}")

    lines.append("")
    lines.append("#### Recommended Actions:")
    if score >= 70:
        lines.append("- [ ] Block defanged domain/IP on perimeter firewalls & web proxies")
        lines.append("- [ ] Purge matching messages across email gateways")
        lines.append("- [ ] Reset user credentials if authentication forms were submitted")
    elif score >= 30:
        lines.append("- [ ] Flag for Tier-2 SOC review & monitor perimeter telemetry")
    else:
        lines.append("- [ ] No immediate containment required; close ticket as benign")

    return "\n".join(lines)

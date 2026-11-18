"""
Explainable Risk Scoring Engine & SOC Tier-1 Triage Playbook
Calculates normalized threat scores (0–100), transparent point breakdowns,
and tailored Tier-1 incident response recommendations.
"""
from typing import Dict, Any, List, Tuple


def calculate_threat_score(indicators: List[Dict[str, Any]]) -> Tuple[int, str, List[Dict[str, Any]], Dict[str, Any]]:
    """
    Calculate an explainable Threat Risk Score (0–100) from detected indicators.
    Returns:
        score: int (0 to 100)
        verdict: str ('SAFE', 'SUSPICIOUS', 'HIGH RISK / PHISHING')
        breakdown: list of indicators with exact point additions
        summary_meta: dict with high-level SOC statistics
    """
    total_score = 0
    breakdown = []
    category_totals = {
        "Lexical": 0,
        "Infrastructure": 0,
        "DNS Infrastructure": 0,
        "SSL/TLS": 0,
        "Page Content": 0,
        "Network": 0,
        "Email Spoofing": 0,
        "Email Authentication": 0,
        "Attachment Security": 0,
        "Deceptive Content": 0,
        "Security Guard": 0
    }

    # Deduplicate indicators by key to avoid double-scoring the same heuristic
    seen_keys = set()
    for ind in indicators:
        key = ind.get("key", "")
        weight = ind.get("weight", 0)
        category = ind.get("category", "General")
        desc = ind.get("description", "")

        if key in seen_keys:
            continue
        seen_keys.add(key)

        if weight > 0:
            total_score += weight
            category_totals[category] = category_totals.get(category, 0) + weight
            breakdown.append({
                "key": key,
                "category": category,
                "weight": weight,
                "description": desc
            })

    # Clamp score to [0, 100]
    final_score = min(100, max(0, total_score))

    # Classify verdict
    if final_score >= 70:
        verdict = "HIGH RISK / PHISHING"
        verdict_color = "red"
    elif final_score >= 30:
        verdict = "SUSPICIOUS"
        verdict_color = "amber"
    else:
        verdict = "SAFE"
        verdict_color = "emerald"

    # Sort breakdown descending by weight
    breakdown.sort(key=lambda x: x["weight"], reverse=True)

    summary_meta = {
        "final_score": final_score,
        "verdict": verdict,
        "verdict_color": verdict_color,
        "indicators_count": len(breakdown),
        "category_totals": {k: v for k, v in category_totals.items() if v > 0}
    }

    return final_score, verdict, breakdown, summary_meta


def generate_tier1_playbook_actions(verdict: str, indicators: List[Dict[str, Any]], target_type: str = "URL") -> List[Dict[str, str]]:
    """
    Generate SOC Tier-1 Playbook triage actions based on findings.
    """
    actions = []

    if verdict == "HIGH RISK / PHISHING":
        actions.append({
            "action": "Immediate Perimeter Block",
            "priority": "P1 - CRITICAL",
            "instructions": "Push defanged domain and IP indicators to Firewall, EDR web filtering, and Secure Web Gateway (SWG) blocklists."
        })
        if target_type == "EMAIL" or any("email" in ind.get("category", "").lower() for ind in indicators):
            actions.append({
                "action": "Tenant Mailbox Remediation",
                "priority": "P1 - CRITICAL",
                "instructions": "Execute automated M365/Google Workspace Purge via PowerShell/Security Center to delete this message across all employee inboxes."
            })
            actions.append({
                "action": "Identity & Credential Revocation",
                "priority": "P2 - HIGH",
                "instructions": "If recipient interacted with URL or opened attachment, trigger forced password reset and revoke active Entra ID/Google session tokens."
            })
        if any("form" in ind.get("key", "") or "credential" in ind.get("key", "") for ind in indicators):
            actions.append({
                "action": "Credential Harvesting Containment",
                "priority": "P1 - CRITICAL",
                "instructions": "Page features credential-harvesting mechanisms. Search SIEM proxy logs for any internal POST requests to the drop domain."
            })
        actions.append({
            "action": "Escalate Incident Ticket",
            "priority": "P2 - HIGH",
            "instructions": "Promote triage case to Tier-2 Incident Response for compromised account sweep and persistence check."
        })

    elif verdict == "SUSPICIOUS":
        actions.append({
            "action": "Proxy Graylisting / Monitoring",
            "priority": "P2 - MEDIUM",
            "instructions": "Add target to SIEM alert watchlist. Monitor firewall/proxy logs for repeat outbound connections."
        })
        if target_type == "EMAIL":
            actions.append({
                "action": "Quarantine Email",
                "priority": "P2 - MEDIUM",
                "instructions": "Move message to administrative quarantine pending Tier-2 review. Advise recipient not to click links or download attachments."
            })
        actions.append({
            "action": "Enhanced Endpoint Telemetry",
            "priority": "P3 - LOW",
            "instructions": "Verify endpoint EDR agent is healthy on recipient workstation and running up-to-date threat signatures."
        })

    else:  # SAFE
        actions.append({
            "action": "Close Incident Ticket",
            "priority": "P4 - INFORMATIONAL",
            "instructions": "No critical malicious heuristics detected. Close triage ticket as benign / false positive."
        })
        actions.append({
            "action": "Release from Quarantine",
            "priority": "P4 - INFORMATIONAL",
            "instructions": "If held in spam quarantine, message may be released to user according to organization policy."
        })

    return actions

"""
MITRE ATT&CK Framework Mapping Engine
Maps detected phishing indicators, lexical anomalies, email spoofing, and credential forms
to official MITRE ATT&CK Enterprise Matrix techniques.
"""
from typing import List, Dict, Any

MITRE_DEFINITIONS = {
    "T1566.001": {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/001/",
        "description": "Adversaries send emails with malicious attachments to gain code execution upon user interaction."
    },
    "T1566.002": {
        "id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
        "description": "Adversaries send emails with malicious links to lure victims into visiting adversary-controlled sites."
    },
    "T1583.001": {
        "id": "T1583.001",
        "name": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development",
        "url": "https://attack.mitre.org/techniques/T1583/001/",
        "description": "Adversaries acquire domains that look similar to legitimate services (typosquatting, lookalike domains)."
    },
    "T1036": {
        "id": "T1036",
        "name": "Masquerading",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1036/",
        "description": "Adversaries attempt to manipulate features of artifacts to make them appear legitimate or benign."
    },
    "T1036.005": {
        "id": "T1036.005",
        "name": "Masquerading: Match Legitimate Name",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1036/005/",
        "description": "Adversaries match or closely approximate legitimate filenames, domains, or brand identities."
    },
    "T1056.003": {
        "id": "T1056.003",
        "name": "Input Capture: Web Portal Capture",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1056/003/",
        "description": "Adversaries install code on adversary-controlled portals to harvest user credentials entered into web forms."
    },
    "T1204.001": {
        "id": "T1204.001",
        "name": "User Execution: Malicious Link",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1204/001/",
        "description": "An adversary relies on the user clicking a malicious link in an email or document."
    },
    "T1204.002": {
        "id": "T1204.002",
        "name": "User Execution: Malicious File",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1204/002/",
        "description": "An adversary relies on the user opening a malicious attachment or container file (ISO, LNK, HTML)."
    },
    "T1586.002": {
        "id": "T1586.002",
        "name": "Compromise Accounts: Email Accounts",
        "tactic": "Resource Development",
        "url": "https://attack.mitre.org/techniques/T1586/002/",
        "description": "Adversaries compromise email accounts or spoof authorized sender identities to send phishing campaigns."
    },
    "T1598": {
        "id": "T1598",
        "name": "Phishing for Information",
        "tactic": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1598/",
        "description": "Adversaries send phishing messages to elicit sensitive corporate data or employee credentials."
    }
}


def map_indicators_to_mitre(indicators: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Map detected indicators/heuristics to MITRE ATT&CK techniques with triggered reasons.
    """
    technique_triggers: Dict[str, List[str]] = {}

    for ind in indicators:
        key = ind.get("key", "").lower()
        desc = ind.get("description", "")
        weight = ind.get("weight", 0)

        # Skip zero-weight safe findings
        if weight <= 0:
            continue

        # Rule mappings:
        if "typosquat" in key or "homograph" in key or "punycode" in key:
            technique_triggers.setdefault("T1583.001", []).append(desc)
            technique_triggers.setdefault("T1036.005", []).append(desc)
        elif "brand_abuse" in key or "url_masking" in key:
            technique_triggers.setdefault("T1036", []).append(desc)
        elif "form" in key or "credential_harvest" in key:
            technique_triggers.setdefault("T1056.003", []).append(desc)
            technique_triggers.setdefault("T1598", []).append(desc)
        elif "attachment" in key:
            technique_triggers.setdefault("T1566.001", []).append(desc)
            technique_triggers.setdefault("T1204.002", []).append(desc)
        elif "spf" in key or "dmarc" in key or "dkim" in key or "spoof" in key:
            technique_triggers.setdefault("T1586.002", []).append(desc)
            technique_triggers.setdefault("T1036", []).append(desc)
        elif "url" in key or "entropy" in key or "ip_host" in key or "high_risk_tld" in key:
            technique_triggers.setdefault("T1566.002", []).append(desc)
            technique_triggers.setdefault("T1204.001", []).append(desc)
        elif "nrd" in key or "domain_age" in key:
            technique_triggers.setdefault("T1583.001", []).append(desc)

    mapped_results = []
    for tech_id, triggers in technique_triggers.items():
        meta = MITRE_DEFINITIONS.get(tech_id)
        if meta:
            mapped_results.append({
                "id": tech_id,
                "name": meta["name"],
                "tactic": meta["tactic"],
                "url": meta["url"],
                "description": meta["description"],
                "triggers": list(set(triggers))
            })

    # Sort by technique ID for deterministic UI display
    mapped_results.sort(key=lambda x: x["id"])
    return mapped_results

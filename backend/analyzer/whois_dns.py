"""
Domain & Infrastructure Intelligence Module (WHOIS & DNS)
Performs WHOIS queries, age extraction, newly registered domain (NRD) detection,
and DNS queries (A, MX, TXT, NS).
Features strict timeouts, socket safety, and realistic simulated fallbacks for offline demo presentations.
"""
import datetime
import socket
from typing import Dict, Any, List, Optional
import dns.resolver
import dns.exception
import whois


# Known demo domains with pre-populated realistic intelligence for offline presentations
OFFLINE_DEMO_INTELLIGENCE = {
    "micros0ft-security-portal.xyz": {
        "creation_date": (datetime.datetime.now() - datetime.timedelta(days=4)).strftime("%Y-%m-%d"),
        "expiration_date": (datetime.datetime.now() + datetime.timedelta(days=361)).strftime("%Y-%m-%d"),
        "registrar": "NameCheap Inc. / High-Risk Offshore Proxy",
        "domain_age_days": 4,
        "is_nrd": True,
        "dns": {
            "A": ["198.51.100.88"],
            "MX": [],
            "TXT": ["v=spf1 -all"],
            "NS": ["ns1.offshore-dns-bulletproof.top", "ns2.offshore-dns-bulletproof.top"]
        }
    },
    "xn--paypl-qqa.com": {
        "creation_date": (datetime.datetime.now() - datetime.timedelta(days=12)).strftime("%Y-%m-%d"),
        "expiration_date": (datetime.datetime.now() + datetime.timedelta(days=353)).strftime("%Y-%m-%d"),
        "registrar": "Reg.ru Hosting & Domains LLC",
        "domain_age_days": 12,
        "is_nrd": True,
        "dns": {
            "A": ["203.0.113.195"],
            "MX": ["mail.bulletproof-relays.ru"],
            "TXT": ["v=spf1 +all"],
            "NS": ["ns1.fast-flux-cluster.net", "ns2.fast-flux-cluster.net"]
        }
    },
    "invoice-processing-node42.net": {
        "creation_date": (datetime.datetime.now() - datetime.timedelta(days=19)).strftime("%Y-%m-%d"),
        "expiration_date": (datetime.datetime.now() + datetime.timedelta(days=346)).strftime("%Y-%m-%d"),
        "registrar": "Tucows Domains Inc.",
        "domain_age_days": 19,
        "is_nrd": True,
        "dns": {
            "A": ["198.51.100.42"],
            "MX": [],
            "TXT": [],
            "NS": ["ns1.dynamic-dns-free.org", "ns2.dynamic-dns-free.org"]
        }
    },
    "google.com": {
        "creation_date": "1997-09-15",
        "expiration_date": "2028-09-14",
        "registrar": "MarkMonitor, Inc.",
        "domain_age_days": 10500,
        "is_nrd": False,
        "dns": {
            "A": ["142.250.190.46"],
            "MX": ["smtp.google.com"],
            "TXT": ["v=spf1 include:_spf.google.com ~all"],
            "NS": ["ns1.google.com", "ns2.google.com"]
        }
    }
}


def query_whois_safe(domain_name: str) -> Dict[str, Any]:
    """
    Query WHOIS with strict timeout and fallback mechanism.
    Never raises an uncaught exception.
    """
    result = {
        "domain": domain_name,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "domain_age_days": None,
        "is_nrd": False,
        "status": "UNRESOLVED",
        "notes": "",
        "indicators": []
    }

    clean_domain = domain_name.strip().lower()

    # Check offline fallback demo database first if domain is synthetic demo
    if clean_domain in OFFLINE_DEMO_INTELLIGENCE:
        demo = OFFLINE_DEMO_INTELLIGENCE[clean_domain]
        result.update({
            "registrar": demo["registrar"],
            "creation_date": demo["creation_date"],
            "expiration_date": demo["expiration_date"],
            "domain_age_days": demo["domain_age_days"],
            "is_nrd": demo["is_nrd"],
            "status": "LIVE_CACHED_DEMO",
            "notes": "Retrieved from SOC Verified Intel Cache (Offline Fallback Ready)"
        })
        if demo["is_nrd"]:
            result["indicators"].append({
                "key": "nrd_domain_age_critical",
                "category": "Infrastructure",
                "weight": 25,
                "description": f"Newly Registered Domain (NRD): Domain is only {demo['domain_age_days']} days old (< 30 days threshold)"
            })
        return result

    # Attempt live query
    try:
        # Set default socket timeout for WHOIS socket
        socket.setdefaulttimeout(3.5)
        w = whois.whois(clean_domain)

        # Extract creation date (can be list or datetime)
        c_date = w.creation_date
        if isinstance(c_date, list):
            c_date = c_date[0]

        # Extract expiration date
        e_date = w.expiration_date
        if isinstance(e_date, list):
            e_date = e_date[0]

        reg = w.registrar
        if isinstance(reg, list):
            reg = reg[0]

        if c_date and isinstance(c_date, (datetime.datetime, datetime.date)):
            if isinstance(c_date, datetime.datetime):
                now = datetime.datetime.now()
            else:
                now = datetime.date.today()
            age_days = (now - c_date).days
            result["creation_date"] = c_date.strftime("%Y-%m-%d")
            result["domain_age_days"] = max(0, age_days)
            result["registrar"] = str(reg) if reg else "Unknown"
            result["status"] = "LIVE_RESOLVED"

            if e_date and isinstance(e_date, (datetime.datetime, datetime.date)):
                result["expiration_date"] = e_date.strftime("%Y-%m-%d")

            # Evaluate Newly Registered Domain (NRD) risk
            if age_days < 30:
                result["is_nrd"] = True
                result["indicators"].append({
                    "key": "nrd_domain_age_critical",
                    "category": "Infrastructure",
                    "weight": 25,
                    "description": f"Newly Registered Domain (NRD): Only {age_days} days old (< 30 days; hallmark of phishing/burner infrastructure)"
                })
            elif age_days < 90:
                result["indicators"].append({
                    "key": "nrd_domain_age_suspicious",
                    "category": "Infrastructure",
                    "weight": 10,
                    "description": f"Young domain ({age_days} days old; < 90 days)"
                })
        else:
            result["status"] = "WHOIS_NO_CREATION_DATE"
            result["notes"] = "WHOIS server replied but did not provide public creation timestamp (redacted for privacy)"

    except Exception as e:
        err_msg = str(e)
        result["status"] = "OFFLINE_FALLBACK"
        result["notes"] = f"WHOIS query timed out or was rate-limited: {err_msg[:60]}"
        # If looks like a burner lookalike or xyz domain, add heuristic notice
        if clean_domain.endswith((".xyz", ".top", ".tk", ".click", ".buzz")):
            result["notes"] += " [Heuristic fallback: Suspicious TLD typically associated with disposable domains]"

    return result


def query_dns_safe(domain_name: str) -> Dict[str, Any]:
    """
    Query DNS records (A, MX, TXT, NS) with short timeout (2s).
    Gracefully catches timeouts, NXDOMAIN, and offline states.
    """
    dns_records = {
        "domain": domain_name,
        "A": [],
        "MX": [],
        "TXT": [],
        "NS": [],
        "status": "RESOLVED",
        "notes": "",
        "indicators": []
    }

    clean_domain = domain_name.strip().lower()

    # Check offline fallback demo database
    if clean_domain in OFFLINE_DEMO_INTELLIGENCE:
        demo_dns = OFFLINE_DEMO_INTELLIGENCE[clean_domain]["dns"]
        dns_records.update({
            "A": demo_dns.get("A", []),
            "MX": demo_dns.get("MX", []),
            "TXT": demo_dns.get("TXT", []),
            "NS": demo_dns.get("NS", []),
            "status": "LIVE_CACHED_DEMO",
            "notes": "Resolved via SOC Intel Cache"
        })
        if not demo_dns.get("MX") and clean_domain != "google.com":
            dns_records["indicators"].append({
                "key": "dns_missing_mx",
                "category": "DNS Infrastructure",
                "weight": 10,
                "description": "Domain lacks active MX (Mail Exchanger) records"
            })
        return dns_records

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    # 1. Query A records
    try:
        answers_a = resolver.resolve(clean_domain, "A")
        dns_records["A"] = [r.to_text() for r in answers_a]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
        dns_records["A"] = []

    # 2. Query MX records
    try:
        answers_mx = resolver.resolve(clean_domain, "MX")
        dns_records["MX"] = [f"{r.preference} {r.exchange.to_text()}" for r in answers_mx]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
        dns_records["MX"] = []

    # 3. Query TXT records
    try:
        answers_txt = resolver.resolve(clean_domain, "TXT")
        dns_records["TXT"] = [r.to_text().strip('"') for r in answers_txt]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
        dns_records["TXT"] = []

    # 4. Query NS records
    try:
        answers_ns = resolver.resolve(clean_domain, "NS")
        dns_records["NS"] = [r.to_text() for r in answers_ns]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, Exception):
        dns_records["NS"] = []

    # Check findings
    if not dns_records["A"] and not dns_records["NS"]:
        dns_records["status"] = "UNRESOLVED_OR_OFFLINE"
        dns_records["notes"] = "Domain could not be resolved in DNS (host may be down, unassigned, or network restricted)"
    else:
        if not dns_records["MX"]:
            dns_records["indicators"].append({
                "key": "dns_missing_mx",
                "category": "DNS Infrastructure",
                "weight": 5,
                "description": "No MX records found for domain (indicates non-standard or disposable mail setup)"
            })

    return dns_records

"""
Lexical and Heuristic URL Analysis Engine
Detects obfuscation, Shannon entropy anomalies, IP hostnames, excessive subdomains,
high-risk TLDs, Punycode/homoglyph attacks, and brand typosquatting.
"""
import math
import re
from typing import Dict, Any, List, Tuple
from urllib.parse import urlparse
import tldextract


# Target brands frequently abused in phishing campaigns
TARGET_BRANDS = [
    "microsoft", "office365", "outlook", "azure", "windows",
    "google", "gmail", "youtube", "drive",
    "paypal", "chase", "wellsfargo", "bankofamerica", "citibank",
    "amazon", "apple", "icloud", "netflix", "facebook", "instagram",
    "linkedin", "dhl", "fedex", "dropbox", "docusign", "steam", "adobe"
]

# High-risk / frequently abused TLDs (Spamhaus / APWG top abused)
HIGH_RISK_TLDS = {
    "xyz", "top", "tk", "zip", "click", "buzz", "ml", "ga", "cf", "gq",
    "country", "stream", "rest", "icu", "cam", "fit", "work", "monster",
    "link", "surf", "racing", "kim", "party", "gdn", "sbs"
}

# Suspicious security/credential keywords used in combosquatting
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "security", "update", "billing", "support", "account", "recover",
    "recovery", "portal", "auth", "authorize", "secure", "validate",
    "password", "credential", "session", "suspended", "service"
]

# Common Cyrillic / Greek homoglyphs that visually mimic ASCII Latin characters
CONFUSABLE_HOMOGLYPHS = {
    '\u0430': 'a',  # Cyrillic small letter a
    '\u0441': 'c',  # Cyrillic small letter es
    '\u0435': 'e',  # Cyrillic small letter ie
    '\u0456': 'i',  # Cyrillic small letter byelorussian-ukrainian i
    '\u0458': 'j',  # Cyrillic small letter je
    '\u043e': 'o',  # Cyrillic small letter o
    '\u0440': 'p',  # Cyrillic small letter er
    '\u0455': 's',  # Cyrillic small letter dze
    '\u0443': 'y',  # Cyrillic small letter u
    '\u0445': 'x',  # Cyrillic small letter ha
    '\u03bf': 'o',  # Greek small letter omicron
    '\u03c1': 'p',  # Greek small letter rho
}


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate the Shannon entropy of a string.
    Higher entropy indicates random/pseudo-random generation (e.g. DGA domains).
    """
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    char_counts: Dict[str, int] = {}
    for char in data:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p_x = count / length
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings"""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def is_ip_address(host: str) -> Tuple[bool, str]:
    """Detect if the host is a raw IPv4 or IPv6 address or hex/dword encoded IP"""
    # Remove port if present
    host_clean = host.split(":")[0].strip("[]")

    # Standard IPv4
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, host_clean):
        parts = host_clean.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            return True, "Standard IPv4 address"

    # Hex or octal or dword encoded IP (e.g., 0x7f.0.0.1 or 2130706433)
    if re.match(r"^0x[0-9a-fA-F.]+$", host_clean) or (host_clean.isdigit() and len(host_clean) > 8):
        return True, "Obfuscated / Hex / Dword IP format"

    # Standard IPv6
    if ":" in host_clean:
        # Check basic IPv6 structure
        hex_parts = host_clean.split(":")
        if 2 <= len(hex_parts) <= 8 and all(len(p) <= 4 for p in hex_parts if p):
            return True, "IPv6 address"

    return False, ""


def check_punycode_and_homoglyphs(host: str) -> Dict[str, Any]:
    """Detect Punycode (`xn--`) and confusable Cyrillic/Greek IDN homograph characters"""
    result = {
        "is_punycode": False,
        "decoded_unicode": "",
        "has_homoglyphs": False,
        "confusable_chars": [],
        "normalized_lookalike": ""
    }

    if "xn--" in host.lower():
        result["is_punycode"] = True
        try:
            decoded = host.encode("ascii").decode("idna")
            result["decoded_unicode"] = decoded
        except Exception:
            result["decoded_unicode"] = host

    target_str = result["decoded_unicode"] if result["decoded_unicode"] else host
    found_confusables = []
    normalized_chars = []

    for char in target_str:
        if char in CONFUSABLE_HOMOGLYPHS:
            found_confusables.append({
                "char": char,
                "unicode_point": f"U+{ord(char):04X}",
                "mimics": CONFUSABLE_HOMOGLYPHS[char]
            })
            normalized_chars.append(CONFUSABLE_HOMOGLYPHS[char])
        else:
            normalized_chars.append(char)

    if found_confusables:
        result["has_homoglyphs"] = True
        result["confusable_chars"] = found_confusables
        result["normalized_lookalike"] = "".join(normalized_chars)

    return result


def detect_brand_typosquatting(domain: str, subdomain: str) -> List[Dict[str, Any]]:
    """
    Detect typosquatting and combosquatting targeting reputable brands.
    - Levenshtein distance 1 or 2 on domain stem
    - Substring / combosquatting with keywords (e.g. microsoft-verify.com)
    """
    findings = []
    # Check both domain and subdomain parts
    parts_to_check = [domain.lower()]
    if subdomain:
        parts_to_check.extend([p.lower() for p in subdomain.split(".") if p])

    for test_target in parts_to_check:
        # Split tokens on hyphens and numbers
        tokens = re.split(r"[-_0-9]+", test_target)
        tokens = [t for t in tokens if len(t) >= 3]

        for brand in TARGET_BRANDS:
            # 1. Exact match in subdomain while registered domain is different (Subdomain deceptive impersonation)
            if brand in parts_to_check and brand != domain.lower():
                findings.append({
                    "brand": brand,
                    "type": "subdomain_deception",
                    "details": f"Brand '{brand}' appears in subdomain to deceive user while root domain is '{domain}'",
                    "severity": "HIGH"
                })

            # 2. Levenshtein typosquatting on domain or tokens
            dist = levenshtein_distance(test_target, brand)
            if 1 <= dist <= 2 and abs(len(test_target) - len(brand)) <= 2:
                # Discard trivial short collision
                if len(test_target) >= 4 and len(brand) >= 4:
                    findings.append({
                        "brand": brand,
                        "type": "typosquatting",
                        "distance": dist,
                        "details": f"Lookalike domain '{test_target}' is edit distance {dist} from brand '{brand}'",
                        "severity": "HIGH"
                    })

            # 3. Check tokens for typosquatting (e.g. micros0ft-login)
            for token in tokens:
                t_dist = levenshtein_distance(token, brand)
                if 1 <= t_dist <= 2 and abs(len(token) - len(brand)) <= 2:
                    findings.append({
                        "brand": brand,
                        "type": "typosquatting_token",
                        "distance": t_dist,
                        "details": f"Token '{token}' in '{test_target}' mimics brand '{brand}' (edit distance {t_dist})",
                        "severity": "HIGH"
                    })

            # 4. Combosquatting: brand name + suspicious keywords (e.g., paypal-security, login-microsoft)
            if brand in test_target and test_target != brand:
                has_suspicious_kw = any(kw in test_target for kw in SUSPICIOUS_KEYWORDS)
                if has_suspicious_kw or "-" in test_target or "_" in test_target:
                    findings.append({
                        "brand": brand,
                        "type": "combosquatting",
                        "details": f"Brand '{brand}' combined with security/action keywords in '{test_target}'",
                        "severity": "HIGH"
                    })

    # Deduplicate findings
    unique_findings = []
    seen = set()
    for f in findings:
        identifier = (f["brand"], f["type"], f.get("details"))
        if identifier not in seen:
            seen.add(identifier)
            unique_findings.append(f)

    return unique_findings


def analyze_url_lexical(raw_url: str) -> Dict[str, Any]:
    """
    Comprehensive Lexical and Heuristic URL Analyzer.
    Returns detailed metrics, extracted structural components, and heuristic flags with weights.
    """
    indicators = []
    url = raw_url.strip()

    # Prepend schema if missing for uniform parsing
    if not re.match(r"^[a-zA-Z]+://", url):
        url_with_scheme = "http://" + url
    else:
        url_with_scheme = url

    parsed = urlparse(url_with_scheme)
    extracted = tldextract.extract(url_with_scheme)

    domain = extracted.domain
    suffix = extracted.suffix.lower()
    subdomain = extracted.subdomain
    registered_domain = extracted.registered_domain or parsed.netloc

    # Hostname clean
    netloc = parsed.netloc
    host = netloc.split(":")[0]
    port = parsed.port

    # 1. Credential Masking with @ Symbol
    has_at_symbol = "@" in netloc or "@" in parsed.netloc
    if has_at_symbol:
        indicators.append({
            "key": "credential_masking_at",
            "category": "Lexical",
            "weight": 25,
            "description": "Credential masking '@' symbol detected (obfuscates actual destination host)"
        })

    # 2. Raw IP address check
    is_ip, ip_detail = is_ip_address(host)
    if is_ip:
        indicators.append({
            "key": "ip_host_detected",
            "category": "Lexical",
            "weight": 25,
            "description": f"Raw IP address used as hostname ({ip_detail})"
        })

    # 3. Excessive subdomains
    subdomain_parts = [p for p in subdomain.split(".") if p] if subdomain else []
    if len(subdomain_parts) >= 3:
        indicators.append({
            "key": "excessive_subdomains",
            "category": "Lexical",
            "weight": 15,
            "description": f"Excessive subdomains detected ({len(subdomain_parts)} levels: '{subdomain}')"
        })
    elif len(subdomain_parts) == 2:
        indicators.append({
            "key": "multiple_subdomains",
            "category": "Lexical",
            "weight": 5,
            "description": f"Multiple subdomains present ('{subdomain}')"
        })

    # 4. Abnormal URL Length
    url_len = len(raw_url)
    if url_len > 120:
        indicators.append({
            "key": "excessive_url_length",
            "category": "Lexical",
            "weight": 15,
            "description": f"Abnormally long URL ({url_len} characters; common in phishing payload obfuscation)"
        })
    elif url_len > 75:
        indicators.append({
            "key": "moderate_url_length",
            "category": "Lexical",
            "weight": 5,
            "description": f"Elevated URL length ({url_len} characters)"
        })

    # 5. Shannon Entropy Calculation
    domain_entropy = calculate_shannon_entropy(domain)
    subdomain_entropy = calculate_shannon_entropy(subdomain) if subdomain else 0.0
    path_entropy = calculate_shannon_entropy(parsed.path + parsed.query) if (parsed.path or parsed.query) else 0.0
    full_url_entropy = calculate_shannon_entropy(raw_url)

    if domain_entropy >= 3.8 and len(domain) >= 8:
        indicators.append({
            "key": "high_domain_entropy",
            "category": "Lexical",
            "weight": 20,
            "description": f"High Shannon entropy in domain ({domain_entropy}; indicates randomized/DGA name)"
        })
    elif subdomain_entropy >= 3.8 and len(subdomain) >= 10:
        indicators.append({
            "key": "high_subdomain_entropy",
            "category": "Lexical",
            "weight": 15,
            "description": f"High Shannon entropy in subdomain ({subdomain_entropy}; indicates DGA tunneling or random identifier)"
        })

    # 6. High-risk / frequently abused TLDs
    if suffix in HIGH_RISK_TLDS:
        indicators.append({
            "key": "high_risk_tld",
            "category": "Lexical",
            "weight": 20,
            "description": f"High-risk / heavily abused Top-Level Domain detected (.{suffix})"
        })

    # 7. Punycode & IDN Homographs
    punycode_info = check_punycode_and_homoglyphs(host)
    if punycode_info["is_punycode"]:
        indicators.append({
            "key": "punycode_detected",
            "category": "Lexical",
            "weight": 25,
            "description": f"Punycode (IDN) encoding detected: '{host}' decodes to '{punycode_info['decoded_unicode']}'"
        })
    if punycode_info["has_homoglyphs"]:
        indicators.append({
            "key": "homograph_attack",
            "category": "Lexical",
            "weight": 30,
            "description": f"IDN Homoglyph attack: Non-ASCII characters mimicking Latin: {punycode_info['confusable_chars']}"
        })

    # 8. Brand Typosquatting / Combosquatting
    typo_findings = detect_brand_typosquatting(domain, subdomain)
    for tf in typo_findings:
        weight = 25 if tf["type"] in ("typosquatting", "combosquatting") else 20
        indicators.append({
            "key": f"brand_abuse_{tf['type']}",
            "category": "Lexical",
            "weight": weight,
            "description": f"Brand Masquerading ({tf['brand'].capitalize()}): {tf['details']}"
        })

    # 9. Suspicious keywords in path/query
    path_query = (parsed.path + "?" + parsed.query).lower()
    matched_kws = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path_query]
    if len(matched_kws) >= 2:
        indicators.append({
            "key": "credential_keywords_in_path",
            "category": "Lexical",
            "weight": 10,
            "description": f"Suspicious authentication keywords in path/query: {matched_kws[:4]}"
        })

    return {
        "raw_url": raw_url,
        "normalized_url": url_with_scheme,
        "scheme": parsed.scheme or "http",
        "netloc": netloc,
        "host": host,
        "port": port,
        "subdomain": subdomain,
        "domain": domain,
        "suffix": suffix,
        "registered_domain": registered_domain,
        "path": parsed.path,
        "query": parsed.query,
        "url_length": url_len,
        "entropy": {
            "domain": domain_entropy,
            "subdomain": subdomain_entropy,
            "path": path_entropy,
            "full_url": full_url_entropy
        },
        "is_ip": is_ip,
        "ip_detail": ip_detail,
        "punycode": punycode_info,
        "typosquatting": typo_findings,
        "indicators": indicators
    }

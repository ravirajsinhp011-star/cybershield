import re
import math
from urllib.parse import urlparse
from typing import Dict, Any, List
from .risk_scorer import calculate_risk_level

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "update", "banking", "secure",
    "security", "account", "wallet", "confirm", "recovery", "password", "credential",
    "support", "service", "bonus", "reward", "prize", "airdrop", "claim", "kyc"
]

HIGH_RISK_TLDS = [
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".click",
    ".buzz", ".fit", ".rest", ".cc", ".monster", ".icu", ".cam"
]

KNOWN_SHORTENERS = [
    "bit.ly", "tinyurl.com", "is.gd", "t.co", "cutt.ly", "ow.ly", "buff.ly", "rebrand.ly"
]

TARGETED_BRANDS = [
    "paypal", "google", "apple", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "whatsapp", "telegram", "chase", "wellsfargo", "bankofamerica",
    "sbi", "hdfc", "icici", "paytm", "binance", "metamask", "coinbase"
]

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string (measures randomness/obfuscation)."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 2)

def check_admin_custom_rules(hostname: str, full_url: str) -> Dict[str, Any]:
    """Inspects if domain or URL matches admin-enforced custom threat rules."""
    try:
        from ..database import SessionLocal
        from ..models.threat_rule import ThreatRule
        db = SessionLocal()
        try:
            rules = db.query(ThreatRule).all()
            for rule in rules:
                pat = rule.pattern.lower().strip()
                if pat and (pat in hostname or pat in full_url):
                    if rule.rule_type == "whitelist":
                        return {
                            "matched": True,
                            "type": "whitelist",
                            "rule": rule
                        }
                    elif rule.rule_type == "blacklist":
                        return {
                            "matched": True,
                            "type": "blacklist",
                            "rule": rule
                        }
        finally:
            db.close()
    except Exception:
        pass
    return {"matched": False}

def analyze_url(raw_url: str) -> Dict[str, Any]:
    """Analyzes a URL for malicious indicators, phishing signals, and anomalies."""
    clean_url = raw_url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "http://" + clean_url

    parsed = urlparse(clean_url)
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    full_url = clean_url.lower()

    # 0. Check Admin Custom Rules (SOC Whitelist / Blacklist Overrides)
    rule_match = check_admin_custom_rules(hostname, full_url)
    if rule_match["matched"]:
        r = rule_match["rule"]
        if rule_match["type"] == "whitelist":
            return {
                "scan_type": "url",
                "target": raw_url,
                "risk_score": 0.0,
                "risk_level": "LOW",
                "badge_color": "#10b981",
                "summary": f"VERIFIED SAFE: Target matches Admin Whitelist policy rule: '{r.pattern}' ({r.reason or 'Authorized domain'}).",
                "findings": [{
                    "indicator": "Admin Whitelist Enforced",
                    "severity": "INFO",
                    "description": f"Domain '{r.pattern}' is officially whitelisted and trusted by organization SOC policy."
                }],
                "recommendations": ["This resource is verified safe by system administrators."],
                "technical_details": {"rule_override": "whitelist", "matched_pattern": r.pattern}
            }
        elif rule_match["type"] == "blacklist":
            return {
                "scan_type": "url",
                "target": raw_url,
                "risk_score": 100.0,
                "risk_level": "CRITICAL",
                "badge_color": "#ef4444",
                "summary": f"CRITICAL THREAT: Target matches Admin Custom Blacklist rule: '{r.pattern}' ({r.reason or 'Security Block'}).",
                "findings": [{
                    "indicator": "Admin Custom Blacklist Enforced",
                    "severity": "DANGER",
                    "description": f"Destination explicitly prohibited by administrator: '{r.pattern}' ({r.reason or 'Known threat'})."
                }],
                "recommendations": ["Access is prohibited. Do not visit this address under any circumstances."],
                "technical_details": {"rule_override": "blacklist", "matched_pattern": r.pattern}
            }

    findings: List[Dict[str, str]] = []
    recommendations: List[str] = []
    risk_points = 0.0

    # 1. Protocol check
    is_https = parsed.scheme == "https"
    if not is_https:
        risk_points += 20.0
        findings.append({
            "indicator": "Insecure Protocol (HTTP)",
            "severity": "WARNING",
            "description": "Connection is unencrypted (HTTP). Data transmitted can be intercepted by eavesdroppers."
        })
        recommendations.append("Never enter passwords, OTPs, or financial information on unencrypted HTTP pages.")
    else:
        findings.append({
            "indicator": "HTTPS Protocol",
            "severity": "INFO",
            "description": "Transport layer encryption is active. Note that modern phishing sites may also use free SSL certificates."
        })

    # 2. IP address used as hostname
    if IP_PATTERN.match(hostname):
        risk_points += 35.0
        findings.append({
            "indicator": "Raw IP Address Host",
            "severity": "DANGER",
            "description": f"URL directly uses an IP address ({hostname}) instead of a registered domain name. Typical of botnets and phishing hosts."
        })
        recommendations.append("Legitimate services virtually never direct users to raw numerical IP addresses.")

    # 3. URL Shortener detection
    if any(shortener in hostname for shortener in KNOWN_SHORTENERS):
        risk_points += 15.0
        findings.append({
            "indicator": "URL Shortening Service",
            "severity": "WARNING",
            "description": f"Domain matches known URL shortener ({hostname}). Attackers frequently use shorteners to mask final malicious destinations."
        })
        recommendations.append("Expand and inspect shortened URLs before clicking to verify the true landing destination.")

    # 4. Dangerous / High-Risk TLD
    matched_tld = next((tld for tld in HIGH_RISK_TLDS if hostname.endswith(tld)), None)
    if matched_tld:
        risk_points += 25.0
        findings.append({
            "indicator": f"High-Risk TLD ({matched_tld})",
            "severity": "WARNING",
            "description": f"The domain uses '{matched_tld}', which has a statistically elevated association with spam, phishing, and disposable domains."
        })

    # 5. Shannon Entropy (Random string / DGA detection)
    domain_entropy = calculate_entropy(hostname)
    if domain_entropy > 3.8 and len(hostname) > 12:
        risk_points += 20.0
        findings.append({
            "indicator": "High Domain Entropy (Random Characters)",
            "severity": "WARNING",
            "description": f"Domain name exhibits high algorithmic randomness (Entropy: {domain_entropy}). Often generated by Domain Generation Algorithms (DGA)."
        })

    # 6. Brand Spoofing / Typosquatting
    matched_brand = next((brand for brand in TARGETED_BRANDS if brand in full_url), None)
    if matched_brand:
        legit_domains = [f"{matched_brand}.com", f"{matched_brand}.org", f"{matched_brand}.net", f"{matched_brand}.in", f"{matched_brand}.co.in"]
        is_legit = any(hostname == legit or hostname.endswith("." + legit) for legit in legit_domains)
        if not is_legit:
            risk_points += 35.0
            findings.append({
                "indicator": f"Brand Impersonation / Typosquatting ({matched_brand.upper()})",
                "severity": "DANGER",
                "description": f"The URL references reputable brand '{matched_brand}', but the hosting domain is '{hostname}', indicating probable spoofing or credential theft."
            })
            recommendations.append(f"Visit {matched_brand}'s official website directly by typing their genuine address into your browser.")

    # 7. Suspicious Keywords in Path or Query
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path or kw in query]
    if matched_keywords:
        risk_points += min(25.0, len(matched_keywords) * 10.0)
        findings.append({
            "indicator": "Suspicious Security / Action Keywords",
            "severity": "WARNING",
            "description": f"Detected sensitive action keywords: {', '.join(matched_keywords)}. Phishing landing pages lure users to 'verify' or 'recover' accounts."
        })

    # 8. Suspicious Characters (@ symbol, excessive hyphens)
    if "@" in raw_url:
        risk_points += 30.0
        findings.append({
            "indicator": "Obfuscated '@' Symbol in URL",
            "severity": "DANGER",
            "description": "URL includes an '@' symbol. In standard URLs, text before '@' is treated as credentials, concealing the true server address."
        })

    subdomains = hostname.split(".")
    if len(subdomains) > 3:
        risk_points += 15.0
        findings.append({
            "indicator": "Excessive Subdomains",
            "severity": "WARNING",
            "description": f"Hostname contains {len(subdomains)} domain levels. Attackers use deep subdomains to imitate legitimate organizations."
        })

    if raw_url.count("-") >= 3:
        risk_points += 10.0
        findings.append({
            "indicator": "Excessive Hyphens in Domain/URL",
            "severity": "WARNING",
            "description": "Multiple hyphens detected. Frequently used to construct fake compound domain names (e.g., 'service-login-secure')."
        })

    if parsed.port and parsed.port not in [80, 443]:
        risk_points += 15.0
        findings.append({
            "indicator": f"Non-Standard Port ({parsed.port})",
            "severity": "WARNING",
            "description": f"The URL connects via unusual port {parsed.port} rather than standard web ports (80/443)."
        })

    if not recommendations:
        recommendations.append("Always verify the domain name in your browser address bar before entering private information.")
        recommendations.append("Keep your browser and antivirus signatures up to date.")

    tier = calculate_risk_level(risk_points)

    technical_details = {
        "hostname": hostname,
        "protocol": parsed.scheme,
        "domain_entropy": domain_entropy,
        "url_length": len(raw_url),
        "subdomain_count": len(subdomains),
        "suspicious_keywords_found": matched_keywords,
        "raw_points": risk_points
    }

    return {
        "scan_type": "url",
        "target": raw_url,
        "risk_score": tier["score"],
        "risk_level": tier["level"],
        "badge_color": tier["badge_color"],
        "summary": tier["summary"],
        "findings": findings,
        "recommendations": recommendations,
        "technical_details": technical_details
    }

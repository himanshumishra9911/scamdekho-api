import requests
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime
import whois
import os

GOOGLE_SAFE_API_KEY = os.getenv("GOOGLE_SAFE_API_KEY")


# ======================================
# DOMAIN BASIC SIGNALS
# ======================================
def rule_based_signals(domain):
    score = 0
    reasons = []

    bad_tlds = [".xyz", ".top", ".club", ".click", ".info"]

    if any(domain.endswith(tld) for tld in bad_tlds):
        score += 25
        reasons.append("Suspicious domain extension")

    if domain.count("-") >= 3:
        score += 15
        reasons.append("Too many hyphens in domain")

    if sum(c.isdigit() for c in domain) > 4:
        score += 10
        reasons.append("Too many numbers in domain")

    return score, reasons


# ======================================
# DOMAIN AGE
# ======================================
def check_domain_age(domain):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days

            if age_days < 180:
                return 35, "Domain is very new (less than 6 months old)"
            elif age_days < 365:
                return 15, "Domain less than 1 year old"

        return 0, None

    except Exception:
        return 10, "Could not verify domain age"


# ======================================
# SSL CHECK
# ======================================
def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                return 0, None
    except Exception:
        return 20, "SSL certificate invalid or missing"


# ======================================
# WEBSITE STATUS CHECK (LIGHTWEIGHT)
# ======================================
def check_website_status(url):
    try:
        r = requests.head(url, timeout=4, allow_redirects=True)
        if 200 <= r.status_code < 400:
            return 0, None
        return 20, "Website returned abnormal HTTP status"
    except Exception:
        return 25, "Website unreachable"


# ======================================
# GOOGLE SAFE BROWSING
# ======================================
def check_google_safe(url):
    if not GOOGLE_SAFE_API_KEY:
        return 0, None

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_API_KEY}"

    body = {
        "client": {"clientId": "scamdekho", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        r = requests.post(endpoint, json=body, timeout=4)
        if r.status_code == 200 and r.json().get("matches"):
            return 60, "Flagged by Google Safe Browsing"
        return 0, None
    except Exception:
        return 0, None


# ======================================
# IP + ASN + GEO CHECK
# ======================================
def check_ip_reputation(domain):
    try:
        ip = socket.gethostbyname(domain)

        r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp,org", timeout=4)
        data = r.json()

        score = 0
        reasons = []

        # Suspicious hosting providers (cheap hosting abused often)
        risky_hosts = ["ovh", "digitalocean", "vultr", "linode", "contabo"]

        if any(host in data.get("isp", "").lower() for host in risky_hosts):
            score += 10
            reasons.append("Hosted on commonly abused infrastructure")

        # High risk geographies (optional risk signal)
        high_risk_countries = ["RU", "CN", "KP"]

        if data.get("countryCode") in high_risk_countries:
            score += 15
            reasons.append("Hosting country considered high risk")

        return score, reasons

    except Exception:
        return 0, []


# ======================================
# FINAL ANALYSIS ENGINE
# ======================================
def analyze_url(url):

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    total_score = 0
    reasons = []

    # Basic rules
    score, rule_reasons = rule_based_signals(domain)
    total_score += score
    reasons.extend(rule_reasons)

    # Domain age
    age_score, age_reason = check_domain_age(domain)
    total_score += age_score
    if age_reason:
        reasons.append(age_reason)

    # SSL
    ssl_score, ssl_reason = check_ssl(domain)
    total_score += ssl_score
    if ssl_reason:
        reasons.append(ssl_reason)

    # HTTP status
    status_score, status_reason = check_website_status(url)
    total_score += status_score
    if status_reason:
        reasons.append(status_reason)

    # Google Safe Browsing
    safe_score, safe_reason = check_google_safe(url)
    total_score += safe_score
    if safe_reason:
        reasons.append(safe_reason)

    # IP Reputation
    ip_score, ip_reasons = check_ip_reputation(domain)
    total_score += ip_score
    reasons.extend(ip_reasons)

    total_score = min(total_score, 100)

    # ======================================
    # FINAL VERDICT LOGIC
    # ======================================
    if total_score >= 75:
        verdict = "SCAM DETECTED"
    elif total_score >= 40:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    return {
        "risk_score": total_score,
        "verdict": verdict,
        "reasons": reasons
    }

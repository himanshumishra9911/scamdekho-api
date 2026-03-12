import asyncio
import socket
import ssl
import os
import re
import httpx
import whois
from urllib.parse import urlparse
from datetime import datetime

GOOGLE_SAFE_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")


# ======================================
# DOMAIN BASIC SIGNALS
# ======================================
def rule_based_signals(domain: str):
    score = 0
    reasons = []

    bad_tlds = [".xyz", ".top", ".club", ".click", ".info", ".tk", ".ml", ".ga", ".cf", ".gq"]
    if any(domain.endswith(tld) for tld in bad_tlds):
        score += 25
        reasons.append("Suspicious domain extension")

    if domain.count("-") >= 3:
        score += 15
        reasons.append("Too many hyphens in domain")

    if sum(c.isdigit() for c in domain) > 4:
        score += 10
        reasons.append("Too many numbers in domain")

    scam_keywords = [
        "kyc", "verify", "update", "secure", "login",
        "refund", "prize", "reward", "lucky", "winner",
        "helpdesk", "support", "care", "paytm", "sbi",
        "hdfc", "icici", "npci", "upi", "free-gift"
    ]
    for kw in scam_keywords:
        if kw in domain:
            score += 20
            reasons.append(f"Scam keyword in domain: '{kw}'")
            break

    url_shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "short.ly"]
    if any(s in domain for s in url_shorteners):
        score += 15
        reasons.append("URL shortener detected — hides real destination")

    return min(score, 60), reasons


# ======================================
# DOMAIN AGE — WHOIS
# ======================================
def check_domain_age(domain: str):
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date).days
            if age_days < 30:
                return 40, f"Very new domain — only {age_days} days old"
            elif age_days < 90:
                return 25, f"New domain — {age_days} days old"
            elif age_days < 180:
                return 15, f"Relatively new domain — {age_days} days old"
            elif age_days < 365:
                return 10, f"Domain less than 1 year old"
            elif age_days > 730:
                return -10, None  # Established — lower risk
        return 0, None
    except Exception:
        return 10, "Could not verify domain age"


# ======================================
# SSL CHECK
# ======================================
def check_ssl(domain: str):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                return 0, None
    except Exception:
        return 20, "SSL certificate invalid or missing"


# ======================================
# GOOGLE SAFE BROWSING — ASYNC
# ======================================
async def check_google_safe(url: str):
    if not GOOGLE_SAFE_API_KEY:
        return 0, None
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_API_KEY}"
        payload = {
            "client": {"clientId": "scamdekho", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(endpoint, json=payload)
            if r.status_code == 200 and r.json().get("matches"):
                return 85, "Flagged by Google Safe Browsing"
        return 0, None
    except Exception:
        return 0, None


# ======================================
# OPENPHISH — No key needed
# ======================================
async def check_openphish(url: str):
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get("https://openphish.com/feed.txt")
            feed_urls = [line.strip() for line in r.text.splitlines() if line.strip()]
            for feed_url in feed_urls:
                if url.startswith(feed_url) or feed_url.startswith(url):
                    return 80, "Listed in OpenPhish phishing database"
        return 0, None
    except Exception:
        return 0, None


# ======================================
# URLHAUS — No key needed
# ======================================
async def check_urlhaus(url: str):
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url}
            )
            data = r.json()
            if data.get("query_status") == "is_listed":
                return 80, "Listed in URLhaus malware database"
        return 0, None
    except Exception:
        return 0, None


# ======================================
# HTTP HEADERS — ASYNC
# ======================================
async def check_http_headers(url: str):
    score = 0
    reasons = []
    try:
        async with httpx.AsyncClient(
            timeout=7.0,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        ) as client:
            response = await client.get(url)

            if len(response.history) > 3:
                score += 20
                reasons.append(f"Too many redirects ({len(response.history)})")

            if response.history:
                final_domain = str(response.url).split("/")[2]
                orig_domain = url.split("/")[2]
                if final_domain != orig_domain:
                    score += 25
                    reasons.append(f"Redirects to different domain: {final_domain}")

            if len(response.text) < 300:
                score += 10
                reasons.append("Very thin page content — possible fake page")

    except Exception as e:
        score += 15
        reasons.append("Site unreachable or blocked")

    return min(score, 50), reasons


# ======================================
# IP REPUTATION
# ======================================
async def check_ip_reputation(domain: str):
    try:
        ip = socket.gethostbyname(domain)
        async with httpx.AsyncClient(timeout=4.0) as client:
            r = await client.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,org")
            data = r.json()

        score = 0
        reasons = []

        risky_hosts = ["ovh", "digitalocean", "vultr", "linode", "contabo", "hostinger"]
        if any(host in data.get("isp", "").lower() for host in risky_hosts):
            score += 10
            reasons.append("Hosted on commonly abused infrastructure")

        high_risk_countries = ["RU", "CN", "KP", "NG"]
        if data.get("countryCode") in high_risk_countries:
            score += 15
            reasons.append(f"Hosted in high-risk country: {data.get('country')}")

        return score, reasons
    except Exception:
        return 0, []


# ======================================
# MASTER FUNCTION — ALL PARALLEL
# ======================================
async def analyze_url_full(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower().replace("www.", "")

    # Sync checks
    rule_score, rule_reasons = rule_based_signals(domain)
    age_score, age_reason = check_domain_age(domain)
    ssl_score, ssl_reason = check_ssl(domain)

    # Async checks — sab parallel mein
    google_result, openphish_result, urlhaus_result, headers_result, ip_result = await asyncio.gather(
        check_google_safe(url),
        check_openphish(url),
        check_urlhaus(url),
        check_http_headers(url),
        check_ip_reputation(domain),
        return_exceptions=True
    )

    # Handle exceptions
    def safe(result, default): return default if isinstance(result, Exception) else result

    google_score, google_reason = safe(google_result, (0, None))
    openphish_score, openphish_reason = safe(openphish_result, (0, None))
    urlhaus_score, urlhaus_reason = safe(urlhaus_result, (0, None))
    headers_score, headers_reasons = safe(headers_result, (0, []))
    ip_score, ip_reasons = safe(ip_result, (0, []))

    # Collect all signals
    signals = []
    for reason in [google_reason, openphish_reason, urlhaus_reason, age_reason, ssl_reason]:
        if reason:
            signals.append(reason)
    signals.extend(rule_reasons)
    signals.extend(headers_reasons)
    signals.extend(ip_reasons)

    # Total score
    total = (
        rule_score + age_score + ssl_score +
        google_score + openphish_score + urlhaus_score +
        headers_score + ip_score
    )
    total = min(total, 100)

    blacklisted = any([
        google_score >= 80,
        openphish_score >= 80,
        urlhaus_score >= 80
    ])

    return {
        "total_score": total,
        "signals": signals,
        "blacklisted": blacklisted,
        "domain": domain
    }

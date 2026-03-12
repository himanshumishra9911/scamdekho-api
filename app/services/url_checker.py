import asyncio
import socket
import ssl
import os
import httpx
import whois
from urllib.parse import urlparse
from datetime import datetime

GOOGLE_SAFE_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")


# ======================================
# DOMAIN AGE — WHOIS
# ======================================
def check_domain_age(domain: str):
    try:
        import subprocess
        import re

        # System whois command use karo — most reliable
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.lower()

        # Multiple date patterns try karo
        patterns = [
            r"creation date[:\s]+([0-9]{4}-[0-9]{2}-[0-9]{2})",
            r"created[:\s]+([0-9]{4}-[0-9]{2}-[0-9]{2})",
            r"registered on[:\s]+([0-9]{4}-[0-9]{2}-[0-9]{2})",
            r"domain registered[:\s]+([0-9]{4}-[0-9]{2}-[0-9]{2})",
            r"created date[:\s]+([0-9]{4}-[0-9]{2}-[0-9]{2})",
        ]

        creation_date = None
        for pattern in patterns:
            match = re.search(pattern, output)
            if match:
                creation_date = datetime.strptime(match.group(1), "%Y-%m-%d")
                break

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
                return -10, f"Established domain — {age_days} days old"
            else:
                return 0, f"Domain {age_days} days old"

        # Fallback — python-whois try karo
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
                return -10, f"Established domain — {age_days} days old"
            else:
                return 0, f"Domain {age_days} days old"

        # Dono fail — koi penalty nahi
        return 0, None

    except Exception:
        return 0, None  # Fail hone pe koi penalty nahi

# ======================================
# SSL CHECK
# ======================================
def check_ssl(domain: str):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                expiry = cert.get("notAfter", "")
                return 0, f"SSL valid — issuer: {issuer.get('organizationName', 'Unknown')}, expires: {expiry}"
    except ssl.SSLCertVerificationError:
        return 30, "SSL certificate verification failed"
    except Exception:
        return 20, "SSL certificate missing or invalid"


# ======================================
# GOOGLE SAFE BROWSING
# ======================================
async def check_google_safe(url: str):
    if not GOOGLE_SAFE_API_KEY:
        return 0, "Google Safe Browsing: API key not set"
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
                return 85, "DANGER: Listed in Google Safe Browsing database"
        return 0, "Google Safe Browsing: Clean"
    except Exception:
        return 0, "Google Safe Browsing: Check failed"


# ======================================
# OPENPHISH
# ======================================
async def check_openphish(url: str):
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get("https://openphish.com/feed.txt")
            feed_urls = [line.strip() for line in r.text.splitlines() if line.strip()]
            for feed_url in feed_urls:
                if url.startswith(feed_url) or feed_url.startswith(url):
                    return 80, "DANGER: Listed in OpenPhish phishing database"
        return 0, "OpenPhish: Clean"
    except Exception:
        return 0, "OpenPhish: Check failed"


# ======================================
# URLHAUS
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
                return 80, "DANGER: Listed in URLhaus malware database"
        return 0, "URLhaus: Clean"
    except Exception:
        return 0, "URLhaus: Check failed"


# ======================================
# HTTP HEADERS + REDIRECT CHECK
# ======================================
async def check_http_headers(url: str):
    score = 0
    notes = []
    try:
        async with httpx.AsyncClient(
            timeout=8.0,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        ) as client:
            response = await client.get(url)

            # Redirect count
            notes.append(f"Redirects: {len(response.history)}")
            if len(response.history) > 3:
                score += 20
                notes.append("WARNING: Too many redirects")

            # Domain changed after redirect
            if response.history:
                final_domain = str(response.url).split("/")[2]
                orig_domain = url.split("/")[2]
                if final_domain != orig_domain:
                    score += 25
                    notes.append(f"WARNING: Redirects to different domain: {final_domain}")
                else:
                    notes.append(f"Final domain: {final_domain}")

            # HTTP status
            notes.append(f"HTTP Status: {response.status_code}")

            # Content size
            content_len = len(response.text)
            notes.append(f"Page content size: {content_len} chars")
            if content_len < 300:
                score += 15
                notes.append("WARNING: Very thin page content")

    except Exception as e:
        score += 15
        notes.append(f"Site unreachable: {str(e)[:80]}")

    return min(score, 50), notes


# ======================================
# IP + HOSTING CHECK
# ======================================
async def check_ip_info(domain: str):
    notes = []
    score = 0
    try:
        ip = socket.gethostbyname(domain)
        notes.append(f"IP: {ip}")

        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,org,hosting"
            )
            data = r.json()

        notes.append(f"Hosting country: {data.get('country', 'Unknown')}")
        notes.append(f"ISP: {data.get('isp', 'Unknown')}")
        notes.append(f"Is hosting provider: {data.get('hosting', False)}")

        high_risk_countries = ["RU", "CN", "KP", "NG"]
        if data.get("countryCode") in high_risk_countries:
            score += 15
            notes.append(f"WARNING: Hosted in high-risk country")

    except Exception as e:
        notes.append(f"IP info unavailable: {str(e)[:50]}")

    return score, notes


# ======================================
# MASTER FUNCTION
# ======================================
async def analyze_url_full(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower().replace("www.", "")

    # Sync checks
    age_score, age_note = check_domain_age(domain)
    ssl_score, ssl_note = check_ssl(domain)

    # Async checks — all parallel
    google_result, openphish_result, urlhaus_result, headers_result, ip_result = await asyncio.gather(
        check_google_safe(url),
        check_openphish(url),
        check_urlhaus(url),
        check_http_headers(url),
        check_ip_info(domain),
        return_exceptions=True
    )

    def safe(result, default):
        return default if isinstance(result, Exception) else result

    google_score, google_note = safe(google_result, (0, "Google SB: Failed"))
    openphish_score, openphish_note = safe(openphish_result, (0, "OpenPhish: Failed"))
    urlhaus_score, urlhaus_note = safe(urlhaus_result, (0, "URLhaus: Failed"))
    headers_score, headers_notes = safe(headers_result, (0, []))
    ip_score, ip_notes = safe(ip_result, (0, []))

    # Build complete technical report for AI
    technical_report = f"""
DOMAIN: {domain}
URL: {url}

BLACKLIST CHECKS:
- {google_note}
- {openphish_note}
- {urlhaus_note}

DOMAIN AGE:
- {age_note}

SSL CERTIFICATE:
- {ssl_note}

HTTP / REDIRECT ANALYSIS:
{chr(10).join(f'- {n}' for n in headers_notes)}

IP / HOSTING INFO:
{chr(10).join(f'- {n}' for n in ip_notes)}
""".strip()

    total = min(
        age_score + ssl_score + google_score +
        openphish_score + urlhaus_score +
        headers_score + ip_score,
        100
    )

    blacklisted = google_score >= 80 or openphish_score >= 80 or urlhaus_score >= 80

    return {
        "total_score": total,
        "technical_report": technical_report,
        "blacklisted": blacklisted,
        "domain": domain
    }

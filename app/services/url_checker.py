import asyncio
import socket
import ssl
import os
import re
import httpx
import whois
from urllib.parse import urlparse, quote
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ======================================
# API KEYS — SAB FREE HAI
# ======================================
GOOGLE_SAFE_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")  # Free 1000/day

executor = ThreadPoolExecutor(max_workers=5)

# ======================================
# SOURCE WEIGHTS
# ======================================
SOURCE_WEIGHTS = {
    "Google Safe Browsing": 0.95,
    "PhishDestroy": 0.85,
    "OpenPhish": 0.85,
    "URLhaus": 0.85,
    "PhishTank": 0.80,
    "AbuseIPDB": 0.85,
    "DNS Security": 0.70,
    "SSL Certificate": 0.80,
    "Domain Age": 0.55,
    "HTTP Analysis": 0.55,
    "IP & Hosting": 0.45,
    "Content Analysis": 0.50,
    "URL Patterns": 0.75,
}


# ======================================
# 1. DOMAIN AGE (SYNC, FREE)
# ======================================
def check_domain_age(domain: str):
    try:
        info = whois.whois(domain)
        creation = info.creation_date
        registrar = info.registrar or "Unknown"
        expiry = info.expiration_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(expiry, list):
            expiry = expiry[0]

        if creation:
            age_days = (datetime.now() - creation).days
            created_str = creation.strftime("%B %d, %Y")
            expiry_warn = ""
            if expiry:
                dte = (expiry - datetime.now()).days
                if dte < 30:
                    expiry_warn = " | Expiring very soon!"
                elif dte < 90:
                    expiry_warn = " | Expires within 3 months"

            if age_days < 30:
                return {"score": 40, "status": "negative", "message": f"Very new domain — only {age_days} days old", "detail": f"Created: {created_str} | Registrar: {registrar}{expiry_warn}", "age_days": age_days, "created": created_str}
            elif age_days < 90:
                return {"score": 25, "status": "negative", "message": f"New domain — {age_days} days old", "detail": f"Created: {created_str} | Registrar: {registrar}{expiry_warn}", "age_days": age_days, "created": created_str}
            elif age_days < 180:
                return {"score": 15, "status": "neutral", "message": f"Relatively new domain — {age_days} days old", "detail": f"Created: {created_str} | Registrar: {registrar}{expiry_warn}", "age_days": age_days, "created": created_str}
            elif age_days < 365:
                return {"score": 10, "status": "neutral", "message": "Domain less than 1 year old", "detail": f"Created: {created_str} | Registrar: {registrar}{expiry_warn}", "age_days": age_days, "created": created_str}
            elif age_days > 730:
                return {"score": -10, "status": "positive", "message": f"Established domain — {age_days // 365} years old", "detail": f"Created: {created_str} | Registrar: {registrar}", "age_days": age_days, "created": created_str}
            else:
                return {"score": 0, "status": "positive", "message": f"Domain {age_days} days old", "detail": f"Created: {created_str} | Registrar: {registrar}", "age_days": age_days, "created": created_str}
        return {"score": 5, "status": "neutral", "message": "Domain age unavailable", "detail": f"Registrar: {registrar}", "age_days": None, "created": None}
    except Exception:
        return {"score": 5, "status": "neutral", "message": "Domain age unavailable", "detail": "WHOIS lookup failed", "age_days": None, "created": None}


# ======================================
# 2. SSL CHECK (SYNC, FREE)
# ======================================
def check_ssl(domain: str):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                expiry = cert.get("notAfter", "")
                org = issuer.get("organizationName", "Unknown")
                icn = issuer.get("commonName", "")
                scn = subject.get("commonName", "")
                if icn == scn and org == "Unknown":
                    return {"score": 20, "status": "negative", "message": "Self-signed SSL certificate", "detail": f"Not issued by trusted CA | CN: {scn}", "issuer": org, "expiry": expiry}
                return {"score": 0, "status": "positive", "message": f"SSL valid — Issuer: {org}", "detail": f"Expires: {expiry} | CN: {scn}", "issuer": org, "expiry": expiry}
    except ssl.SSLCertVerificationError:
        return {"score": 30, "status": "negative", "message": "SSL certificate verification FAILED", "detail": "Certificate invalid", "issuer": None, "expiry": None}
    except Exception:
        return {"score": 20, "status": "negative", "message": "SSL certificate missing or invalid", "detail": "No valid SSL found", "issuer": None, "expiry": None}


# ======================================
# 3. GOOGLE SAFE BROWSING (FREE)
# ======================================
async def check_google_safe(url: str):
    if not GOOGLE_SAFE_API_KEY:
        return {"score": 0, "status": "neutral", "message": "Google Safe Browsing: API key not set", "detail": "Set GOOGLE_SAFE_BROWSING_KEY"}
    try:
        payload = {
            "client": {"clientId": "scamdekho", "clientVersion": "2.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_API_KEY}", json=payload)
            if r.status_code == 200 and r.json().get("matches"):
                threats = [m.get("threatType", "") for m in r.json()["matches"]]
                return {"score": 85, "status": "negative", "message": "DANGER: Listed in Google Safe Browsing", "detail": f"Threats: {', '.join(threats)}"}
        return {"score": 0, "status": "positive", "message": "Google Safe Browsing: Clean", "detail": "Not reported for phishing or malware"}
    except Exception:
        return {"score": 0, "status": "neutral", "message": "Google Safe Browsing: Check failed", "detail": "API unreachable"}


# ======================================
# 4. PHISHDESTROY (100% FREE, NO KEY)
# ======================================
async def check_phishdestroy(domain: str):
    try:
        async with httpx.AsyncClient(timeout=6.0) as c:
            r = await c.get("https://api.destroy.tools/v1/check", params={"domain": domain})
            if r.status_code == 200:
                d = r.json()
                threat = d.get("threat", False)
                severity = d.get("severity", "none")
                risk = d.get("risk_score", 0)
                flags = d.get("flags", [])
                if threat and severity in ["critical", "high"]:
                    return {"score": 80, "status": "negative", "message": f"DANGER: PhishDestroy — {severity.upper()} threat", "detail": f"Risk: {risk}/100 | Flags: {', '.join(flags[:5])}", "risk_score": risk}
                elif threat and severity == "medium":
                    return {"score": 40, "status": "negative", "message": "WARNING: PhishDestroy — Medium threat", "detail": f"Risk: {risk}/100 | Flags: {', '.join(flags[:5])}", "risk_score": risk}
                elif threat:
                    return {"score": 20, "status": "negative", "message": "PhishDestroy: Low threat", "detail": f"Risk: {risk}/100", "risk_score": risk}
                else:
                    return {"score": 0, "status": "positive", "message": "PhishDestroy: Clean", "detail": "Not in 770K+ threat database", "risk_score": 0}
        return {"score": 0, "status": "neutral", "message": "PhishDestroy: Check failed", "detail": "API error"}
    except Exception:
        return {"score": 0, "status": "neutral", "message": "PhishDestroy: Check failed", "detail": "Unreachable"}


# ======================================
# 5. OPENPHISH (FREE, NO KEY)
# ======================================
async def check_openphish(url: str):
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.get("https://openphish.com/feed.txt")
            for line in r.text.splitlines():
                line = line.strip()
                if line and (url.startswith(line) or line.startswith(url)):
                    return {"score": 80, "status": "negative", "message": "DANGER: Listed in OpenPhish", "detail": "Confirmed active phishing"}
        return {"score": 0, "status": "positive", "message": "OpenPhish: Clean", "detail": "Not reported for phishing"}
    except Exception:
        return {"score": 0, "status": "neutral", "message": "OpenPhish: Check failed", "detail": "Feed unreachable"}


# ======================================
# 6. URLHAUS (FREE, NO KEY)
# ======================================
async def check_urlhaus(url: str):
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url})
            d = r.json()
            if d.get("query_status") == "is_listed":
                return {"score": 80, "status": "negative", "message": "DANGER: Listed in URLhaus", "detail": f"Threat: {d.get('threat', 'malware')}"}
        return {"score": 0, "status": "positive", "message": "URLhaus: Clean", "detail": "Not reported for malware"}
    except Exception:
        return {"score": 0, "status": "neutral", "message": "URLhaus: Check failed", "detail": "API unreachable"}


# ======================================
# 7. PHISHTANK (FREE, works without key)
# ======================================
async def check_phishtank(url: str):
    try:
        data = {"url": url, "format": "json"}
        key = os.getenv("PHISHTANK_APP_KEY", "")
        if key:
            data["app_key"] = key
        async with httpx.AsyncClient(timeout=8.0) as c:
            r = await c.post("https://checkurl.phishtank.com/checkurl/", data=data)
            if r.status_code == 200:
                res = r.json().get("results", {})
                if res.get("in_database") and res.get("valid"):
                    return {"score": 80, "status": "negative", "message": "DANGER: PhishTank — Confirmed phishing", "detail": f"Phish ID: {res.get('phish_id', '')}"}
                elif res.get("in_database"):
                    return {"score": 30, "status": "negative", "message": "PhishTank: In database (unverified)", "detail": "Reported but not yet verified"}
        return {"score": 0, "status": "positive", "message": "PhishTank: Clean", "detail": "Not reported as phishing"}
    except Exception:
        return {"score": 0, "status": "neutral", "message": "PhishTank: Check failed", "detail": "API unreachable"}


# ======================================
# 8. ABUSEIPDB (FREE 1000/day)
# ======================================
async def check_abuseipdb(ip_address: str):
    if not ABUSEIPDB_API_KEY or not ip_address:
        return {"score": 0, "status": "neutral", "message": "AbuseIPDB: Not configured", "detail": "Set ABUSEIPDB_API_KEY", "abuse_score": None}
    try:
        async with httpx.AsyncClient(timeout=6.0) as c:
            r = await c.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip_address, "maxAgeInDays": 90}, headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"})
            if r.status_code == 200:
                d = r.json().get("data", {})
                abuse = d.get("abuseConfidenceScore", 0)
                reports = d.get("totalReports", 0)
                isp = d.get("isp", "Unknown")
                cc = d.get("countryCode", "??")
                detail = f"Reports: {reports} | ISP: {isp} | Country: {cc}"
                if abuse >= 80:
                    return {"score": 50, "status": "negative", "message": f"AbuseIPDB: HIGH abuse ({abuse}%)", "detail": detail, "abuse_score": abuse}
                elif abuse >= 40:
                    return {"score": 25, "status": "negative", "message": f"AbuseIPDB: Moderate abuse ({abuse}%)", "detail": detail, "abuse_score": abuse}
                elif abuse > 0:
                    return {"score": 10, "status": "neutral", "message": f"AbuseIPDB: Low abuse ({abuse}%)", "detail": detail, "abuse_score": abuse}
                else:
                    return {"score": 0, "status": "positive", "message": "AbuseIPDB: Clean IP", "detail": detail, "abuse_score": 0}
        return {"score": 0, "status": "neutral", "message": "AbuseIPDB: Check failed", "detail": "API error", "abuse_score": None}
    except Exception:
        return {"score": 0, "status": "neutral", "message": "AbuseIPDB: Check failed", "detail": "Unreachable", "abuse_score": None}


# ======================================
# 9. DNS SECURITY (FREE via Cloudflare DoH)
# ======================================
async def check_dns_security(domain: str):
    score = 0
    findings = []
    status = "positive"
    try:
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.get("https://cloudflare-dns.com/dns-query", params={"name": domain, "type": "A"}, headers={"Accept": "application/dns-json"})
            dns = r.json()
            if dns.get("Status") == 3:
                return {"score": 30, "status": "negative", "message": "DNS: Domain does not exist (NXDOMAIN)", "detail": "Domain not found"}
            if dns.get("AD", False):
                findings.append("DNSSEC: Enabled")
            else:
                findings.append("DNSSEC: Not enabled")
                score += 5
            mx = await c.get("https://cloudflare-dns.com/dns-query", params={"name": domain, "type": "MX"}, headers={"Accept": "application/dns-json"})
            if mx.json().get("Answer"):
                findings.append("MX: Present")
            else:
                findings.append("MX: None")
                score += 5
            txt = await c.get("https://cloudflare-dns.com/dns-query", params={"name": domain, "type": "TXT"}, headers={"Accept": "application/dns-json"})
            if any("v=spf1" in str(a.get("data", "")) for a in txt.json().get("Answer", [])):
                findings.append("SPF: Present")
            else:
                findings.append("SPF: Missing")
                score += 3
        if score >= 10:
            status = "neutral"
    except Exception as e:
        findings.append(f"DNS error: {str(e)[:50]}")
        status = "neutral"
    return {"score": min(score, 30), "status": status, "message": "DNS: " + ("Issues found" if score > 5 else "OK"), "detail": " | ".join(findings)}


# ======================================
# 10. HTTP HEADERS + REDIRECTS (FREE)
# ======================================
async def check_http_headers(url: str):
    score = 0
    findings = []
    status = "positive"
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}) as c:
            resp = await c.get(url)
            rcount = len(resp.history)
            if rcount > 3:
                score += 20; status = "negative"; findings.append(f"Too many redirects ({rcount})")
            elif rcount > 0:
                findings.append(f"Redirects: {rcount}")
            if resp.history:
                fd = str(resp.url).split("/")[2]
                od = url.split("/")[2]
                if fd != od:
                    score += 25; status = "negative"; findings.append(f"Redirects to different domain: {fd}")
            findings.append(f"HTTP {resp.status_code}")
            hdrs = resp.headers
            sec_count = sum(1 for h in ["x-frame-options", "x-content-type-options", "strict-transport-security", "content-security-policy"] if h in hdrs)
            if sec_count >= 3:
                findings.append(f"Security headers: {sec_count}/4")
            elif sec_count == 0:
                score += 10; findings.append("Security headers: None")
                if status == "positive": status = "neutral"
            else:
                findings.append(f"Security headers: {sec_count}/4")
            cl = len(resp.text)
            if cl < 300:
                score += 15; status = "negative"; findings.append(f"Very thin page ({cl} chars)")
            else:
                findings.append(f"Content: {cl} chars")
    except Exception as e:
        score += 15; status = "negative"; findings.append(f"Unreachable: {str(e)[:80]}")
    return {"score": min(score, 50), "status": status, "message": "HTTP: " + ("Issues" if status == "negative" else "OK"), "detail": " | ".join(findings)}


# ======================================
# 11. CONTENT ANALYSIS (FREE)
# ======================================
async def check_content_analysis(url: str):
    score = 0
    findings = []
    status = "positive"
    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}) as c:
            resp = await c.get(url)
            html = resp.text.lower()
            scam_patterns = {
                "verify your account": 5, "unusual activity": 5, "confirm your identity": 4,
                "update your payment": 5, "click here immediately": 4, "act now": 3,
                "wallet connect": 4, "seed phrase": 5, "private key": 5,
                "airdrop claim": 5, "lottery winner": 5, "congratulations you won": 5,
                "double your money": 5, "guaranteed returns": 5, "invest now": 3,
            }
            triggered = []
            for pat, w in scam_patterns.items():
                if pat in html:
                    score += w; triggered.append(pat)
            pw_fields = len(re.findall(r'type=["\']password["\']', html))
            if pw_fields > 1:
                score += 10; triggered.append(f"Multiple password fields ({pw_fields})")
            hidden_iframes = len(re.findall(r'<iframe[^>]*style=["\'][^"\']*display\s*:\s*none', html))
            if hidden_iframes > 0:
                score += 15; triggered.append(f"Hidden iframes ({hidden_iframes})")
            form_actions = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', html)
            for action in form_actions:
                if action.startswith("http") and urlparse(url).netloc not in action:
                    score += 20; triggered.append("Form submits to external domain"); break
            if score >= 15:
                status = "negative"; findings.append(f"Suspicious: {', '.join(triggered[:5])}")
            elif score > 5:
                status = "neutral"; findings.append(f"Minor: {', '.join(triggered[:3])}")
            else:
                findings.append("No suspicious patterns")
    except Exception:
        findings.append("Content analysis skipped"); status = "neutral"
    return {"score": min(score, 50), "status": status, "message": "Content: " + ("Suspicious" if status == "negative" else "Clean" if status == "positive" else "Inconclusive"), "detail": " | ".join(findings)}


# ======================================
# 12. IP & HOSTING (FREE)
# ======================================
async def check_ip_info(domain: str):
    score = 0
    findings = []
    status = "positive"
    location = "Unknown"
    ip = None
    try:
        ip = socket.gethostbyname(domain)
        findings.append(f"IP: {ip}")
        async with httpx.AsyncClient(timeout=5.0) as c:
            r = await c.get(f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,isp,org,hosting")
            d = r.json()
        location = d.get("country", "Unknown")
        findings.append(f"Country: {location}")
        findings.append(f"ISP: {d.get('isp', 'Unknown')}")
        if d.get("countryCode") in ["RU", "CN", "KP", "NG"]:
            score += 15; status = "negative"; findings.append("High-risk country")
    except Exception as e:
        findings.append(f"IP unavailable: {str(e)[:50]}"); status = "neutral"
    return {"score": score, "status": status, "message": f"Server: {location}", "detail": " | ".join(findings), "ip": ip, "location": location}

# ======================================
# 13. SUSPICIOUS URL PATTERN CHECK (FREE)
# ======================================
def check_url_patterns(url: str, domain: str):
    score = 0
    findings = []
    status = "positive"

    SUSPICIOUS_TLDS = ['.name', '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
                       '.club', '.online', '.site', '.website', '.info', '.biz',
                       '.click', '.link', '.work', '.date', '.download', '.win']

    tld = '.' + domain.split('.')[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        score += 20
        status = "negative"
        findings.append(f"Suspicious TLD: {tld}")

    path = urlparse(url).path.lower()
    suspicious_paths = ['/verify', '/login', '/secure', '/update', '/confirm',
                        '/account', '/wallet', '/claim']
    for p in suspicious_paths:
        if path.startswith(p):
            score += 15
            status = "negative"
            findings.append(f"Suspicious path: {path}")
            break

    # Short random path like /yiy /xyz /aab
    path_parts = [p for p in path.split('/') if p]
    if path_parts and len(path_parts[-1]) <= 4 and path_parts[-1].isalpha():
        score += 10
        findings.append(f"Short random path: /{path_parts[-1]}")
        if status == "positive":
            status = "neutral"

    if not findings:
        findings.append("No suspicious URL patterns")

    return {
        "score": min(score, 40),
        "status": status,
        "message": "URL Pattern: " + ("Suspicious" if status == "negative" else "OK" if status == "positive" else "Caution"),
        "detail": " | ".join(findings)
    }


# ======================================
# SCORING ENGINE
# ======================================
def calculate_trust_score(source_results: dict) -> int:
    wr = 0; tw = 0
    for name, res in source_results.items():
        w = SOURCE_WEIGHTS.get(name, 0.5)
        wr += res.get("score", 0) * w
        tw += w
    norm = wr / tw if tw > 0 else 0
    return max(0, min(100, int(100 - norm)))


def get_verdict(trust_score: int, blacklisted: bool) -> dict:
    if blacklisted:
        return {"verdict": "HIGH RISK SCAM", "verdict_hi": "⛔ KHATARNAK — Ye website blacklist me hai!", "confidence": "VERY HIGH", "color": "red", "emoji": "🚨"}
    if trust_score >= 85:
        return {"verdict": "VERY LIKELY SAFE", "verdict_hi": "✅ Ye website safe lagti hai — koi major risk nahi mila", "confidence": "HIGH", "color": "green", "emoji": "✅"}
    elif trust_score >= 70:
        return {"verdict": "LIKELY SAFE", "verdict_hi": "🟢 Website theek lagti hai, lekin thoda dhyan rakhein", "confidence": "MODERATE", "color": "light_green", "emoji": "🟢"}
    elif trust_score >= 50:
        return {"verdict": "SUSPICIOUS", "verdict_hi": "⚠️ Ye website suspicious hai — savdhaan rahein!", "confidence": "MODERATE", "color": "orange", "emoji": "⚠️"}
    elif trust_score >= 30:
        return {"verdict": "HIGH RISK", "verdict_hi": "🔴 Ye website risky hai — isse avoid karein!", "confidence": "HIGH", "color": "red", "emoji": "🔴"}
    else:
        return {"verdict": "VERY HIGH RISK SCAM", "verdict_hi": "🚨 BAHUT KHATARNAK — Scam ki bohot zyada possibility!", "confidence": "VERY HIGH", "color": "dark_red", "emoji": "🚨"}


def categorize_signals(source_results: dict) -> dict:
    pos, neg, neu = [], [], []
    for name, res in source_results.items():
        entry = {"name": name, "status": res.get("status", "neutral"), "message": res.get("message", ""), "detail": res.get("detail", "")}
        if res.get("status") == "positive": pos.append(entry)
        elif res.get("status") == "negative": neg.append(entry)
        else: neu.append(entry)
    return {"positive_signals": len(pos), "negative_signals": len(neg), "neutral_signals": len(neu), "positive": pos, "negative": neg, "neutral": neu}


def generate_explanation(sr: dict, ts: int, bl: bool) -> list:
    reasons = []
    if bl: reasons.append("Ye URL security databases me blacklisted hai")
    da = sr.get("Domain Age", {})
    if da.get("age_days") is not None:
        if da["age_days"] < 90: reasons.append(f"Domain bahut naya hai ({da['age_days']} din purana)")
        elif da["age_days"] > 730: reasons.append(f"Domain established hai ({da['age_days'] // 365} saal purana)")
    ss = sr.get("SSL Certificate", {})
    if ss.get("status") == "positive": reasons.append("SSL certificate valid hai")
    elif ss.get("status") == "negative": reasons.append("SSL me problem hai")
    ab = sr.get("AbuseIPDB", {})
    if (ab.get("abuse_score") or 0) >= 40: reasons.append(f"IP address abuse reports me hai (score: {ab.get('abuse_score')}%)")
    for src in ["Google Safe Browsing", "PhishDestroy", "OpenPhish", "URLhaus", "PhishTank"]:
        r = sr.get(src, {})
        if r.get("status") == "negative": reasons.append(f"{src}: DANGER — reported!")
        elif r.get("status") == "positive": reasons.append(f"{src}: Clean")
    ca = sr.get("Content Analysis", {})
    if ca.get("status") == "negative": reasons.append("Page me suspicious patterns mile")
    if ts >= 85 and not bl: reasons.append("Zyada tar sources ne safe report kiya hai")
    elif ts < 50: reasons.append("Kai sources ne risky report kiya hai")
    return reasons


def build_technical_report(domain: str, url: str, sr: dict) -> str:
    lines = [f"DOMAIN: {domain}", f"URL: {url}", ""]
    lines.append("=== BLACKLIST & THREAT DATABASES ===")
    for s in ["Google Safe Browsing", "PhishDestroy", "OpenPhish", "URLhaus", "PhishTank"]:
        r = sr.get(s, {}); lines.append(f"- {s}: {r.get('message', 'N/A')}")
    lines.append("\n=== IP REPUTATION ===")
    for s in ["AbuseIPDB", "IP & Hosting"]:
        r = sr.get(s, {}); lines.append(f"- {s}: {r.get('message', 'N/A')}")
        if r.get("detail"): lines.append(f"  Detail: {r['detail']}")
    lines.append("\n=== TECHNICAL CHECKS ===")
    for s in ["Domain Age", "SSL Certificate", "DNS Security", "HTTP Analysis", "Content Analysis"]:
        r = sr.get(s, {}); lines.append(f"- {s}: {r.get('message', 'N/A')}")
        if r.get("detail"): lines.append(f"  Detail: {r['detail']}")
    return "\n".join(lines)


# ======================================
# MASTER FUNCTION
# ======================================
async def analyze_url_full(url: str) -> dict:
    if not url.startswith("http"):
        url = "https://" + url
    parsed = urlparse(url)
    domain = parsed.netloc.lower().replace("www.", "")
    loop = asyncio.get_event_loop()

    ip_address = None
    try:
        ip_address = socket.gethostbyname(domain)
    except Exception:
        pass
    url_pattern_result = check_url_patterns(url, domain)
    results = await asyncio.gather(
        loop.run_in_executor(executor, check_domain_age, domain),
        loop.run_in_executor(executor, check_ssl, domain),
        check_google_safe(url),
        check_phishdestroy(domain),
        check_openphish(url),
        check_urlhaus(url),
        check_phishtank(url),
        check_abuseipdb(ip_address),
        check_dns_security(domain),
        check_http_headers(url),
        check_content_analysis(url),
        check_ip_info(domain),
        return_exceptions=True
    )

    def safe(r, n):
        return {"score": 0, "status": "neutral", "message": f"{n}: Failed", "detail": str(r)[:100]} if isinstance(r, Exception) else r

    sr = {
        "Google Safe Browsing": safe(results[2], "GSB"),
        "PhishDestroy": safe(results[3], "PhishDestroy"),
        "OpenPhish": safe(results[4], "OpenPhish"),
        "URLhaus": safe(results[5], "URLhaus"),
        "PhishTank": safe(results[6], "PhishTank"),
        "AbuseIPDB": safe(results[7], "AbuseIPDB"),
        "DNS Security": safe(results[8], "DNS"),
        "Domain Age": safe(results[0], "Domain Age"),
        "SSL Certificate": safe(results[1], "SSL"),
        "HTTP Analysis": safe(results[9], "HTTP"),
        "Content Analysis": safe(results[10], "Content"),
        "IP & Hosting": safe(results[11], "IP"),
        "URL Patterns": url_pattern_result,
    }

     # ── COMBO RISK OVERRIDE ──────────────────────────────────────
    _ssl_bad   = sr["SSL Certificate"].get("status") == "negative"
    _abuse_val = sr["AbuseIPDB"].get("score", 0)
    _url_bad   = sr["URL Patterns"].get("status") in ["negative", "neutral"]
    _age_unk   = "unavailable" in sr["Domain Age"].get("message", "").lower()

    _risk_flags = sum([_ssl_bad, _abuse_val >= 30, _url_bad, _age_unk])
    _combo_override = False

    if _risk_flags >= 3:
        _combo_override = True
    elif _risk_flags >= 2 and _ssl_bad:
        _combo_override = True

    blacklisted = any(sr[s].get("score", 0) >= 80 for s in ["Google Safe Browsing", "PhishDestroy", "OpenPhish", "URLhaus", "PhishTank"])
    trust_score = max(5, min(15, calculate_trust_score(sr))) if blacklisted else calculate_trust_score(sr)
    # COMBO OVERRIDE — agar 2-3+ risk signals hain toh cap karo
    if _combo_override and trust_score > 55:
        trust_score = min(trust_score, 48)
    verdict_info = get_verdict(trust_score, blacklisted)
    signals = categorize_signals(sr)
    explanation = generate_explanation(sr, trust_score, blacklisted)
    tech_report = build_technical_report(domain, url, sr)
    da = sr.get("Domain Age", {}); ip_d = sr.get("IP & Hosting", {})

    sources_list = [{"name": n, "status": r.get("status", "neutral"), "message": r.get("message", ""), "detail": r.get("detail", "")} for n, r in sr.items()]
    top_risks = sorted([{"source": n, "risk": r.get("message", "")} for n, r in sr.items() if r.get("status") == "negative" and r.get("score", 0) > 0], key=lambda x: sr.get(x["source"], {}).get("score", 0), reverse=True)[:5]

    return {
        "trust_score": trust_score,
        "verdict": verdict_info["verdict"],
        "verdict_hi": verdict_info["verdict_hi"],
        "confidence": verdict_info["confidence"],
        "emoji": verdict_info["emoji"],
        "color": verdict_info["color"],
        "domain": domain,
        "url": url,
        "blacklisted": blacklisted,
        "summary": {"positive_signals": signals["positive_signals"], "negative_signals": signals["negative_signals"], "neutral_signals": signals["neutral_signals"], "total_sources_checked": len(sr)},
        "sources": sources_list,
        "top_risks": [r["risk"] for r in top_risks],
        "explanation": explanation,
        "other_info": {"domain_created": da.get("created", "Unknown"), "server_location": ip_d.get("location", "Unknown"), "ssl_issuer": sr.get("SSL Certificate", {}).get("issuer", "Unknown"), "ip_address": ip_d.get("ip", ip_address)},
        "technical_report": tech_report,
        "signals": {"positive": signals["positive"], "negative": signals["negative"], "neutral": signals["neutral"]},
    }

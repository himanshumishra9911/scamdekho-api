import re
import requests
from urllib.parse import urlparse
import os

from app.services.ai_engine import call_ai_analysis

GOOGLE_SAFE_API_KEY = os.getenv("GOOGLE_SAFE_API_KEY")


# ===============================
# RULE BASED SIGNALS
# ===============================
def rule_based_url_signals(url: str):
    score = 0
    reasons = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    bad_tlds = [".xyz", ".top", ".club", ".click", ".info"]

    if any(domain.endswith(tld) for tld in bad_tlds):
        score += 25
        reasons.append("Suspicious domain extension")

    if domain.count("-") >= 3:
        score += 20
        reasons.append("Too many hyphens in domain")

    if sum(c.isdigit() for c in domain) > 4:
        score += 15
        reasons.append("Too many numbers in domain")

    brand_words = ["paytm", "bank", "sbi", "amazon", "flipkart", "upi", "kyc"]

    for b in brand_words:
        if b in domain and not domain.endswith(".com"):
            score += 20
            reasons.append("Possible brand spoofing")

    return score, reasons


# ===============================
# SMART WEBSITE LOAD CHECK (Memory Safe)
# ===============================
def check_website_status(url: str):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        # 🔹 Step 1: HEAD request first (lightweight)
        head = requests.head(url, timeout=5, allow_redirects=True, headers=headers)

        content_length = int(head.headers.get("Content-Length", 0))
        content_type = head.headers.get("Content-Type", "")

        # If not HTML → no need to download
        if "text/html" not in content_type:
            return True, ""

        # If very large site (>800KB) skip full download
        if content_length > 800000:
            return True, ""

        # 🔹 Step 2: Controlled GET (stream mode)
        r = requests.get(
            url,
            timeout=6,
            headers=headers,
            stream=True,
            allow_redirects=True
        )

        if 200 <= r.status_code < 400:
            text_chunks = []
            total_read = 0

            for chunk in r.iter_content(chunk_size=2048):
                total_read += len(chunk)
                text_chunks.append(chunk.decode(errors="ignore"))

                if total_read > 5000:   # only read first 5KB
                    break

            return True, " ".join(text_chunks)

        return False, ""

    except requests.exceptions.Timeout:
        return True, ""

    except Exception:
        return False, ""


# ===============================
# GOOGLE SAFE BROWSING CHECK
# ===============================
def check_google_safe_browsing(url: str):
    if not GOOGLE_SAFE_API_KEY:
        return False

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_API_KEY}"

    body = {
        "client": {
            "clientId": "scamdekho",
            "clientVersion": "1.0"
        },
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
        r = requests.post(endpoint, json=body, timeout=5)

        if r.status_code == 200 and r.json().get("matches"):
            return True

        return False

    except Exception:
        return False


# ===============================
# MAIN ANALYSIS FUNCTION
# ===============================
def analyze_url(url: str):

    rule_score, rule_reasons = rule_based_url_signals(url)

    loaded, text = check_website_status(url)

    safe_flag = check_google_safe_browsing(url)

    phishing_keywords = []
    if text:
        lower_text = text.lower()
        keywords = [
            "verify your account",
            "update kyc",
            "urgent action",
            "login now",
            "otp required",
            "bank alert",
            "account suspended"
        ]
        for k in keywords:
            if k in lower_text:
                phishing_keywords.append(k)

    # ===============================
    # PREPARE AI INPUT
    # ===============================
    structured_summary = f"""
URL: {url}

Rule Score: {rule_score}
Rule Reasons: {rule_reasons}

Website Loaded: {loaded}

Google Safe Browsing Flagged: {safe_flag}

Detected Page Keywords: {phishing_keywords}
"""

    # ===============================
    # CALL GPT FOR FINAL VERDICT
    # ===============================
    ai_result = call_ai_analysis(structured_summary)

    return ai_result

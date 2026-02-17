import re
import requests
import os
from urllib.parse import urlparse

SAFE_BROWSING_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY")


# =========================================
# 1. RULE BASED CHECKS
# =========================================
def rule_based_signals(url: str):
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
            reasons.append("Possible brand spoofing attempt")

    return score, reasons


# =========================================
# 2. GOOGLE SAFE BROWSING CHECK
# =========================================
def safe_browsing_check(url: str):
    if not SAFE_BROWSING_KEY:
        return 0, []

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_KEY}"

    body = {
        "client": {"clientId": "scamdekho", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        r = requests.post(endpoint, json=body, timeout=5)
        data = r.json()

        if "matches" in data:
            return 50, ["Blacklisted by Google Safe Browsing"]

        return 0, []

    except:
        return 0, []


# =========================================
# 3. WEBSITE STATUS CHECK
# =========================================
def check_website_status(url: str):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        r = requests.get(url, timeout=8, headers=headers)

        if 200 <= r.status_code < 400:
            return True, r.text[:4000]

        return False, ""

    except requests.exceptions.Timeout:
        return True, ""

    except:
        return False, ""


# =========================================
# 4. MAIN ANALYSIS FUNCTION
# =========================================
def analyze_url(url: str):

    total_score = 0
    reasons = []

    # Rule Engine
    rule_score, rule_reasons = rule_based_signals(url)
    total_score += rule_score
    reasons.extend(rule_reasons)

    # Google Blacklist
    sb_score, sb_reasons = safe_browsing_check(url)
    total_score += sb_score
    reasons.extend(sb_reasons)

    # Website Load Check
    loaded, text = check_website_status(url)

    if not loaded:
        total_score += 15
        reasons.append("Website could not be loaded")

    # Phishing Keywords
    phishing_words = ["verify your account", "update kyc", "urgent action", "login now"]

    if text:
        lower_text = text.lower()
        for word in phishing_words:
            if word in lower_text:
                total_score += 20
                reasons.append("Phishing-related keywords detected")
                break

    # Final Verdict Logic
    if total_score >= 70:
        verdict = "SCAM DETECTED"
    elif total_score >= 35:
        verdict = "Suspicious – Use Caution"
    else:
        verdict = "SAFE"

    return {
        "score": total_score,
        "verdict": verdict,
        "reasons": reasons
    }

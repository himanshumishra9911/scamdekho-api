import re
import requests
from urllib.parse import urlparse


# ====================================
# BASIC DOMAIN RULE CHECKS
# ====================================
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


# ====================================
# CHECK WEBSITE LOAD STATUS (IMPROVED)
# ====================================
def check_website_status(url: str):

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        }

        r = requests.get(
            url,
            timeout=8,
            headers=headers,
            allow_redirects=True
        )

        # 200–399 = working
        if 200 <= r.status_code < 400:
            return True, r.text[:4000]

        return False, ""

    except requests.exceptions.Timeout:
        # Timeout ≠ scam
        return True, ""

    except Exception:
        return False, ""


# ====================================
# MAIN URL ANALYSIS FUNCTION
# ====================================
def analyze_url(url: str):

    total_score = 0
    reasons = []

    # Rule-based signals
    rule_score, rule_reasons = rule_based_url_signals(url)
    total_score += rule_score
    reasons.extend(rule_reasons)

    # Website load check
    loaded, text = check_website_status(url)

    if not loaded:
        total_score += 15
        reasons.append("Website could not be loaded")

    # Basic phishing keyword detection
    phishing_words = ["verify your account", "update kyc", "urgent action", "login now"]

    if text:
        lower_text = text.lower()
        for word in phishing_words:
            if word in lower_text:
                total_score += 20
                reasons.append("Phishing-related keywords detected")
                break

    # Final Verdict
    if total_score >= 60:
        verdict = "SCAM DETECTED"
    elif total_score >= 30:
        verdict = "Suspicious – Use Caution"
    else:
        verdict = "No major scam signals detected"

    return {
        "score": total_score,
        "verdict": verdict,
        "reasons": reasons
    }

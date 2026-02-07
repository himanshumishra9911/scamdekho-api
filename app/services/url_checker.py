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

    # suspicious TLDs
    bad_tlds = [".xyz", ".top", ".club", ".click", ".info"]

    if any(domain.endswith(tld) for tld in bad_tlds):
        score += 25
        reasons.append("Suspicious domain extension")

    # too many hyphens
    if domain.count("-") >= 3:
        score += 20
        reasons.append("Too many hyphens in domain")

    # numbers heavy domain
    if sum(c.isdigit() for c in domain) > 4:
        score += 15
        reasons.append("Too many numbers in domain")

    # brand spoofing words
    brand_words = ["paytm", "bank", "sbi", "amazon", "flipkart", "upi", "kyc"]

    for b in brand_words:
        if b in domain and not domain.endswith(".com"):
            score += 20
            reasons.append("Possible brand spoofing")

    return score, reasons


# ====================================
# FETCH PAGE TITLE (LIGHTWEIGHT)
# ====================================
def fetch_page_text(url: str):

    try:
        headers = {
            "User-Agent": "Mozilla/5.0"
        }

        r = requests.get(url, timeout=4, headers=headers)

        text = r.text[:4000]  # limit

        # crude text cleanup
        text = re.sub(r"<[^>]+>", " ", text)

        return text

    except Exception:
        return ""

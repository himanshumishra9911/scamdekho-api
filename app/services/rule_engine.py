import json
from app.utils.text_cleaner import (
    clean_text,
    detect_language,
    is_all_caps_ratio,
    has_excessive_symbols,
    has_suspicious_numbers
)

KEYWORDS_PATH = "app/data/keywords.json"
PATTERNS_PATH = "app/data/scam_patterns.json"

with open(KEYWORDS_PATH, "r", encoding="utf-8") as f:
    KEYWORDS = json.load(f)

with open(PATTERNS_PATH, "r", encoding="utf-8") as f:
    PATTERNS = json.load(f)


def run_text_rules(text: str):
    cleaned = clean_text(text)
    lang = detect_language(text)

    score = 0
    reasons = []

    keyword_set = KEYWORDS.get(lang, {})

    # 1️⃣ Keyword rules
    for kw in keyword_set.get("high_risk", []):
        if kw in cleaned:
            score += 12
            reasons.append(f"High-risk keyword detected: {kw}")

    for kw in keyword_set.get("medium_risk", []):
        if kw in cleaned:
            score += 6
            reasons.append(f"Medium-risk keyword detected: {kw}")

    # 2️⃣ Urgency language
    for w in PATTERNS.get("urgency_words", {}).get(lang, []):
        if w in cleaned:
            score += 10
            reasons.append("Urgency language detected")
            break

    # 3️⃣ Fear / threat language
    for w in PATTERNS.get("fear_words", {}).get(lang, []):
        if w in cleaned:
            score += 10
            reasons.append("Threat / fear language detected")
            break

    # 4️⃣ Visual shouting patterns
    if is_all_caps_ratio(text):
        score += 8
        reasons.append("Excessive ALL CAPS usage")

    if has_excessive_symbols(text):
        score += 6
        reasons.append("Excessive symbols detected (!!! / $$$)")

    # 5️⃣ Numbers (OTP / suspicious digits)
    if has_suspicious_numbers(text):
        score += 8
        reasons.append("Suspicious numeric pattern detected")

    # Max cap for rule engine
    score = min(score, 60)

    return {
        "rule_score": score,
        "matched_reasons": reasons,
        "language": lang
    }

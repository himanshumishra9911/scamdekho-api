def combine_scores(rule_score: int, ai_score: int) -> int:
    # Rules 70%, AI 30%
    final = int((rule_score * 0.7) + (ai_score * 0.3))
    return min(final, 100)


def map_level(score: int, lang: str) -> str:
    if score <= 30:
        return "Safe" if lang == "en" else "सुरक्षित"
    elif score <= 60:
        return "Suspicious" if lang == "en" else "संदिग्ध"
    else:
        return "High Risk" if lang == "en" else "उच्च जोखिम"


# ── Website trust score → the verdict shown on /check/<domain> ──
# Single source of truth for the label. Colour bands in
# public_pages.verdict_color stay at 70/50 so no existing page changes
# colour; this only splits the sub-50 range, which keeps blacklisted
# sites (trust score is clamped to 5-15 for those) reading as SCAM.
def display_verdict(trust_score) -> str:
    try:
        ts = int(trust_score)
    except (TypeError, ValueError):
        ts = 50
    if ts >= 70:
        return "SAFE"
    if ts >= 50:
        return "SUSPICIOUS"
    if ts >= 30:
        return "HIGH RISK"
    return "SCAM"

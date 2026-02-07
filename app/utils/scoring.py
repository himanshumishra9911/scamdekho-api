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

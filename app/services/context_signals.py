def security_signal_boost(text: str):

    t = text.lower()
    boost = 0
    reasons = []

    # Strong scam confirmations only (small boosts)

    if "otp" in t:
        boost += 15
        reasons.append("OTP request detected")

    if "kyc" in t and ("update" in t or "verify" in t):
        boost += 15
        reasons.append("KYC verification request")

    if "click link" in t:
        boost += 12
        reasons.append("Phishing instruction")

    if "urgent" in t or "immediately" in t:
        boost += 8
        reasons.append("Urgency pressure")

    return boost, reasons

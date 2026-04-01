import os
import json
import base64
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ===============================
# SYSTEM PROMPT — TEXT / IMAGE
# ===============================
SYSTEM_PROMPT = """
You are an expert scam detection engine for India. Your job is to protect Indian users from CLEAR online fraud.

Return ONLY valid JSON in this exact format:
{
  "risk_score": number (0-100),
  "confidence": {
    "en": "One clear sentence verdict explanation",
    "hi": "Same in Hindi"
  },
  "why": [
    {"en": "Specific reason 1", "hi": "Hindi reason 1"},
    {"en": "Specific reason 2", "hi": "Hindi reason 2"}
  ],
  "what_to_do": [
    {"en": "Specific action 1", "hi": "Hindi action 1"}
  ],
  "how_to_avoid": [
    {"en": "Prevention tip 1", "hi": "Hindi tip 1"}
  ]
}

STRICT RULES:
1. DEFAULT IS SAFE — Only mark SCAM if you see CLEAR, SPECIFIC fraud evidence.
2. Mark SCAM only for: fake KYC/OTP harvesting, guaranteed high returns, lottery/prize fraud, brand impersonation, confirmed blacklist, phishing pages, suspicious UPI fraud.
3. NEVER scam reasons alone: no reviews, new domain, simple design, unknown app, no testimonials, marketing language.
4. risk_score: 0-30 = SAFE, 31-69 = borderline, 70-100 = SCAM. When in doubt → SAFE.
5. Scam detection/cybersecurity websites = ALWAYS SAFE (risk 0-20).
"""


# ===============================
# URL ANALYSIS SYSTEM PROMPT
# Receives: 14-source report + screenshot
# ===============================
URL_ANALYSIS_SYSTEM_PROMPT = """
You are ScamDekho's expert URL analysis engine for Indian users.

Return ONLY valid JSON:
{
  "risk_score": number (0-100),
  "confidence": {"en": "verdict", "hi": "Hindi verdict"},
  "why": [{"en": "reason", "hi": "Hindi reason"}],
  "what_to_do": [{"en": "action", "hi": "Hindi action"}],
  "how_to_avoid": [{"en": "tip", "hi": "Hindi tip"}]
}

SCORING RULES — STRICT:

AUTOMATIC SCAM (risk 85-100):
- ANY hit in: Google Safe Browsing, PhishDestroy, OpenPhish, URLhaus, PhishTank
- AbuseIPDB 80%+ with any other negative signal
- Screenshot shows fake login / KYC / brand impersonation

HIGH RISK (risk 65-84) — 2+ of these present:
- SSL certificate missing or invalid
- AbuseIPDB 40%+
- Suspicious TLD: .one .name .tk .ml .xyz .top .click .online .icu .vip etc.
- Domain age under 30 days OR unknown
- VirusTotal flagged any engine
- High-risk hosting country (HK, RU, CN, KP, NG)
- Short random path like /yiy /xyz /abc

SUSPICIOUS (risk 40-64) — ANY 1 of:
- SSL missing/invalid
- AbuseIPDB 30-79%
- Suspicious TLD with no other trust signals
- Domain age unknown + 1 other minor signal
- combo_override=true in data

SAFE (risk 0-30) — ALL must be true:
- All 5 blacklists: CLEAN
- SSL valid (trusted CA)
- AbuseIPDB below 20%
- Domain 1+ year old OR well-known brand
- Normal TLD (.com .org .gov .edu .in etc.)
- VirusTotal: CLEAN

ALIGNMENT RULE (CRITICAL):
- The scoring engine has already calculated a trust_score. Your risk_score should align with it.
- trust_score to AI risk conversion: AI risk = 100 - trust_score
- Only deviate by more than 20 points if the screenshot shows CLEAR contradiction.
- Example: trust_score=25 → your risk_score should be ~70-85 (HIGH RISK range)
- Example: trust_score=80 → your risk_score should be ~15-30 (SAFE range)

CRITICAL RULES:
1. "8 sources clean" does NOT mean safe if domain is 1 day old + suspicious TLD + VirusTotal flag
2. .one .tk .ml TLDs are HIGH suspicion — rarely used by legitimate sites
3. Short random paths like /yiy suggest phishing redirect
4. Name SPECIFIC sources in "why" (e.g. "VirusTotal flagged 1 malicious engine")
5. Give SPECIFIC actions in "what_to_do" — not generic advice
6. combo_override=true means technical signals strongly indicate fraud
7. Brand impersonation (e.g. fake Marina Bay Sands on .one domain) = HIGH RISK
"""


# ===============================
# TEXT AI ANALYSIS (unchanged)
# ===============================
def call_ai_analysis(content: str, language="auto", content_type="text"):
    try:
        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": content}
            ],
            response_format={"type": "json_object"},
        )
        data = json.loads(response.choices[0].message.content)
        return {
            "risk_score": int(data.get("risk_score", 50)),
            "confidence": data.get("confidence", {}),
            "why": data.get("why", []),
            "what_to_do": data.get("what_to_do", []),
            "how_to_avoid": data.get("how_to_avoid", [])
        }
    except Exception as e:
        print("AI TEXT ERROR:", e)
        return {"risk_score": 50, "confidence": {"en": "Analysis fallback", "hi": "विश्लेषण उपलब्ध नहीं"}, "why": [], "what_to_do": [], "how_to_avoid": []}


# ===============================
# IMAGE VISION AI (unchanged)
# ===============================
def call_ai_vision_analysis(image_bytes):
    try:
        image_b64 = base64.b64encode(image_bytes).decode()
        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": [
                    {"type": "text", "text": "Analyze this image for scam risk"},
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{image_b64}"}}
                ]}
            ],
            response_format={"type": "json_object"},
        )
        data = json.loads(response.choices[0].message.content)
        return {"risk_score": int(data.get("risk_score", 50)), "confidence": data.get("confidence", {}), "why": data.get("why", []), "what_to_do": data.get("what_to_do", []), "how_to_avoid": data.get("how_to_avoid", [])}
    except Exception as e:
        print("VISION AI ERROR:", e)
        return None


# ===============================
# VISION + TECHNICAL CONTEXT (kept for backward compat)
# ===============================
def call_ai_vision_analysis_with_context(image_bytes, technical_report: str):
    try:
        image_b64 = base64.b64encode(image_bytes).decode()
        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": [
                    {"type": "text", "text": f"""Analyze this website screenshot for scam risk.

TECHNICAL ANALYSIS REPORT:
{technical_report}

Use BOTH the screenshot AND the technical data to determine if this is a scam.
Remember: Only mark SCAM if there is CLEAR fraud evidence. When in doubt → SAFE."""},
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{image_b64}"}}
                ]}
            ],
            response_format={"type": "json_object"},
        )
        data = json.loads(response.choices[0].message.content)
        return {"risk_score": int(data.get("risk_score", 50)), "confidence": data.get("confidence", {}), "why": data.get("why", []), "what_to_do": data.get("what_to_do", []), "how_to_avoid": data.get("how_to_avoid", [])}
    except Exception as e:
        print("VISION CONTEXT AI ERROR:", e)
        return None


# ===============================
# SCORE RECONCILIATION HELPER
# ===============================
def reconcile_ai_and_score(trust_score: int, ai_result: dict) -> dict:
    """
    Agar AI risk aur trust_score mein 30+ point gap hai toh blend karo.
    trust_score=25 → expected AI risk ~75. Agar AI ne 20 diya → blend karke ~55 karo.
    """
    ai_risk = ai_result.get("risk_score", 50)
    expected_ai_risk = 100 - trust_score
    gap = abs(ai_risk - expected_ai_risk)

    if gap > 30:
        # 60% scoring engine, 40% AI
        blended_risk = int((expected_ai_risk * 0.60) + (ai_risk * 0.40))
        blended_risk = max(0, min(100, blended_risk))
        ai_result["risk_score"] = blended_risk

    return ai_result


# ===============================
# NEW — FULL URL ANALYSIS WITH AI
# Screenshot + 14-source intel + trust score → AI final verdict
# ===============================
def call_ai_url_full_analysis(screenshot_bytes, intel: dict):
    """
    Sends ALL intelligence data + screenshot to AI for final verdict.
    intel = full response from analyze_url_full()
    """
    try:
        # Score guidance for AI alignment
        ts = intel.get("trust_score", 50)
        expected_risk = 100 - ts

        if ts >= 75:
            score_guidance = (
                f"Scoring engine trust_score={ts}/100 → LIKELY SAFE. "
                f"Your risk_score should be ~{expected_risk} (low). "
                "Only override higher if screenshot shows CLEAR fraud (fake login, brand impersonation, KYC harvesting)."
            )
        elif ts >= 50:
            score_guidance = (
                f"Scoring engine trust_score={ts}/100 → SUSPICIOUS. "
                f"Your risk_score should be ~{expected_risk} (medium). "
                "Look for confirming visual evidence of fraud."
            )
        elif ts >= 30:
            score_guidance = (
                f"Scoring engine trust_score={ts}/100 → HIGH RISK. "
                f"Your risk_score should be ~{expected_risk} (high). "
                "Technical signals strongly suggest fraud — confirm with visual."
            )
        else:
            score_guidance = (
                f"Scoring engine trust_score={ts}/100 → VERY HIGH RISK. "
                f"Your risk_score should be ~{expected_risk} (very high). "
                "Multiple strong fraud signals present."
            )

        # Build source summary
        source_summary = ""
        for src in intel.get("sources", []):
            icon = "✅" if src["status"] == "positive" else "❌" if src["status"] == "negative" else "⚪"
            source_summary += f"{icon} {src['name']}: {src['message']}\n"
            if src.get("detail"):
                source_summary += f"   Detail: {src['detail']}\n"

        prompt_text = f"""SCORING ENGINE GUIDANCE: {score_guidance}

Analyze this website for scam risk using ALL the intelligence data below.

=== TRUST SCORE: {ts}/100 (Expected AI risk: ~{expected_risk}) ===
=== VERDICT FROM SCORING ENGINE: {intel.get('verdict', 'N/A')} ===
=== BLACKLISTED: {intel.get('blacklisted', False)} ===
=== COMBO OVERRIDE: {intel.get('combo_override', False)} ===

=== SIGNAL SUMMARY ===
Positive signals: {intel.get('summary', {}).get('positive_signals', 0)}
Negative signals: {intel.get('summary', {}).get('negative_signals', 0)}
Neutral signals: {intel.get('summary', {}).get('neutral_signals', 0)}
Total sources checked: {intel.get('summary', {}).get('total_sources_checked', 0)}

=== ALL SOURCE RESULTS ===
{source_summary}

=== OTHER INFO ===
Domain created: {intel.get('other_info', {}).get('domain_created', 'Unknown')}
Server location: {intel.get('other_info', {}).get('server_location', 'Unknown')}
SSL issuer: {intel.get('other_info', {}).get('ssl_issuer', 'Unknown')}
IP address: {intel.get('other_info', {}).get('ip_address', 'Unknown')}

=== TOP RISKS ===
{chr(10).join(intel.get('top_risks', ['None'])) if intel.get('top_risks') else 'None identified'}

=== EXPLANATION FROM SCORING ENGINE ===
{chr(10).join(intel.get('explanation', []))}

=== FULL TECHNICAL REPORT ===
{intel.get('technical_report', 'N/A')}

NOW analyze the website SCREENSHOT along with ALL this data.
Look for: brand impersonation, fake login pages, KYC harvesting, urgency language, prize/lottery, poor design, suspicious forms.
Give your final verdict considering EVERYTHING — the 14 intelligence sources AND what you SEE in the screenshot.
Your risk_score MUST be within 20 points of {expected_risk} unless screenshot shows clear contradiction."""

        messages = [
            {"role": "system", "content": URL_ANALYSIS_SYSTEM_PROMPT},
        ]

        if screenshot_bytes:
            image_b64 = base64.b64encode(screenshot_bytes).decode()
            messages.append({
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt_text},
                    {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{image_b64}"}}
                ]
            })
        else:
            messages.append({
                "role": "user",
                "content": prompt_text + "\n\nNOTE: Screenshot could not be captured. Analyze based on technical intelligence only."
            })

        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=messages,
            response_format={"type": "json_object"},
        )

        data = json.loads(response.choices[0].message.content)
        ai_result = {
            "risk_score": int(data.get("risk_score", 50)),
            "confidence": data.get("confidence", {}),
            "why": data.get("why", []),
            "what_to_do": data.get("what_to_do", []),
            "how_to_avoid": data.get("how_to_avoid", [])
        }

        # Final reconciliation — safety net
        ai_result = reconcile_ai_and_score(ts, ai_result)

        return ai_result

    except Exception as e:
        print("AI URL FULL ANALYSIS ERROR:", e)
        return None

# -*- coding: utf-8 -*-
import os
import re
import json
import base64
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()


def get_client():
    return OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


def _image_to_base64(image_bytes: bytes) -> str:
    return base64.b64encode(image_bytes).decode("utf-8")


def _detect_media_type(image_bytes: bytes) -> str:
    if image_bytes[:8] == b'\x89PNG\r\n\x1a\n':
        return "image/png"
    if image_bytes[:3] == b'\xff\xd8\xff':
        return "image/jpeg"
    if image_bytes[:4] == b'RIFF' and image_bytes[8:12] == b'WEBP':
        return "image/webp"
    return "image/jpeg"


PROMPT = """You are a UPI payment screenshot forensic expert. Your goal is to help users avoid scams by detecting fake or misleading payment screenshots with high accuracy.

Carefully analyze the provided screenshot using these checks:

### 1. UI & DESIGN CONSISTENCY
- Check fonts, spacing, alignment, icons
- Look for blur, mismatch, overlays, cropping issues
- Compare with standard Paytm / GPay / PhonePe UI patterns

### 2. TRANSACTION DETAILS VALIDATION
Verify presence and format of:
- Amount (Rs format)
- Receiver name
- UPI ID (must follow valid structure like name@bank)
- Sender name + bank name
- UPI Reference Number (12-digit numeric)
- Date and Time

Missing or incorrect format = HIGH suspicion

### 3. LOGICAL CONSISTENCY
- Does amount match text (Rs 150 vs "One Hundred Fifty")?
- Does app branding match (Paytm vs PhonePe mismatch)?
- Does UPI handle match bank? (e.g., @ybl = Yes Bank)

### 4. COMMON SCAM PATTERNS
- "Paid Successfully" but no transaction ID
- Fake green tick overlays
- Edited names or numbers
- Cropped screens hiding key details
- Too clean or too perfect UI
- Mismatch in fonts or emoji/icons

### 5. IMPORTANT RULES - READ CAREFULLY
- @ptys, @ptm, @paytm = GENUINE Paytm merchant handles - do NOT flag as suspicious
- April/May 2026 dates = CURRENT dates, NOT future dates
- WhatsApp forwarded screenshots may have compression - do NOT flag as fake for this alone
- Any app can pay to any UPI handle - cross-app payments are normal in India
- Screenshots alone are NOT proof of payment even if real

### 6. VERDICT LOGIC
- GENUINE: No visual tampering, all details consistent, no scam indicators
- SUSPICIOUS: Minor issues, unclear, or something mildly off - cannot confirm either way
- FAKE: Clear visual tampering OR impossible data OR scam UPI ID keywords (support/refund/kyc/help/verify/prize/reward/rbi)

Give risk_percentage:
- GENUINE = 5 to 30
- SUSPICIOUS = 31 to 65
- FAKE = 66 to 100

Extract all visible fields. Return ONLY valid JSON:
{
  "app_name": "Paytm",
  "app_key": "paytm",
  "app_confidence": 95,
  "fields": {
    "amount": "500",
    "transaction_id": "609532000947",
    "upi_id": "merchant@ptys",
    "recipient_name": "Shop Name",
    "bank_name": "State Bank of India",
    "timestamp": "05:49 PM, 05 Apr 2026",
    "status_text": "Paid Successfully"
  },
  "visual_verdict": "genuine",
  "visual_signals": [
    "Font consistent throughout - no tampering detected",
    "Paytm blue header matches genuine design",
    "Status bar visible and real"
  ],
  "verdict": "GENUINE",
  "risk_percentage": 10,
  "confidence": "high",
  "reasons": [
    {"en": "All visual elements match genuine Paytm design", "hi": "सभी visual elements असली Paytm design से match करते हैं"},
    {"en": "UTR number present and valid", "hi": "UTR number present है और valid है"},
    {"en": "No tampering evidence found", "hi": "Tampering का कोई evidence नहीं मिला"}
  ]
}

Return ONLY the JSON. No markdown. No text outside JSON."""


def _run_ai_analysis(image_bytes: bytes) -> dict:
    b64 = _image_to_base64(image_bytes)
    media_type = _detect_media_type(image_bytes)

    response = get_client().chat.completions.create(
        model="gpt-4.1-mini",
        max_tokens=1500,
        temperature=0.1,
        messages=[
            {
                "role": "user",
                "content": [
                    {
                        "type": "image_url",
                        "image_url": {
                            "url": f"data:{media_type};base64,{b64}",
                            "detail": "high"
                        }
                    },
                    {
                        "type": "text",
                        "text": PROMPT
                    }
                ]
            }
        ]
    )

    raw = response.choices[0].message.content.strip()

    if raw.startswith("```"):
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)
        raw = raw.strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except Exception:
                pass
        return {}


VERDICT_LABELS = {
    "SAFE": {
        "en": "This payment screenshot appears genuine.",
        "hi": "यह payment screenshot genuine लग रहा है।"
    },
    "SUSPICIOUS": {
        "en": "Suspicious - Verify Before Accepting",
        "hi": "संदिग्ध - Accept करने से पहले verify करें"
    },
    "SCAM": {
        "en": "High Risk - This screenshot shows signs of fraud.",
        "hi": "High Risk - इस screenshot में fraud के संकेत हैं।"
    }
}

WHAT_TO_DO = {
    "SAFE": [
        {"en": "Still verify the payment in your own bank/UPI app before releasing goods.", "hi": "Goods देने से पहले अपने bank/UPI app में payment verify करें।"},
        {"en": "A screenshot alone is never 100% proof - check your transaction history.", "hi": "Screenshot अकेला proof नहीं है - अपना transaction history देखें।"},
    ],
    "SUSPICIOUS": [
        {"en": "DO NOT accept this as payment proof - verify directly in your bank app.", "hi": "इसे payment proof मत मानें - अपने bank app में directly verify करें।"},
        {"en": "Ask the sender to show the transaction live in their UPI app.", "hi": "Sender से कहें कि अपने UPI app में live transaction दिखाएं।"},
        {"en": "If payment not in your account, do not hand over goods/services.", "hi": "अगर payment account में नहीं है तो goods/services मत दें।"},
    ],
    "SCAM": [
        {"en": "DO NOT accept this payment - it is likely fraudulent.", "hi": "यह payment मत लें - यह fraud हो सकता है।"},
        {"en": "Report this UPI ID to NPCI at npci.org.in.", "hi": "इस UPI ID को NPCI को report करें - npci.org.in पर।"},
        {"en": "File a cybercrime complaint at cybercrime.gov.in or call 1930.", "hi": "cybercrime.gov.in पर complaint करें या 1930 call करें।"},
        {"en": "Block the sender and do not engage further.", "hi": "Sender को block करें और आगे engage मत करें।"},
    ]
}

HOW_TO_AVOID = [
    {"en": "Always check your own UPI app or bank SMS for credit confirmation.", "hi": "हमेशा अपने UPI app या bank SMS में credit confirm करें।"},
    {"en": "Ask the buyer to show live transaction - not a screenshot.", "hi": "Buyer से live transaction दिखाने को कहें - screenshot नहीं।"},
    {"en": "Never release goods/services based on screenshot alone.", "hi": "कभी भी सिर्फ screenshot देखकर goods/services मत दें।"},
    {"en": "Real UPI payments reflect in your account within seconds.", "hi": "Real UPI payment seconds में आपके account में reflect होती है।"},
]


async def analyze_payment_screenshot(image_bytes: bytes) -> dict:
    import asyncio
    loop = asyncio.get_running_loop()
    ai = await loop.run_in_executor(None, _run_ai_analysis, image_bytes)

    # Parse
    app_name       = ai.get("app_name") or "Unknown"
    app_key        = (ai.get("app_key") or "unknown").lower()
    app_confidence = int(ai.get("app_confidence") or 0)
    fields         = ai.get("fields") or {}
    visual_signals = ai.get("visual_signals") or []
    ai_risk        = float(ai.get("risk_percentage") or 50)
    ai_confidence  = (ai.get("confidence") or "medium").lower()
    ai_reasons     = ai.get("reasons") or []

    # AI verdict -> our verdict (pure trust)
    raw_verdict = (ai.get("verdict") or "SUSPICIOUS").upper()
    if raw_verdict == "GENUINE":
        final_verdict = "SAFE"
    elif raw_verdict == "FAKE":
        final_verdict = "SCAM"
    elif raw_verdict in ("SAFE", "SCAM", "SUSPICIOUS"):
        final_verdict = raw_verdict
    else:
        final_verdict = "SUSPICIOUS"

    final_risk = round(ai_risk)

    if final_verdict not in VERDICT_LABELS:
        final_verdict = "SUSPICIOUS"

    # Reasons
    why = []
    for r in ai_reasons:
        if isinstance(r, dict):
            why.append(r)
        elif isinstance(r, str):
            why.append({"en": r, "hi": ""})

    # Visual signals
    visual_forensics = []
    for vs in visual_signals:
        if isinstance(vs, str):
            visual_forensics.append({"en": vs, "hi": ""})
        elif isinstance(vs, dict):
            visual_forensics.append(vs)

    return {
        "verdict": final_verdict,
        "risk_percentage": final_risk,
        "confidence": ai_confidence,
        "verdict_label": VERDICT_LABELS[final_verdict],
        "detected_app": {
            "name": app_name,
            "app_key": app_key,
            "detection_confidence": app_confidence,
        },
        "extracted_fields": {
            "amount": fields.get("amount"),
            "transaction_id": fields.get("transaction_id"),
            "upi_id": fields.get("upi_id"),
            "recipient_name": fields.get("recipient_name"),
            "bank_name": fields.get("bank_name"),
            "timestamp": fields.get("timestamp"),
            "status_text": fields.get("status_text"),
        },
        "why": why,
        "visual_forensics": visual_forensics,
        "pattern_match": {"found": False, "match_count": 0},
        "what_to_do": WHAT_TO_DO[final_verdict],
        "how_to_avoid": HOW_TO_AVOID,
    }

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


PROMPT = """You are a forensic expert specializing in UPI payment screenshot fraud detection in India. You have analyzed thousands of real and fake UPI payment screenshots.

Your task: Determine if this screenshot is GENUINE, SUSPICIOUS, or FAKE.

IMPORTANT BALANCE RULE:
- Most UPI screenshots shared by real users are GENUINE - do not over-flag
- Only mark FAKE when you see CLEAR, DEFINITIVE evidence of tampering
- Mark SUSPICIOUS when something is mildly off but not conclusive
- Mark GENUINE when everything looks correct

STEP 1: VISUAL FORENSIC ANALYSIS
Look for CLEAR signs of tampering (not just compression or quality issues):
- Font looks CLEARLY different in amount area vs rest of screen
- Amount text has OBVIOUS color or background mismatch (not subtle)
- VISIBLE hard edges or blurry artifacts specifically around amount (copy-paste)
- Logo is clearly blurry, wrong color, or stretched
- Status bar is completely missing or obviously fake
- Element clearly looks "pasted on" with different rendering quality

NOTE: Slight blur, compression artifacts, or WhatsApp forwarding quality = NOT fake evidence

STEP 2: UI & APP AUTHENTICITY
Verify UI matches real app design:
- Google Pay: "Google Pay" branding, usually 2 transaction IDs, dark or light theme both ok
- PhonePe: purple header, white checkmark in circle, "Transaction Successful"
- Paytm: blue theme, "Paid Successfully", "UPI Ref No" label
- BHIM: government orange/blue UI
- CRED: dark premium UI, masked account numbers like XXXXXX2729 = NORMAL
- WhatsApp Pay: green theme
- Navi: green header, "Navi Transaction ID" label
- Paytm merchant QR: UPI ID ending @ptys or @paytm = completely genuine

Only flag UI issues if they are OBVIOUS and DEFINITIVE - not minor differences

STEP 3: TRANSACTION DATA
- UTR/Transaction ID present = good sign
- UTR missing = only suspicious if NOT a bill payment or CRED
- UPI ID with scam words (support, refund, kyc, help, verify, prize, reward, rbi) = red flag
- Timestamp before 2016 or clearly in future = red flag
- Amount zero or negative = red flag
- "UPI Ref No", "Reference No", "Transaction ID", "UTR" = all mean same thing

STEP 4: FINAL VERDICT LOGIC
- GENUINE: UI matches app, fields present, no clear tampering evidence
- SUSPICIOUS: One or two minor issues, unclear, or missing one field
- FAKE: Multiple CLEAR tampering signs OR wrong UI design OR scam UPI keywords OR impossible data

Give risk_percentage:
- GENUINE = 5 to 30
- SUSPICIOUS = 31 to 65
- FAKE = 66 to 100

RETURN ONLY VALID JSON:
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
        messages=[
            {
                "role": "system",
                "content": "You are a balanced UPI payment fraud detection expert in India. You must be accurate - not too strict, not too lenient. Mark SAFE only when everything looks genuinely correct. Mark SCAM only when you see clear visual tampering or fabricated data. Mark SUSPICIOUS when something is unclear or mildly off. Most real UPI screenshots from Indian users are genuine - do not over-flag them."
            },
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
        ],
        temperature=0.2
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


def _risk_to_verdict(risk: float) -> str:
    if risk <= 35:
        return "SAFE"
    if risk <= 65:
        return "SUSPICIOUS"
    return "SCAM"


async def analyze_payment_screenshot(image_bytes: bytes) -> dict:
    import asyncio
    loop = asyncio.get_running_loop()
    ai_result = await loop.run_in_executor(None, _run_ai_analysis, image_bytes)

    app_name       = ai_result.get("app_name") or "Unknown"
    app_key        = (ai_result.get("app_key") or "unknown").lower()
    app_confidence = int(ai_result.get("app_confidence") or 0)
    fields         = ai_result.get("fields") or {}
    visual_verdict = ai_result.get("visual_verdict") or "unknown"
    visual_signals = ai_result.get("visual_signals") or []
    ai_risk        = float(ai_result.get("risk_percentage") or 50)
    ai_confidence  = ai_result.get("confidence") or "medium"
    ai_reasons     = ai_result.get("reasons") or []

    # ── Final Risk + Verdict Logic (balanced, probability-based) ──────────
    final_risk = round(ai_risk)

    # Adjust based on AI confidence
    if ai_confidence == "low":
        final_risk = min(final_risk + 10, 100)
    elif ai_confidence == "high":
        final_risk = max(final_risk - 10, 0)

    # Clamp
    final_risk = max(0, min(final_risk, 100))

    # Soft rules - raise risk floor but never hard-force SCAM
    utr = (fields.get("transaction_id") or "").strip()
    if not utr:
        # UTR missing = suspicious, not SCAM (many apps delay showing it)
        final_risk = max(final_risk, 50)
    elif not re.match(r'^[0-9]{10,16}$', utr):
        # UTR format off = raise floor slightly
        final_risk = max(final_risk, 60)

    # Final classification (3-tier, not binary)
    if final_risk >= 75:
        final_verdict = "SCAM"
    elif final_risk >= 40:
        final_verdict = "SUSPICIOUS"
    else:
        final_verdict = "SAFE"

    # Visual safety override - if AI says genuine and risk < 60, trust it
    if visual_verdict == "genuine" and final_risk < 60:
        final_verdict = "SAFE"

    # Normalize reasons
    why = []
    for r in ai_reasons:
        if isinstance(r, dict):
            why.append(r)
        elif isinstance(r, str):
            why.append({"en": r, "hi": ""})

    # Visual forensics
    visual_forensics = []
    for vs in visual_signals:
        if isinstance(vs, str):
            visual_forensics.append({"en": vs, "hi": ""})
        elif isinstance(vs, dict):
            visual_forensics.append(vs)

    # Ensure verdict label exists
    if final_verdict not in VERDICT_LABELS:
        final_verdict = "SUSPICIOUS"

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

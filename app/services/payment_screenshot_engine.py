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


PROMPT = """You are a forensic expert specializing in UPI payment screenshot fraud detection in India. You have analyzed thousands of real and fake UPI payment screenshots across apps like Google Pay, PhonePe, Paytm, BHIM, CRED, Navi, and WhatsApp Pay.

Your task is to analyze the provided screenshot and determine whether it is:
1. GENUINE
2. SUSPICIOUS
3. FAKE

Be strict with fake detection, fair with genuine cases, and decisive in your conclusion.

STEP 1: VISUAL FORENSIC ANALYSIS
Check for signs of image tampering:
- Font inconsistencies (amount vs rest of text)
- Misalignment in spacing, padding, or layout
- Blurry or sharp edges around amount or key fields (copy-paste traces)
- Color mismatch in amount text or UI elements
- Logo distortion (blurred, stretched, wrong color)
- Checkmark icon incorrect size, shade, or placement
- Status bar inconsistencies (time, battery, network icons look fake or missing)
- Any element appearing "pasted" or rendered differently
If multiple issues found: mark as FAKE

STEP 2: UI & APP AUTHENTICITY CHECK
Verify whether UI matches real app design:
- Google Pay: clean layout, "Google Pay" branding, proper spacing, usually 2 transaction IDs
- PhonePe: purple header, white checkmark in circle, "Transaction Successful"
- Paytm: blue theme, "Paid Successfully", "UPI Ref No"
- BHIM: government orange/blue UI
- CRED: dark premium UI with masked account numbers
- WhatsApp Pay: green theme, chat-based confirmation
- Navi: green header with "Navi Transaction ID"

Check for:
- Missing buttons (like "View Details")
- Incorrect button placement
- Abnormal spacing or alignment
If UI does not match known design: FAKE

STEP 3: TRANSACTION DATA VALIDATION
Analyze transaction details:
- Check if UTR / Transaction ID is present
- UTR should typically be numeric (10-16 digits, often ~12 digits in India)
- Avoid repeated patterns like 111111, 123456, etc.
- Timestamp should be realistic (not future or invalid)
- Amount should be valid (> 0)

UPI ID red flags:
- Contains words like: support, refund, help, verify, prize, reward, kyc, rbi, bank
If data looks fabricated: SUSPICIOUS or FAKE

STEP 4: IMAGE QUALITY & COMPRESSION
- Real screenshots usually have slight compression artifacts
- Completely clean / overly perfect image: possible fake generator
- WhatsApp-forwarded images may have compression (do NOT mark fake for this alone)

STEP 5: CONTEXTUAL / BEHAVIORAL FRAUD PATTERNS
Consider common scam behaviors:
- Sender insists "payment done" but asks not to check immediately
- Claims delay due to "server issue" or "weekend"
- Refuses to share live proof or screen recording
- Pushes urgency after sending screenshot
If combined with visual issues: FAKE

STEP 6: FINAL VERDICT LOGIC
- If strong visual tampering OR wrong UI: FAKE
- If minor inconsistencies OR unclear: SUSPICIOUS
- If everything aligns correctly: GENUINE

Also extract all visible fields from the screenshot.

RETURN ONLY VALID JSON (no markdown, no text outside JSON):
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
    "Paytm blue header matches genuine design exactly",
    "Status bar real - carrier, time, battery all visible"
  ],
  "verdict": "SAFE",
  "risk_percentage": 8,
  "confidence": "high",
  "reasons": [
    {"en": "All visual elements match genuine Paytm design", "hi": "सभी visual elements असली Paytm design से match करते हैं"},
    {"en": "UTR number present and format valid", "hi": "UTR number present है और format valid है"},
    {"en": "Merchant QR UPI ID (@ptys) is genuine Paytm handle", "hi": "@ptys genuine Paytm merchant handle है"}
  ]
}

Return ONLY the JSON. No markdown. No text outside JSON."""


def _run_ai_analysis(image_bytes: bytes) -> dict:
    b64 = _image_to_base64(image_bytes)
    media_type = _detect_media_type(image_bytes)

    response = get_client().chat.completions.create(
        model="gpt-4o-mini",
        max_tokens=1500,
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

    # Map AI verdict to risk if not already set
    ai_verdict_str = (ai_result.get("verdict") or "SUSPICIOUS").upper()
    if ai_verdict_str == "FAKE":
        ai_verdict_str = "SCAM"
    elif ai_verdict_str == "GENUINE":
        ai_verdict_str = "SAFE"

    # Use AI verdict directly - trust the AI
    final_verdict = ai_verdict_str
    final_risk = round(ai_risk)

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

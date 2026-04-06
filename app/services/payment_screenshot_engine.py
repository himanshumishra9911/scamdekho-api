# -*- coding: utf-8 -*-
"""
Payment Screenshot Engine v3.0 - ScamDekho
============================================
AI-First Architecture (Option B)

Flow:
  1. GPT-4o-mini Vision -> extract all fields + visual verdict + risk score
  2. Hard Rule Checks (4 rules only - catches obvious scams AI might miss)
  3. Pattern Memory (MongoDB perceptual hash)
  4. Final verdict combining AI + hard rules

Why this is better than v2:
  - No more OCR extraction failures ("UPI Ref No" vs "UTR" etc)
  - No more rule engine firing on empty fields
  - AI reads context like a human - understands any label/format
  - Still catches: scam UPI keywords, future timestamps, pattern matches
"""

import asyncio
import os
import re
import json
import base64
import hashlib
import io
from datetime import datetime
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()


def get_client():
    """Lazy OpenAI client - avoids crash at import time."""
    return OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


# -----------------------------------------------------------------------------
# HARD RULE CONSTANTS  (only 4 rules - clear-cut fraud signals)
# -----------------------------------------------------------------------------

# Scam keywords in UPI ID - no legitimate business uses these
SCAM_UPI_KEYWORDS = [
    "support", "refund", "helpdesk", "kyc", "kycupdate", "kycverify",
    "help", "care", "customercare", "verify", "verification",
    "reward", "prize", "lucky", "lottery", "offer", "cashback",
    "neft", "imps", "rtgs", "bank", "rbi", "npci", "govt", "gov",
    "pmkisan", "pmjandhan", "income", "tax",
]

# Earliest possible UPI transaction date (UPI launched Aug 2016)
UPI_LAUNCH_YEAR = 2016

# Pattern memory: hamming distance threshold for "same template"
PHASH_THRESHOLD = 20


# -----------------------------------------------------------------------------
# HELPER: IMAGE -> BASE64
# -----------------------------------------------------------------------------

def _image_to_base64(image_bytes: bytes) -> str:
    return base64.b64encode(image_bytes).decode("utf-8")


def _detect_media_type(image_bytes: bytes) -> str:
    if image_bytes[:8] == b'\x89PNG\r\n\x1a\n':
        return "image/png"
    if image_bytes[:3] == b'\xff\xd8\xff':
        return "image/jpeg"
    if image_bytes[:4] == b'RIFF' and image_bytes[8:12] == b'WEBP':
        return "image/webp"
    return "image/jpeg"  # fallback


# -----------------------------------------------------------------------------
# MAIN AI ANALYSIS  (single GPT-4o-mini call - does everything)
# -----------------------------------------------------------------------------

def _run_ai_analysis(image_bytes: bytes) -> dict:
    """
    Single GPT-4o-mini call that:
    1. Identifies the UPI app
    2. Extracts all fields (handles any label variation)
    3. Visually inspects for tampering
    4. Returns structured verdict + risk score
    """

    b64 = _image_to_base64(image_bytes)
    media_type = _detect_media_type(image_bytes)

    prompt = """You are a forensic expert specializing in UPI payment screenshot fraud detection in India. You have seen thousands of both real and fake screenshots.

YOUR JOB: Analyze this screenshot and determine if it is GENUINE or FAKE with maximum accuracy.

== FAKE SCREENSHOT RED FLAGS ==

VISUAL TAMPERING:
- Font looks different in amount area vs rest of screen (size, weight, spacing, family)
- Amount text has slightly different color, background, or shadow than surrounding text
- Pixels around amount look blurry, smeared, or have hard edges (copy-paste artifact)
- Logo is blurry, pixelated, wrong shade, or stretched
- Green checkmark looks wrong - wrong size, wrong shade, wrong position
- Status bar looks fake - wrong font, missing elements, or inconsistent
- Any element looks "pasted on" - different rendering quality than rest of image

FAKE APP / GENERATOR SIGNS:
- UI layout does not match the real app - buttons wrong place, wrong spacing
- Missing UI elements that real app always shows
- Watermark from a fake screenshot generator app
- Suspiciously perfect image with zero compression artifacts

SUSPICIOUS DATA:
- UTR/transaction ID missing entirely (except bill payment or CRED - normal for those)
- UPI ID contains: support, refund, kyc, help, care, verify, reward, prize, bank, rbi
- Timestamp before 2016 or in future
- Amount is zero or negative

== GENUINE SCREENSHOT SIGNS ==
- Consistent fonts throughout entire screenshot
- Status bar looks real (carrier name, time, battery visible)
- App UI exactly matches known genuine design
- UTR/ref number present with correct format
- Slight JPEG compression artifacts visible (real phone screenshots)
- Amount in words matches amount in numbers

== APP GENUINE DESIGNS ==
Paytm: blue header, "Paid Successfully", green checkmark badge, "UPI Ref No:" label, Paytm + UPI + bank logo at bottom. Merchant QR UPI IDs ending @ptys or @paytm = completely genuine.
PhonePe: deep purple/violet header, white circle checkmark, "Transaction Successful" text.
GPay: "Google Pay" text at bottom. Black (dark) OR white (light) background - BOTH genuine. TWO transaction IDs shown (long UPI ID + short Google ID) - BOTH real.
CRED: dark premium UI. Masked bank account "XXXXXX2729" instead of UPI ID = NORMAL. Payment flow steps instead of simple UTR = NORMAL. Condensed premium fonts = BY DESIGN.
WhatsApp Pay: green WhatsApp theme, "Sent" status.
BHIM: orange/blue government theme, "BHIM" logo.
Navi: green header, "Navi Transaction ID" label, may show masked UPI.
Bill payments: UTR may not show immediately = normal.

== CRITICAL RULES ==
- Cross-app payments are normal in India - any app can pay to any UPI handle
- "UPI Ref No", "Reference No", "Transaction ID", "UTR", "Ref ID" = ALL the same thing
- WhatsApp forwarded screenshots may have compression - do not flag that alone as fake
- Be STRICT with fakes - clear visual tampering = SCAM (high risk score)
- Be FAIR with genuine ones - all checks pass = SAFE (low risk score)
- Be DECISIVE - avoid calling everything SUSPICIOUS when evidence is clear

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
}"""

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
                        "text": prompt
                    }
                ]
            }
        ]
    )

    raw = response.choices[0].message.content.strip()

    # Strip markdown fences if present
    if raw.startswith("```"):
        raw = re.sub(r"^```[a-z]*\n?", "", raw)
        raw = re.sub(r"\n?```$", "", raw)
        raw = raw.strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # Try to extract JSON object from response
        match = re.search(r'\{.*\}', raw, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except Exception:
                pass
        return {}


# -----------------------------------------------------------------------------
# HARD RULE 1 - Scam keywords in UPI ID
# -----------------------------------------------------------------------------

def _check_scam_upi_keywords(upi_id: str) -> dict | None:
    """Returns a signal dict if scam keyword found, else None."""
    if not upi_id or "@" not in upi_id:
        return None
    upi_lower = upi_id.lower()
    for keyword in SCAM_UPI_KEYWORDS:
        if keyword in upi_lower:
            return {
                "type": "red_flag",
                "weight": 45,
                "en": f"Scam keyword '{keyword}' in UPI ID - classic fraud pattern",
                "hi": f"UPI ID में scam keyword '{keyword}' है - fraud का classic pattern"
            }
    return None


# -----------------------------------------------------------------------------
# HARD RULE 2 - Impossible timestamp
# -----------------------------------------------------------------------------

def _check_timestamp(timestamp: str) -> dict | None:
    """Flag future dates or dates before UPI launch."""
    if not timestamp:
        return None
    now = datetime.utcnow()

    # Try to find a year in the timestamp
    year_match = re.search(r'20\d{2}', timestamp)
    if not year_match:
        return None
    year = int(year_match.group())

    if year < UPI_LAUNCH_YEAR:
        return {
            "type": "red_flag",
            "weight": 50,
            "en": f"Timestamp year {year} is before UPI was launched (2016) - impossible",
            "hi": f"Timestamp year {year} UPI launch (2016) से पहले है - impossible"
        }
    if year > now.year + 1:
        return {
            "type": "red_flag",
            "weight": 50,
            "en": f"Timestamp shows future year {year} - screenshot is fake",
            "hi": f"Timestamp future year {year} दिखा रहा है - screenshot fake है"
        }
    return None


# -----------------------------------------------------------------------------
# HARD RULE 3 - Zero / negative amount
# -----------------------------------------------------------------------------

def _check_amount(amount: str) -> dict | None:
    """Flag ₹0 or negative amounts."""
    if not amount:
        return None
    # Extract numeric part
    nums = re.sub(r'[^\d.]', '', amount)
    if not nums:
        return None
    try:
        val = float(nums)
        if val <= 0:
            return {
                "type": "red_flag",
                "weight": 60,
                "en": f"Amount is ₹{val} - zero or negative amounts are impossible in real UPI",
                "hi": f"Amount ₹{val} है - real UPI में zero या negative amount impossible है"
            }
    except ValueError:
        pass
    return None


# -----------------------------------------------------------------------------
# HARD RULE 4 - Pattern memory (perceptual hash)
# -----------------------------------------------------------------------------

def _perceptual_hash(image_bytes: bytes) -> str:
    """Simple perceptual hash using PIL resize + average."""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes)).convert("L").resize((16, 16), Image.LANCZOS)
        pixels = list(img.getdata())
        avg = sum(pixels) / len(pixels)
        bits = "".join("1" if p >= avg else "0" for p in pixels)
        hex_hash = format(int(bits, 2), "064x")
        return hex_hash
    except Exception:
        return hashlib.md5(image_bytes).hexdigest()


def _hamming_distance(h1: str, h2: str) -> int:
    if len(h1) != len(h2):
        max_len = max(len(h1), len(h2)) * 4
        n1 = int(h1, 16)
        n2 = int(h2, 16)
        return bin(n1 ^ n2).count("1")
    return bin(int(h1, 16) ^ int(h2, 16)).count("1")


async def _check_pattern_memory(image_bytes: bytes) -> dict:
    """Check perceptual hash against known fake templates in MongoDB."""
    result = {"found": False, "match_count": 0, "signal": None, "current_phash": None}
    try:
        from app.core.database import db
        loop = asyncio.get_running_loop()
        phash = await loop.run_in_executor(None, _perceptual_hash, image_bytes)
        result["current_phash"] = phash

        cursor = db.fake_screenshot_hashes.find(
            {"verdict": "SCAM"}, {"phash": 1, "count": 1, "app": 1}
        ).limit(200)

        async for doc in cursor:
            stored = doc.get("phash", "")
            if not stored:
                continue
            if _hamming_distance(phash, stored) < PHASH_THRESHOLD:
                result["found"] = True
                result["match_count"] = doc.get("count", 1)
                result["signal"] = {
                    "type": "red_flag",
                    "weight": 20,
                    "en": f"Matches known fake template seen {result['match_count']} times - verify manually",
                    "hi": f"Known fake template से match - {result['match_count']} बार पहले देखा"
                }
                break
        return result
    except Exception as e:
        print(f"PATTERN MEMORY ERROR: {e}")
        return result


async def _save_pattern_memory(phash: str, app_key: str):
    """Save confirmed SCAM hash to DB (fire-and-forget)."""
    try:
        from app.core.database import db
        if not phash:
            return
        existing = await db.fake_screenshot_hashes.find_one({"phash": phash})
        if existing:
            await db.fake_screenshot_hashes.update_one(
                {"phash": phash},
                {"$inc": {"count": 1}, "$set": {"last_seen": datetime.utcnow()}}
            )
        else:
            await db.fake_screenshot_hashes.insert_one({
                "phash": phash, "verdict": "SCAM", "app": app_key,
                "count": 1, "created_at": datetime.utcnow(), "last_seen": datetime.utcnow()
            })
    except Exception as e:
        print(f"SAVE PATTERN ERROR: {e}")


# -----------------------------------------------------------------------------
# VERDICT LABELS  (EN + HI)
# -----------------------------------------------------------------------------

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


# -----------------------------------------------------------------------------
# SCORE ADJUSTMENT - Hard rules adjust AI risk score
# -----------------------------------------------------------------------------

def _apply_hard_rules(ai_risk: float, hard_signals: list) -> float:
    """
    AI gives base risk. Hard rules push it up if clear fraud signals found.
    Each red_flag adds its weight using Bayesian-style update.
    """
    p = ai_risk / 100.0
    for sig in hard_signals:
        w = sig.get("weight", 0)
        stype = sig.get("type", "")
        if stype == "red_flag":
            lr = 1 + (w / 100) * 4.0   # strong push upward
            p = (p * lr) / (p * lr + (1 - p))
    return max(0.0, min(100.0, p * 100))


def _risk_to_verdict(risk: float) -> str:
    if risk <= 35:
        return "SAFE"
    if risk <= 65:
        return "SUSPICIOUS"
    return "SCAM"


# -----------------------------------------------------------------------------
# MAIN ENTRY POINT
# -----------------------------------------------------------------------------

async def analyze_payment_screenshot(image_bytes: bytes) -> dict:
    """
    Main analysis function. Returns structured result dict.

    Architecture (Option B - AI-first + 4 hard rules):
      1. GPT-4o-mini Vision -> full analysis (app, fields, visual verdict, risk)
      2. Hard Rule 1: scam UPI keywords
      3. Hard Rule 2: impossible timestamp
      4. Hard Rule 3: zero/negative amount
      5. Hard Rule 4: pattern memory (MongoDB)
      6. Combine AI risk + hard rule adjustments -> final verdict
    """

    # ----------------------------------------------------------------------------- Run AI analysis + pattern memory in parallel ----------------------
    loop = asyncio.get_running_loop()

    ai_task = loop.run_in_executor(None, _run_ai_analysis, image_bytes)
    pattern_task = _check_pattern_memory(image_bytes)

    ai_result, pattern_result = await asyncio.gather(ai_task, pattern_task)

    # ----------------------------------------------------------------------------- Parse AI result ---------------------------------------------------
    app_name       = ai_result.get("app_name") or "Unknown"
    app_key        = (ai_result.get("app_key") or "unknown").lower()
    app_confidence = int(ai_result.get("app_confidence") or 0)
    fields         = ai_result.get("fields") or {}
    visual_verdict = ai_result.get("visual_verdict") or "unknown"
    visual_signals = ai_result.get("visual_signals") or []
    ai_verdict     = ai_result.get("verdict") or "SUSPICIOUS"
    ai_risk        = float(ai_result.get("risk_percentage") or 50)
    ai_confidence  = ai_result.get("confidence") or "medium"
    ai_reasons     = ai_result.get("reasons") or []

    # Normalize ai_reasons to list of dicts with en/hi keys
    normalized_reasons = []
    for r in ai_reasons:
        if isinstance(r, dict):
            normalized_reasons.append(r)
        elif isinstance(r, str):
            normalized_reasons.append({"en": r, "hi": ""})

    # ----------------------------------------------------------------------------- Apply hard rules --------------------------------------------------
    hard_signals = []

    upi_id = (fields.get("upi_id") or "").strip()
    ts     = (fields.get("timestamp") or "").strip()
    amt    = (fields.get("amount") or "").strip()

    sig1 = _check_scam_upi_keywords(upi_id)
    if sig1:
        hard_signals.append(sig1)

    sig2 = _check_timestamp(ts)
    if sig2:
        hard_signals.append(sig2)

    sig3 = _check_amount(amt)
    if sig3:
        hard_signals.append(sig3)

    if pattern_result.get("found") and pattern_result.get("signal"):
        hard_signals.append(pattern_result["signal"])

    # ----------------------------------------------------------------------------- Compute final risk ------------------------------------------------
    if hard_signals:
        final_risk = _apply_hard_rules(ai_risk, hard_signals)
    else:
        final_risk = ai_risk

    final_risk    = round(final_risk)
    final_verdict = _risk_to_verdict(final_risk)

    # Confidence: if hard rules overrode AI verdict significantly, lower confidence
    if hard_signals and abs(final_risk - ai_risk) > 20:
        final_confidence = "medium"
    else:
        final_confidence = ai_confidence

    # ----------------------------------------------------------------------------- Build why signals (AI reasons + hard rule signals) ----------------
    why = list(normalized_reasons)
    for sig in hard_signals:
        why.append({"en": sig.get("en", ""), "hi": sig.get("hi", "")})

    # ----------------------------------------------------------------------------- Visual forensics signals for display ------------------------------
    visual_forensics = []
    for vs in visual_signals:
        if isinstance(vs, str):
            visual_forensics.append({"en": vs, "hi": ""})
        elif isinstance(vs, dict):
            visual_forensics.append(vs)

    # ----------------------------------------------------------------------------- Save to pattern memory if high-confidence SCAM --------------------
    phash = pattern_result.get("current_phash")
    if (phash
            and final_verdict == "SCAM"
            and app_confidence >= 75
            and visual_verdict == "fake"):
        asyncio.create_task(_save_pattern_memory(phash, app_key))

    # ----------------------------------------------------------------------------- Build response ----------------------------------------------------
    return {
        "verdict": final_verdict,
        "risk_percentage": final_risk,
        "confidence": final_confidence,
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
        "pattern_match": {
            "found": pattern_result.get("found", False),
            "match_count": pattern_result.get("match_count", 0),
        },
        "what_to_do": WHAT_TO_DO[final_verdict],
        "how_to_avoid": HOW_TO_AVOID,
    }
"""
Payment Screenshot Engine — ScamDekho
======================================
8-Layer Fake UPI Payment Screenshot Detector

Layers:
  1. App Detection + Confidence
  2. OCR Field Extraction + Validation
  3. Rule Engine (Weighted Signals)
  4. Consistency Cross-Check
  5. UPI ID Deep Check
  6. Vision AI Forensics (GPT-4o-mini)
  7. Fraud Pattern Memory (MongoDB perceptual hash)
  8. Soft Score Aggregator → SAFE / SUSPICIOUS / SCAM

Supported apps:
  PhonePe, Google Pay (GPay), Paytm, Amazon Pay, BHIM,
  Airtel Money, CRED, Navi, Slice, Juspay, iMobile (ICICI),
  Kotak, SBI YONO, Axis Pay, HDFC PayZapp, WhatsApp Pay,
  MobiKwik, Freecharge, generic UPI
"""

import os
import re
import json
import base64
import hashlib
import io
from datetime import datetime
from typing import Optional
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

def get_client():
    """Lazy OpenAI client init — avoids crash at import time."""
    return OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ─────────────────────────────────────────────
# APP REGISTRY
# Each entry: name, bg_color_hint, utr_prefix_pattern, handle_hints
# ─────────────────────────────────────────────
APP_REGISTRY = {
    "phonepe": {
        "display": "PhonePe",
        "color_hint": "purple",
        "utr_pattern": r"^\d{12}$",                          # 12 digit numeric
        "utr_prefix": None,
        "handles": ["ybl", "ibl", "axl", "oksbi"],
        "status_texts": ["payment successful", "paid", "money sent", "₹ sent to"],
        "logo_keywords": ["phonepe", "phone pe"],
    },
    "gpay": {
        "display": "Google Pay",
        "color_hint": "white",
        "utr_pattern": r"^[A-Z0-9]{20,35}$",                 # alphanumeric uppercase
        "utr_prefix": None,
        "handles": ["okaxis", "okicici", "oksbi", "okhdfcbank"],
        "status_texts": ["you paid", "payment done", "sent to"],
        "logo_keywords": ["google pay", "gpay", "g pay"],
    },
    "paytm": {
        "display": "Paytm",
        "color_hint": "blue",
        "utr_pattern": r"^\d{15,20}$",                       # long numeric
        "utr_prefix": None,
        "handles": ["paytm", "ptyes", "ptsbi"],
        "status_texts": ["payment successful", "paid successfully", "money transferred"],
        "logo_keywords": ["paytm"],
    },
    "bhim": {
        "display": "BHIM",
        "color_hint": "blue_dark",
        "utr_pattern": r"^\d{12}$",                          # standard RBI UTR = 12 digit
        "utr_prefix": None,
        "handles": ["upi", "bhim"],
        "status_texts": ["transaction successful", "payment done"],
        "logo_keywords": ["bhim", "bharat interface"],
    },
    "amazon_pay": {
        "display": "Amazon Pay",
        "color_hint": "orange",
        "utr_pattern": r"^[A-Za-z0-9]{15,25}$",
        "utr_prefix": None,
        "handles": ["apl", "yapl", "amazon"],
        "status_texts": ["payment successful", "paid"],
        "logo_keywords": ["amazon pay", "amazonpay"],
    },
    "airtel": {
        "display": "Airtel Money",
        "color_hint": "red",
        "utr_pattern": r"^\d{12,15}$",
        "utr_prefix": None,
        "handles": ["airtel", "airtelpaymentsbank"],
        "status_texts": ["transfer successful", "payment done"],
        "logo_keywords": ["airtel"],
    },
    "cred": {
        "display": "CRED",
        "color_hint": "black",
        "utr_pattern": r"^[A-Za-z0-9]{16,30}$",
        "utr_prefix": None,
        "handles": ["cred", "credpay"],
        "status_texts": ["payment successful", "sent"],
        "logo_keywords": ["cred"],
    },
    "whatsapp_pay": {
        "display": "WhatsApp Pay",
        "color_hint": "green",
        "utr_pattern": r"^\d{12}$",
        "utr_prefix": None,
        "handles": ["okaxis", "okicici", "oksbi"],
        "status_texts": ["payment sent", "₹ sent"],
        "logo_keywords": ["whatsapp", "whatsapp pay"],
    },
    "navi": {
        "display": "Navi",
        "color_hint": "yellow",
        "utr_pattern": r"^\d{12,18}$",
        "utr_prefix": None,
        "handles": ["navi", "naviaxis"],
        "status_texts": ["payment successful"],
        "logo_keywords": ["navi"],
    },
    "mobikwik": {
        "display": "MobiKwik",
        "color_hint": "blue",
        "utr_pattern": r"^\d{12,18}$",
        "utr_prefix": None,
        "handles": ["mbk", "ikwik", "mobikwik"],
        "status_texts": ["payment successful", "transfer done"],
        "logo_keywords": ["mobikwik"],
    },
    "freecharge": {
        "display": "FreeCharge",
        "color_hint": "green",
        "utr_pattern": r"^\d{12,18}$",
        "utr_prefix": None,
        "handles": ["freecharge", "fc"],
        "status_texts": ["payment successful"],
        "logo_keywords": ["freecharge"],
    },
    "slice": {
        "display": "Slice",
        "color_hint": "purple_light",
        "utr_pattern": r"^\d{12,18}$",
        "utr_prefix": None,
        "handles": ["slice", "slicepay"],
        "status_texts": ["payment done", "sent"],
        "logo_keywords": ["slice"],
    },
    "yono_sbi": {
        "display": "SBI YONO",
        "color_hint": "blue",
        "utr_pattern": r"^\d{12}$",
        "utr_prefix": None,
        "handles": ["sbi", "sbipay", "oksbi"],
        "status_texts": ["transaction successful", "amount debited"],
        "logo_keywords": ["yono", "sbi yono", "state bank"],
    },
    "imobile": {
        "display": "iMobile (ICICI)",
        "color_hint": "orange_dark",
        "utr_pattern": r"^\d{12}$",
        "utr_prefix": None,
        "handles": ["icici", "icicipay", "okicici"],
        "status_texts": ["transaction successful", "payment done"],
        "logo_keywords": ["imobile", "icici"],
    },
    "hdfc_payzapp": {
        "display": "HDFC PayZapp",
        "color_hint": "red",
        "utr_pattern": r"^\d{12}$",
        "utr_prefix": None,
        "handles": ["hdfc", "hdfcbank", "okhdfcbank"],
        "status_texts": ["payment successful", "transaction complete"],
        "logo_keywords": ["payzapp", "hdfc payzapp"],
    },
    "axis_pay": {
        "display": "Axis Pay",
        "color_hint": "maroon",
        "utr_pattern": r"^\d{12}$",
        "utr_prefix": None,
        "handles": ["axisbank", "axis", "axisgo", "okaxis"],
        "status_texts": ["payment done", "transfer successful"],
        "logo_keywords": ["axis pay", "axispay"],
    },
}

# ─────────────────────────────────────────────
# SCAM UPI KEYWORDS
# ─────────────────────────────────────────────
SCAM_UPI_KEYWORDS = [
    ("support", 35, "Fake support account pattern"),
    ("help", 30, "Fake helpdesk pattern"),
    ("refund", 35, "Refund fraud pattern"),
    ("kyc", 40, "KYC fraud pattern"),
    ("care", 25, "Fake care account pattern"),
    ("service", 20, "Fake service account"),
    ("bank", 15, "Possible bank impersonation"),
    ("official", 30, "Fake official account"),
    ("pm", 25, "Possible PM scheme impersonation"),
    ("reward", 30, "Reward/lottery scam pattern"),
    ("prize", 35, "Prize scam pattern"),
    ("winner", 35, "Lottery winner scam"),
    ("govt", 25, "Government impersonation"),
    ("income", 20, "Income tax fraud pattern"),
    ("tax", 20, "Tax fraud pattern"),
]

# ─────────────────────────────────────────────
# LAYER 1 — APP DETECTION via Vision AI
# ─────────────────────────────────────────────
def detect_app_from_image(image_bytes: bytes) -> dict:
    """
    Use GPT-4o-mini vision to detect which UPI app the screenshot is from.
    Returns app_key, display_name, confidence (0-100), reasoning.
    """
    try:
        app_list = ", ".join([v["display"] for v in APP_REGISTRY.values()])
        image_b64 = base64.b64encode(image_bytes).decode()

        response = get_client().chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": f"""Look at this screenshot and identify which UPI payment app it is from.

Known apps: {app_list}, or Unknown/Generic UPI

Return ONLY valid JSON:
{{
  "app_key": "phonepe|gpay|paytm|bhim|amazon_pay|airtel|cred|whatsapp_pay|navi|mobikwik|freecharge|slice|yono_sbi|imobile|hdfc_payzapp|axis_pay|unknown",
  "display_name": "PhonePe (or exact name)",
  "confidence": 0-100,
  "reasoning": "Why you think this is X app — color, logo, layout clues"
}}

Be strict — if you are not sure, say unknown with low confidence. Do not guess."""
                    },
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{image_b64}"}
                    }
                ]
            }],
            response_format={"type": "json_object"},
            temperature=0.1,
        )
        data = json.loads(response.choices[0].message.content)
        return {
            "app_key": data.get("app_key", "unknown").lower(),
            "display_name": data.get("display_name", "Unknown"),
            "confidence": int(data.get("confidence", 50)),
            "reasoning": data.get("reasoning", ""),
        }
    except Exception as e:
        print(f"APP DETECT ERROR: {e}")
        return {"app_key": "unknown", "display_name": "Unknown", "confidence": 0, "reasoning": "Detection failed"}


# ─────────────────────────────────────────────
# LAYER 2 — OCR FIELD EXTRACTION via Vision AI
# Much more reliable than Tesseract on styled UPI screens
# ─────────────────────────────────────────────
def extract_fields_from_image(image_bytes: bytes, app_key: str) -> dict:
    """
    Extract structured payment fields from the screenshot using Vision AI.
    More accurate than Tesseract on colored/styled UPI success screens.
    """
    try:
        image_b64 = base64.b64encode(image_bytes).decode()
        app_info = APP_REGISTRY.get(app_key, {})

        response = get_client().chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[{
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": """Extract all payment details from this UPI payment screenshot.

Return ONLY valid JSON with these exact fields (use null if not visible):
{
  "amount": "exact amount shown e.g. ₹5,000 or 5000.00",
  "amount_numeric": 5000.00,
  "transaction_id": "UTR or transaction reference number",
  "upi_id": "recipient UPI ID e.g. someone@ybl",
  "recipient_name": "name of recipient shown",
  "sender_name": "name of sender if shown",
  "bank_name": "bank name if visible",
  "timestamp": "date and time shown e.g. 12 Jan 2025, 3:45 PM",
  "status_text": "exact success/failure text shown",
  "payment_note": "remarks or note if any",
  "raw_text_visible": "any other text you can read on screen"
}

Be precise. If a field is partially visible or unclear, still include what you can read with a note."""
                    },
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{image_b64}"}
                    }
                ]
            }],
            response_format={"type": "json_object"},
            temperature=0.1,
        )
        data = json.loads(response.choices[0].message.content)
        return {
            "amount": data.get("amount"),
            "amount_numeric": data.get("amount_numeric"),
            "transaction_id": data.get("transaction_id"),
            "upi_id": data.get("upi_id"),
            "recipient_name": data.get("recipient_name"),
            "sender_name": data.get("sender_name"),
            "bank_name": data.get("bank_name"),
            "timestamp": data.get("timestamp"),
            "status_text": data.get("status_text"),
            "payment_note": data.get("payment_note"),
            "raw_text_visible": data.get("raw_text_visible", ""),
        }
    except Exception as e:
        print(f"FIELD EXTRACT ERROR: {e}")
        return {k: None for k in ["amount", "amount_numeric", "transaction_id", "upi_id",
                                   "recipient_name", "sender_name", "bank_name", "timestamp",
                                   "status_text", "payment_note", "raw_text_visible"]}


# ─────────────────────────────────────────────
# LAYER 2B — OCR FIELD VALIDATION (Regex checks)
# ─────────────────────────────────────────────
def validate_extracted_fields(fields: dict, app_key: str) -> list:
    """
    Validate each extracted field against expected patterns.
    Returns list of validation signals with weights.
    """
    signals = []
    app_info = APP_REGISTRY.get(app_key, {})

    # --- Transaction ID validation ---
    txn_id = (fields.get("transaction_id") or "").strip().replace(" ", "")
    if not txn_id:
        signals.append({
            "type": "red_flag", "weight": 25,
            "en": "Transaction ID / UTR not found in screenshot",
            "hi": "स्क्रीनशॉट में Transaction ID / UTR नहीं मिला"
        })
    else:
        utr_pattern = app_info.get("utr_pattern")
        if utr_pattern and not re.match(utr_pattern, txn_id):
            signals.append({
                "type": "red_flag", "weight": 30,
                "en": f"UTR format invalid for {app_info.get('display', app_key)} (got: {txn_id[:20]})",
                "hi": f"UTR format {app_info.get('display', app_key)} के लिए गलत है"
            })
        else:
            signals.append({
                "type": "green_flag", "weight": -10,
                "en": f"UTR format valid for {app_info.get('display', app_key)}",
                "hi": f"UTR format सही है"
            })

    # --- Amount validation ---
    amount_str = (fields.get("amount") or "").strip()
    amount_num = fields.get("amount_numeric")
    if not amount_str or not amount_num:
        signals.append({
            "type": "red_flag", "weight": 15,
            "en": "Amount not clearly visible in screenshot",
            "hi": "स्क्रीनशॉट में amount स्पष्ट नहीं है"
        })
    else:
        # Check for suspiciously round amounts
        if amount_num and amount_num > 0:
            if amount_num % 1000 == 0 and amount_num >= 1000:
                signals.append({
                    "type": "warning", "weight": 10,
                    "en": f"Round amount ₹{amount_num:,.0f} — common in fake screenshots",
                    "hi": f"Round amount ₹{amount_num:,.0f} — नकली screenshots में आम है"
                })
        # Amount format: should have ₹ symbol or INR
        if not re.search(r'[₹\d]', amount_str):
            signals.append({
                "type": "warning", "weight": 10,
                "en": "Amount format unusual (no ₹ symbol or digits found)",
                "hi": "Amount format असामान्य है"
            })

    # --- UPI ID basic validation ---
    upi_id = (fields.get("upi_id") or "").strip().lower()
    if upi_id:
        if not re.match(r'^[\w.\-]+@[\w.\-]+$', upi_id):
            signals.append({
                "type": "red_flag", "weight": 20,
                "en": f"UPI ID format invalid: {upi_id}",
                "hi": f"UPI ID format गलत है: {upi_id}"
            })
    else:
        signals.append({
            "type": "warning", "weight": 10,
            "en": "UPI ID not visible in screenshot",
            "hi": "UPI ID screenshot में नहीं दिख रहा"
        })

    # --- Timestamp validation ---
    ts = (fields.get("timestamp") or "").strip()
    if not ts:
        signals.append({
            "type": "warning", "weight": 10,
            "en": "Timestamp not visible in screenshot",
            "hi": "Timestamp screenshot में नहीं है"
        })
    else:
        # Check for future date
        try:
            # Try to find year in timestamp
            year_match = re.search(r'20(\d{2})', ts)
            if year_match:
                year = int("20" + year_match.group(1))
                if year > datetime.now().year:
                    signals.append({
                        "type": "red_flag", "weight": 35,
                        "en": f"Future date detected in timestamp: {ts}",
                        "hi": f"Timestamp में भविष्य की date है: {ts}"
                    })
                elif year < 2016:
                    signals.append({
                        "type": "red_flag", "weight": 30,
                        "en": f"Impossible year in timestamp (UPI launched 2016): {ts}",
                        "hi": f"Timestamp में impossible year है: {ts}"
                    })
        except Exception:
            pass

    # --- Bank name ---
    if not fields.get("bank_name"):
        signals.append({
            "type": "warning", "weight": 15,
            "en": "Bank name not visible — genuine receipts usually show bank",
            "hi": "Bank का नाम नहीं दिख रहा — असली receipt में bank दिखता है"
        })

    return signals


# ─────────────────────────────────────────────
# LAYER 3 — RULE ENGINE (Weighted Signals)
# ─────────────────────────────────────────────
def run_rule_engine(fields: dict, app_key: str, app_confidence: int) -> list:
    """
    Apply all heuristic rules. Returns list of signal dicts with weights.
    """
    signals = []
    app_info = APP_REGISTRY.get(app_key, {})

    # Rule R1: Low app detection confidence
    if app_confidence < 60:
        signals.append({
            "type": "red_flag", "weight": 20,
            "en": f"Payment app not clearly identified (confidence: {app_confidence}%) — suspicious",
            "hi": f"Payment app clearly identify नहीं हुआ ({app_confidence}% confidence) — संदिग्ध"
        })
    elif app_key == "unknown":
        signals.append({
            "type": "red_flag", "weight": 25,
            "en": "Unknown payment app — not from any recognized UPI platform",
            "hi": "Unknown payment app — किसी recognized UPI platform का नहीं"
        })

    # Rule R2: No verifiable proof at all → auto suspicious floor
    extractable_fields = [
        fields.get("transaction_id"),
        fields.get("amount"),
        fields.get("upi_id"),
        fields.get("timestamp"),
    ]
    filled_fields = sum(1 for f in extractable_fields if f)
    if filled_fields <= 1:
        signals.append({
            "type": "red_flag", "weight": 30,
            "en": "Very few verifiable fields found — screenshot likely fake or too cropped",
            "hi": "बहुत कम verifiable details मिले — screenshot नकली या incomplete लगता है"
        })

    # Rule R3: Status text check
    status = (fields.get("status_text") or "").lower()
    if not status:
        signals.append({
            "type": "warning", "weight": 12,
            "en": "Payment status text not found in screenshot",
            "hi": "Payment status text नहीं मिला"
        })
    else:
        known_texts = app_info.get("status_texts", [])
        if known_texts and not any(t in status for t in known_texts):
            signals.append({
                "type": "warning", "weight": 15,
                "en": f"Status text '{status[:40]}' unusual for {app_info.get('display', app_key)}",
                "hi": f"Status text {app_info.get('display', app_key)} के लिए unusual है"
            })
        else:
            signals.append({
                "type": "green_flag", "weight": -8,
                "en": "Payment status text matches expected format",
                "hi": "Payment status text सही format में है"
            })

    return signals


# ─────────────────────────────────────────────
# LAYER 4 — CONSISTENCY CROSS-CHECK
# App vs UTR, UPI handle vs App, Amount vs Status
# ─────────────────────────────────────────────
def run_consistency_check(fields: dict, app_key: str) -> list:
    """
    Cross-check fields against each other and the detected app.
    App+UTR mismatch = direct strong SCAM signal.
    """
    signals = []
    app_info = APP_REGISTRY.get(app_key, {})

    # C1: UPI ID handle vs detected app
    upi_id = (fields.get("upi_id") or "").strip().lower()
    if upi_id and "@" in upi_id:
        handle = upi_id.split("@")[1]
        expected_handles = app_info.get("handles", [])
        if expected_handles and handle not in expected_handles:
            # Check if handle belongs to a DIFFERENT app
            for other_key, other_info in APP_REGISTRY.items():
                if other_key != app_key and handle in other_info.get("handles", []):
                    signals.append({
                        "type": "red_flag", "weight": 40,
                        "en": f"MISMATCH: Screenshot claims {app_info.get('display', app_key)} but UPI handle @{handle} belongs to {other_info['display']}",
                        "hi": f"मिसमैच: Screenshot {app_info.get('display', app_key)} दिखा रहा है लेकिन @{handle} handle {other_info['display']} का है"
                    })
                    break
            else:
                # Handle not found in any known app — unknown handle
                signals.append({
                    "type": "warning", "weight": 12,
                    "en": f"UPI handle @{handle} not in expected handles for {app_info.get('display', app_key)}",
                    "hi": f"@{handle} handle {app_info.get('display', app_key)} के expected handles में नहीं है"
                })
        elif expected_handles and handle in expected_handles:
            signals.append({
                "type": "green_flag", "weight": -12,
                "en": f"UPI handle @{handle} matches {app_info.get('display', app_key)}",
                "hi": f"UPI handle @{handle} {app_info.get('display', app_key)} से match करता है"
            })

    # C2: UTR format vs app
    txn_id = (fields.get("transaction_id") or "").strip().replace(" ", "")
    if txn_id and app_key != "unknown":
        utr_pattern = app_info.get("utr_pattern")
        if utr_pattern:
            if not re.match(utr_pattern, txn_id):
                # Check if it matches another app's pattern
                for other_key, other_info in APP_REGISTRY.items():
                    if other_key != app_key:
                        other_pat = other_info.get("utr_pattern")
                        if other_pat and re.match(other_pat, txn_id):
                            signals.append({
                                "type": "red_flag", "weight": 40,
                                "en": f"UTR format matches {other_info['display']} but screenshot shows {app_info.get('display', app_key)} — definite mismatch",
                                "hi": f"UTR format {other_info['display']} का है लेकिन screenshot {app_info.get('display', app_key)} दिखा रहा है"
                            })
                            break

    # C3: Amount consistency — "₹5000" vs status "₹500 sent"
    amount_num = fields.get("amount_numeric")
    raw_text = (fields.get("raw_text_visible") or "").lower()
    if amount_num and raw_text:
        # Look for another amount mentioned in raw text
        other_amounts = re.findall(r'₹\s*(\d[\d,]*(?:\.\d{1,2})?)', raw_text)
        for oa in other_amounts:
            oa_clean = float(oa.replace(",", ""))
            if abs(oa_clean - amount_num) > 1 and oa_clean != amount_num:
                if oa_clean < amount_num * 0.5 or oa_clean > amount_num * 2:
                    signals.append({
                        "type": "warning", "weight": 15,
                        "en": f"Amount inconsistency: main shows ₹{amount_num} but other text shows ₹{oa}",
                        "hi": f"Amount inconsistency: main ₹{amount_num} दिखा रहा है लेकिन अन्य text में ₹{oa} है"
                    })
                    break

    return signals


# ─────────────────────────────────────────────
# LAYER 5 — UPI ID DEEP CHECK
# ─────────────────────────────────────────────
def run_upi_id_check(upi_id: str) -> list:
    """
    Check UPI ID for scam patterns without calling external API.
    Returns weighted signals.
    """
    signals = []
    if not upi_id:
        return signals

    upi_lower = upi_id.lower().strip()
    username = upi_lower.split("@")[0] if "@" in upi_lower else upi_lower

    # Check scam keywords
    for keyword, weight, reason in SCAM_UPI_KEYWORDS:
        if keyword in username:
            signals.append({
                "type": "red_flag", "weight": weight,
                "en": f"Scam keyword '{keyword}' in UPI ID — {reason}",
                "hi": f"UPI ID में scam keyword '{keyword}' — {reason}"
            })

    # Check if username is suspiciously generic
    generic_patterns = [
        r'^[a-z]{1,3}\d{6,}$',      # letters + long number = temp account
        r'^\d{10}$',                  # just phone number
        r'^test',                     # test account
        r'^demo',                     # demo account
        r'^fake',                     # literally fake
        r'^sample',
    ]
    for pat in generic_patterns:
        if re.match(pat, username):
            signals.append({
                "type": "warning", "weight": 15,
                "en": f"UPI ID '{upi_id}' looks like a temporary/generic account",
                "hi": f"UPI ID '{upi_id}' temporary/generic account जैसा लगता है"
            })
            break

    # Positive signals
    if len(username) >= 5 and not any(k in username for k, _, _ in SCAM_UPI_KEYWORDS):
        signals.append({
            "type": "green_flag", "weight": -8,
            "en": "UPI ID has no known scam keywords",
            "hi": "UPI ID में कोई scam keyword नहीं"
        })

    return signals


# ─────────────────────────────────────────────
# LAYER 6 — VISION AI FORENSICS
# ─────────────────────────────────────────────

VISION_FORENSICS_SYSTEM = """You are a forensic expert specializing in detecting fake UPI payment screenshots in India.

You will receive a payment screenshot and context from rule analysis.
Your job is to visually inspect the image for signs of tampering or fakery.

Return ONLY valid JSON:
{
  "visual_risk_score": 0-100,
  "logo_authentic": true/false,
  "font_consistent": true/false,
  "color_scheme_correct": true/false,
  "pixel_artifacts_detected": true/false,
  "amount_area_suspicious": true/false,
  "ui_matches_claimed_app": true/false,
  "overall_visual_verdict": "genuine|suspicious|fake",
  "visual_flags": [
    {"en": "specific visual issue found", "hi": "Hindi version"}
  ],
  "visual_safe_signals": [
    {"en": "positive visual signal", "hi": "Hindi version"}
  ],
  "visual_reasoning": "detailed explanation of what you see"
}

STRICT RULES:
1. If logo is blurry, stretched, or pixelated → flag it
2. If font in amount field looks different from rest of UI → flag it
3. If colors don't match the claimed app → flag it
4. If there are pixel inconsistencies around text (common in edited screenshots) → flag it
5. If the overall layout feels "off" or generic → flag it
6. IMPORTANT: If unsure → mark SUSPICIOUS, NOT genuine/safe
7. Fake payment generator apps create screenshots that look real — look for subtle differences in spacing, font weight, icon quality
8. Green tick / checkmark — is it the same style as the real app uses?"""


def run_vision_forensics(image_bytes: bytes, app_key: str, app_display: str, rule_context: str) -> dict:
    """
    Deep visual forensics using Vision AI.
    Returns visual risk score and specific visual flags.
    """
    try:
        image_b64 = base64.b64encode(image_bytes).decode()
        app_info = APP_REGISTRY.get(app_key, {})

        prompt = f"""Analyze this UPI payment screenshot for authenticity.

CLAIMED APP: {app_display}
EXPECTED COLOR SCHEME: {app_info.get('color_hint', 'unknown')}
EXPECTED STATUS TEXTS: {', '.join(app_info.get('status_texts', []))}

RULE ENGINE CONTEXT (pre-detected issues):
{rule_context}

Now do a VISUAL forensic analysis:
- Is this genuinely from {app_display}?
- Any signs of image editing, cropping, or template use?
- Does the amount field look native or pasted?
- Is the transaction ID area visually consistent?

Remember: If unsure → mark suspicious, not genuine."""

        response = get_client().chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": VISION_FORENSICS_SYSTEM},
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": prompt},
                        {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{image_b64}"}}
                    ]
                }
            ],
            response_format={"type": "json_object"},
            temperature=0.1,
        )
        data = json.loads(response.choices[0].message.content)
        return {
            "visual_risk_score": int(data.get("visual_risk_score", 50)),
            "logo_authentic": data.get("logo_authentic", None),
            "font_consistent": data.get("font_consistent", None),
            "color_scheme_correct": data.get("color_scheme_correct", None),
            "pixel_artifacts_detected": data.get("pixel_artifacts_detected", False),
            "amount_area_suspicious": data.get("amount_area_suspicious", False),
            "ui_matches_claimed_app": data.get("ui_matches_claimed_app", None),
            "overall_visual_verdict": data.get("overall_visual_verdict", "suspicious"),
            "visual_flags": data.get("visual_flags", []),
            "visual_safe_signals": data.get("visual_safe_signals", []),
            "visual_reasoning": data.get("visual_reasoning", ""),
        }
    except Exception as e:
        print(f"VISION FORENSICS ERROR: {e}")
        return {
            "visual_risk_score": 50,
            "overall_visual_verdict": "suspicious",
            "visual_flags": [],
            "visual_safe_signals": [],
            "visual_reasoning": "Visual analysis failed",
            "logo_authentic": None,
            "font_consistent": None,
            "color_scheme_correct": None,
            "pixel_artifacts_detected": False,
            "amount_area_suspicious": False,
            "ui_matches_claimed_app": None,
        }


# ─────────────────────────────────────────────
# LAYER 7 — FRAUD PATTERN MEMORY
# Perceptual hash via MongoDB
# ─────────────────────────────────────────────
def _perceptual_hash(image_bytes: bytes) -> str:
    """
    Simple perceptual hash using resize + pixel average.
    Same fake template = similar hash within threshold.
    """
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes)).convert("L").resize((16, 16), Image.LANCZOS)
        pixels = list(img.getdata())
        avg = sum(pixels) / len(pixels)
        bits = "".join("1" if p > avg else "0" for p in pixels)
        # Convert to hex
        h = hex(int(bits, 2))[2:].zfill(64)
        return h
    except Exception:
        # Fallback to MD5
        return hashlib.md5(image_bytes[:1024]).hexdigest()


def _hamming_distance(h1: str, h2: str) -> int:
    """Hamming distance between two hex hashes."""
    try:
        b1 = bin(int(h1, 16))[2:].zfill(256)
        b2 = bin(int(h2, 16))[2:].zfill(256)
        return sum(c1 != c2 for c1, c2 in zip(b1, b2))
    except Exception:
        return 256


async def check_fraud_pattern_memory(image_bytes: bytes) -> dict:
    """
    Check if this screenshot matches a known fake template in our DB.
    Returns match info and weight signal.
    """
    result = {"found": False, "match_count": 0, "signal": None}
    try:
        from app.core.database import db
        phash = _perceptual_hash(image_bytes)
        # Fetch recent fake screenshot hashes
        cursor = db.fake_screenshot_hashes.find(
            {"verdict": "SCAM"},
            {"phash": 1, "count": 1, "app": 1}
        ).limit(200)

        async for doc in cursor:
            stored_hash = doc.get("phash", "")
            if not stored_hash:
                continue
            dist = _hamming_distance(phash, stored_hash)
            # Threshold: distance < 20 = very similar image
            if dist < 20:
                result["found"] = True
                result["match_count"] = doc.get("count", 1)
                result["matched_app"] = doc.get("app", "unknown")
                result["signal"] = {
                    "type": "red_flag", "weight": 25,
                    "en": f"This screenshot matches a known fake template seen {result['match_count']} times before",
                    "hi": f"यह screenshot एक known fake template से match करता है जो {result['match_count']} बार पहले देखा गया है"
                }
                break

        # Save this hash for future reference (will be tagged after verdict)
        result["current_phash"] = phash
        return result
    except Exception as e:
        print(f"PATTERN MEMORY ERROR: {e}")
        return {"found": False, "match_count": 0, "signal": None, "current_phash": None}


async def save_to_pattern_memory(phash: str, verdict: str, app_key: str):
    """Save screenshot hash to pattern memory after analysis."""
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
                "phash": phash,
                "verdict": verdict,
                "app": app_key,
                "count": 1,
                "created_at": datetime.utcnow(),
                "last_seen": datetime.utcnow(),
            })
    except Exception as e:
        print(f"SAVE PATTERN ERROR: {e}")


# ─────────────────────────────────────────────
# LAYER 8 — SCORE AGGREGATOR
# Weighted combination of all layers
# ─────────────────────────────────────────────
LAYER_WEIGHTS = {
    "rule_engine": 0.20,       # validation + rule signals
    "consistency": 0.15,       # cross-check signals
    "vision_ai": 0.35,         # visual forensics (highest — eyes don't lie)
    "upi_id": 0.15,            # UPI ID check
    "pattern_memory": 0.05,    # fraud template match
    "app_confidence": 0.10,    # app detection confidence
}


def aggregate_score(
    validation_signals: list,
    rule_signals: list,
    consistency_signals: list,
    upi_signals: list,
    vision_result: dict,
    pattern_result: dict,
    app_confidence: int,
    app_key: str,
) -> dict:
    """
    Combine all signal lists into a final risk score (0–100).
    Higher = more likely fake/scam.
    """

    def signals_to_score(signals: list) -> float:
        """Convert weighted signals to a 0-100 risk score."""
        base = 40  # neutral start (benefit of doubt)
        total = base
        for s in signals:
            if s["type"] in ("red_flag", "warning"):
                total += s["weight"]
            elif s["type"] == "green_flag":
                total += s["weight"]  # weight is negative for green flags
        return max(0, min(100, total))

    # Per-layer scores
    rule_score = signals_to_score(validation_signals + rule_signals)
    consistency_score = signals_to_score(consistency_signals)
    upi_score = signals_to_score(upi_signals)
    vision_score = vision_result.get("visual_risk_score", 50)
    memory_score = 80 if pattern_result.get("found") else 40
    conf_score = max(0, (100 - app_confidence))  # lower confidence = higher risk

    # Weighted average
    final_risk = (
        rule_score * LAYER_WEIGHTS["rule_engine"] +
        consistency_score * LAYER_WEIGHTS["consistency"] +
        vision_score * LAYER_WEIGHTS["vision_ai"] +
        upi_score * LAYER_WEIGHTS["upi_id"] +
        memory_score * LAYER_WEIGHTS["pattern_memory"] +
        conf_score * LAYER_WEIGHTS["app_confidence"]
    )
    final_risk = max(0, min(100, final_risk))

    # Auto-floor: if very few fields extracted → minimum SUSPICIOUS (40)
    # Already handled in rule engine R2 signal

    # Hard overrides
    all_signals = validation_signals + rule_signals + consistency_signals + upi_signals
    critical_flags = [s for s in all_signals if s.get("type") == "red_flag" and s.get("weight", 0) >= 35]
    if len(critical_flags) >= 2:
        # Multiple critical violations → cannot be SAFE
        final_risk = max(final_risk, 66)

    if pattern_result.get("found"):
        final_risk = max(final_risk, 60)

    # Verdict
    risk_int = round(final_risk)
    if risk_int <= 35:
        verdict = "SAFE"
        verdict_hi = "सुरक्षित"
    elif risk_int <= 65:
        verdict = "SUSPICIOUS"
        verdict_hi = "संदिग्ध"
    else:
        verdict = "SCAM"
        verdict_hi = "धोखाधड़ी"

    # Confidence in our own verdict
    all_count = len(all_signals)
    critical_count = len(critical_flags)
    if all_count >= 8 or critical_count >= 2:
        confidence_level = "high"
    elif all_count >= 4:
        confidence_level = "medium"
    else:
        confidence_level = "low"

    # Layer scores for debugging / transparency
    layer_scores = {
        "rule_engine": round(rule_score),
        "consistency": round(consistency_score),
        "vision_ai": round(vision_score),
        "upi_id_check": round(upi_score),
        "pattern_memory": round(memory_score),
        "app_confidence_risk": round(conf_score),
    }

    return {
        "risk_score": risk_int,
        "verdict": verdict,
        "verdict_hi": verdict_hi,
        "confidence_level": confidence_level,
        "layer_scores": layer_scores,
        "critical_flag_count": critical_count,
    }


# ─────────────────────────────────────────────
# WHAT TO DO + HOW TO AVOID — per verdict
# ─────────────────────────────────────────────
def get_advice(verdict: str, app_display: str) -> dict:
    if verdict == "SAFE":
        return {
            "what_to_do": [
                {"en": "Always verify the payment in YOUR own UPI app transaction history — don't rely on this screenshot alone", "hi": "अपने UPI app की transaction history में payment verify करें — सिर्फ इस screenshot पर भरोसा न करें"},
                {"en": f"Open your {app_display} or bank app and confirm the credit shows up", "hi": f"अपना {app_display} या bank app खोलें और confirm करें कि credit आया है"},
                {"en": "Match the UTR/Transaction ID shown here with your bank statement", "hi": "यहाँ दिखाई UTR/Transaction ID को अपने bank statement से match करें"},
            ],
            "how_to_avoid": [
                {"en": "A screenshot is never proof of payment — always check your bank", "hi": "Screenshot कभी payment का proof नहीं है — हमेशा अपना bank check करें"},
                {"en": "Enable bank SMS alerts so you get instant credit notifications", "hi": "Bank SMS alerts enable करें ताकि instant credit notification मिले"},
                {"en": "Never hand over goods or services before confirming payment in your account", "hi": "Account में payment confirm होने से पहले कभी goods/services न दें"},
            ],
        }
    elif verdict == "SUSPICIOUS":
        return {
            "what_to_do": [
                {"en": "DO NOT accept this as payment proof — verify directly in your bank app", "hi": "इसे payment proof न मानें — सीधे अपने bank app में verify करें"},
                {"en": "Ask the sender to show you the payment in THEIR UPI app live (not screenshot)", "hi": "Sender से कहें कि वो LIVE अपने UPI app में payment दिखाए (screenshot नहीं)"},
                {"en": "Check your bank account or UPI app for the exact UTR number shown", "hi": "अपने bank account में exact UTR number check करें"},
                {"en": "If unsure, do not hand over goods until bank credit is confirmed", "hi": "यदि doubt है तो bank credit confirm होने तक goods न दें"},
            ],
            "how_to_avoid": [
                {"en": "Always verify payments in YOUR bank app, not the buyer's screenshot", "hi": "हमेशा अपने bank app में verify करें, buyer के screenshot से नहीं"},
                {"en": "Scammers use fake UPI apps and editing tools to create realistic screenshots", "hi": "Scammers fake UPI apps और editing tools से realistic screenshots बनाते हैं"},
                {"en": "Train your staff: screenshot ≠ payment. Only bank credit = payment", "hi": "अपने staff को train करें: screenshot ≠ payment. सिर्फ bank credit = payment"},
            ],
        }
    else:  # SCAM
        return {
            "what_to_do": [
                {"en": "Do NOT accept this payment — no real money has been transferred", "hi": "यह payment स्वीकार न करें — कोई real money transfer नहीं हुई है"},
                {"en": "Do NOT hand over any goods, cash, or services", "hi": "कोई goods, cash, या services न दें"},
                {"en": "Report this UPI ID to NPCI at npci.org.in and call Cyber Crime helpline 1930", "hi": "इस UPI ID को NPCI पर report करें और Cyber Crime helpline 1930 पर call करें"},
                {"en": "File a complaint at cybercrime.gov.in with this screenshot as evidence", "hi": "cybercrime.gov.in पर complaint दर्ज करें — यह screenshot evidence है"},
                {"en": "Block and report the sender's number immediately", "hi": "Sender का नंबर तुरंत block और report करें"},
            ],
            "how_to_avoid": [
                {"en": "Never trust any payment screenshot — always verify in YOUR app", "hi": "कभी भी payment screenshot पर trust न करें — हमेशा अपने app में verify करें"},
                {"en": "Scammers use apps like 'Fake Pay' to generate realistic receipts in seconds", "hi": "Scammers 'Fake Pay' जैसे apps से seconds में realistic receipts बनाते हैं"},
                {"en": "If someone is rushing you to accept payment — that's a red flag", "hi": "यदि कोई आपको जल्दी payment accept करने के लिए pressure कर रहा है — यह red flag है"},
                {"en": "Place a notice at your shop: 'We verify all UPI payments in our app'", "hi": "अपनी shop पर लगाएं: 'हम सभी UPI payments अपने app में verify करते हैं'"},
            ],
        }


# ─────────────────────────────────────────────
# MASTER FUNCTION — Full Pipeline
# ─────────────────────────────────────────────
async def analyze_payment_screenshot(image_bytes: bytes) -> dict:
    """
    Full 8-layer analysis pipeline for fake UPI payment screenshot detection.
    Input: raw image bytes (JPEG/PNG)
    Output: structured verdict with risk%, signals, advice in EN+HI
    """

    # ── Layer 1: App Detection ──
    app_result = detect_app_from_image(image_bytes)
    app_key = app_result["app_key"]
    app_display = app_result["display_name"]
    app_confidence = app_result["confidence"]

    # ── Layer 2: Field Extraction ──
    fields = extract_fields_from_image(image_bytes, app_key)

    # ── Layer 2B: OCR Validation ──
    validation_signals = validate_extracted_fields(fields, app_key)

    # ── Layer 3: Rule Engine ──
    rule_signals = run_rule_engine(fields, app_key, app_confidence)

    # ── Layer 4: Consistency Check ──
    consistency_signals = run_consistency_check(fields, app_key)

    # ── Layer 5: UPI ID Deep Check ──
    upi_id = fields.get("upi_id") or ""
    upi_signals = run_upi_id_check(upi_id)

    # ── Layer 6: Vision Forensics ──
    # Build rule context summary for AI prompt
    all_rule_signals = validation_signals + rule_signals + consistency_signals + upi_signals
    red_flags_for_ai = [s["en"] for s in all_rule_signals if s.get("type") == "red_flag"]
    rule_context = "\n".join(f"- {r}" for r in red_flags_for_ai) if red_flags_for_ai else "No critical rule violations detected yet"

    vision_result = run_vision_forensics(image_bytes, app_key, app_display, rule_context)

    # ── Layer 7: Pattern Memory ──
    pattern_result = await check_fraud_pattern_memory(image_bytes)

    # ── Layer 8: Score Aggregation ──
    score_result = aggregate_score(
        validation_signals=validation_signals,
        rule_signals=rule_signals,
        consistency_signals=consistency_signals,
        upi_signals=upi_signals,
        vision_result=vision_result,
        pattern_result=pattern_result,
        app_confidence=app_confidence,
        app_key=app_key,
    )

    verdict = score_result["verdict"]
    risk_score = score_result["risk_score"]

    # ── Save to pattern memory ──
    phash = pattern_result.get("current_phash")
    if phash:
        await save_to_pattern_memory(phash, verdict, app_key)

    # ── Build why signals (for frontend) ──
    # Show red flags if SCAM/SUSPICIOUS, green flags if SAFE
    why_signals = []
    seen_en = set()
    all_signals_combined = (
        all_rule_signals
        + vision_result.get("visual_flags", [])
        + (vision_result.get("visual_safe_signals", []) if verdict == "SAFE" else [])
    )
    if pattern_result.get("signal"):
        all_signals_combined.append(pattern_result["signal"])

    for sig in all_signals_combined:
        en_text = sig.get("en", "")
        if not en_text or en_text in seen_en:
            continue
        # For SAFE: show green flags. For SUSPICIOUS/SCAM: show red+warnings
        if verdict == "SAFE" and sig.get("type") == "green_flag":
            why_signals.append({"en": en_text, "hi": sig.get("hi", en_text)})
            seen_en.add(en_text)
        elif verdict in ("SUSPICIOUS", "SCAM") and sig.get("type") in ("red_flag", "warning"):
            why_signals.append({"en": en_text, "hi": sig.get("hi", en_text)})
            seen_en.add(en_text)

    # Limit to top 5
    why_signals = why_signals[:5]

    # ── Visual forensics summary flags ──
    visual_detail = []
    if vision_result.get("logo_authentic") is False:
        visual_detail.append({"en": "Logo appears blurry, stretched, or mismatched", "hi": "Logo blurry, stretched, या mismatched दिख रहा है"})
    if vision_result.get("font_consistent") is False:
        visual_detail.append({"en": "Font inconsistency detected in amount/text area", "hi": "Amount/text area में font inconsistency पाई गई"})
    if vision_result.get("pixel_artifacts_detected"):
        visual_detail.append({"en": "Pixel artifacts detected — possible image editing", "hi": "Pixel artifacts मिले — image editing की संभावना"})
    if vision_result.get("amount_area_suspicious"):
        visual_detail.append({"en": "Amount field looks tampered or overlaid", "hi": "Amount field tampered या overlaid लग रहा है"})
    if vision_result.get("color_scheme_correct") is False:
        visual_detail.append({"en": f"Color scheme doesn't match real {app_display} UI", "hi": f"Color scheme real {app_display} UI से match नहीं करता"})

    # ── Advice ──
    advice = get_advice(verdict, app_display)

    # ── Verdict label with Hindi ──
    verdict_label = {
        "SAFE": {"en": "Likely Genuine Payment", "hi": "संभवतः असली Payment"},
        "SUSPICIOUS": {"en": "Suspicious — Verify Before Accepting", "hi": "संदिग्ध — Accept करने से पहले verify करें"},
        "SCAM": {"en": "Likely Fake Screenshot — Do Not Accept", "hi": "संभवतः नकली Screenshot — Accept न करें"},
    }[verdict]

    return {
        "verdict": verdict,
        "risk_percentage": risk_score,
        "confidence": score_result["confidence_level"],
        "verdict_label": verdict_label,
        "detected_app": {
            "name": app_display,
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
        "why": why_signals,
        "visual_forensics": visual_detail,
        "what_to_do": advice["what_to_do"],
        "how_to_avoid": advice["how_to_avoid"],
        "pattern_match": {
            "found": pattern_result.get("found", False),
            "match_count": pattern_result.get("match_count", 0),
        },
        "layer_scores": score_result["layer_scores"],
        "engine": "PAYMENT SCREENSHOT v1.0 — 8-LAYER",
    }

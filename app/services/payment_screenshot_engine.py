"""
Payment Screenshot Engine — ScamDekho
======================================
12-Layer Fake UPI Payment Screenshot Detector (v2.1 — deduplicated + all bugs fixed)

Layers:
  0. ELA (Error Level Analysis) — detects pixel editing
  0B. EXIF Metadata — real device vs fake generator
  0C. Dimension Check — real phone resolution
  0D. Noise Analysis — natural vs synthetic image
  1. App Detection + Confidence
  2. OCR Field Extraction + Validation
  3. Rule Engine (Weighted Signals)
  4. Consistency Cross-Check
  5. UPI ID Deep Check
  6. Vision AI Forensics (GPT-4o-mini)
  7. Fraud Pattern Memory (perceptual hash)
  8. Bayesian Score Aggregator → SAFE / SUSPICIOUS / SCAM

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
# ─────────────────────────────────────────────
APP_REGISTRY = {
    "phonepe": {
        "display": "PhonePe",
        "color_hint": "purple",
        "utr_pattern": r"^\d{12}$",
        "utr_prefix": None,
        "handles": ["ybl", "ibl", "axl", "oksbi"],
        "status_texts": ["payment successful", "paid", "money sent", "₹ sent to"],
        "logo_keywords": ["phonepe", "phone pe"],
    },
    "gpay": {
        "display": "Google Pay",
        "color_hint": "white",
        "utr_pattern": r"^[A-Z0-9]{20,35}$",
        "utr_prefix": None,
        "handles": ["okaxis", "okicici", "oksbi", "okhdfcbank"],
        "status_texts": ["you paid", "payment done", "sent to"],
        "logo_keywords": ["google pay", "gpay", "g pay"],
    },
    "paytm": {
        "display": "Paytm",
        "color_hint": "blue",
        "utr_pattern": r"^\d{10,20}$",
        "utr_prefix": None,
        "handles": ["paytm", "ptyes", "ptsbi", "ybl", "ibl", "okicici", "oksbi", "okhdfcbank", "okaxis"],
        "status_texts": ["payment successful", "paid successfully", "money transferred"],
        "logo_keywords": ["paytm"],
    },
    "bhim": {
        "display": "BHIM",
        "color_hint": "blue_dark",
        "utr_pattern": r"^\d{12}$",
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
        "utr_pattern": r"^[A-Za-z0-9]{10,30}$",
        "utr_prefix": None,
        "handles": ["navi", "naviaxis"],
        "status_texts": ["payment successful", "transaction successful", "received from"],
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


def run_ela_analysis(image_bytes: bytes) -> list:
    signals = []
    try:
        from PIL import Image, ImageChops
        import numpy as np

        img = Image.open(io.BytesIO(image_bytes))
        img_format = (img.format or "").upper()

        # PNG is lossless — converting to JPEG always introduces artifacts
        # ELA would flag EVERY genuine iOS/Android PNG screenshot as SCAM
        if img_format == "PNG":
            signals.append({
                "type": "green_flag", "weight": -5,
                "en": "ELA skipped — PNG is lossless, no JPEG compression artifacts expected",
                "hi": "ELA skip किया — PNG lossless है, JPEG artifacts expected नहीं"
            })
            return signals

        # JPEG: double-pass recompression highlights edited areas
        original = img.convert("RGB")
        buf1 = io.BytesIO()
        original.save(buf1, format="JPEG", quality=75)
        buf1.seek(0)
        recomp1 = Image.open(buf1).convert("RGB")

        buf2 = io.BytesIO()
        recomp1.save(buf2, format="JPEG", quality=75)
        buf2.seek(0)
        recomp2 = Image.open(buf2).convert("RGB")

        # Compare pass1 vs pass2 — edited areas have higher divergence
        diff = ImageChops.difference(recomp1, recomp2)
        diff_arr = np.array(diff).astype(np.float32)
        max_ela  = diff_arr.max()
        mean_ela = diff_arr.mean()

        h = diff_arr.shape[0]
        mid_region  = diff_arr[int(h * 0.25):int(h * 0.75)]
        region_max  = mid_region.max()

        # Calibrated thresholds for double-pass JPEG ELA
        if max_ela > 25 and mean_ela > 3.0:
            signals.append({
                "type": "red_flag", "weight": 40,
                "en": f"ELA detected editing artifacts (max={max_ela:.1f}, mean={mean_ela:.2f}) — image likely tampered",
                "hi": f"ELA में image editing के artifacts मिले — image tampered हो सकती है"
            })
            if region_max > max_ela * 0.85 and region_max > 18:
                signals.append({
                    "type": "red_flag", "weight": 30,
                    "en": "ELA hotspot in amount/transaction area — this region was likely edited",
                    "hi": "Amount/transaction area में ELA hotspot — यह region edit किया गया लगता है"
                })
        elif max_ela > 12 and mean_ela > 1.5:
            signals.append({
                "type": "warning", "weight": 18,
                "en": f"Mild ELA anomalies (max={max_ela:.1f}) — minor editing possible",
                "hi": "Mild ELA anomalies — minor editing की संभावना"
            })
        else:
            signals.append({
                "type": "green_flag", "weight": -15,
                "en": "ELA clean — no editing artifacts detected",
                "hi": "ELA clean — कोई editing artifacts नहीं"
            })
        return signals
    except Exception as e:
        print(f"ELA ERROR: {e}")
        return []


# ─────────────────────────────────────────────
# LAYER 0B — EXIF Metadata Analysis
# Real phone screenshots have EXIF; fake generators don't
# ─────────────────────────────────────────────


def run_exif_analysis(image_bytes: bytes) -> list:
    signals = []
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
        img = Image.open(io.BytesIO(image_bytes))
        exif_raw = None
        try:
            exif_raw = img._getexif()
        except Exception:
            pass
        img_format = img.format or "UNKNOWN"
        if not exif_raw:
            if img_format == "JPEG":
                signals.append({
                    "type": "warning", "weight": 18,
                    "en": "JPEG with no EXIF metadata — real phone screenshots usually have it",
                    "hi": "JPEG screenshot में EXIF metadata नहीं — real screenshots में होता है"
                })
            return signals
        exif = {TAGS.get(k, k): v for k, v in exif_raw.items()}
        software = str(exif.get("Software", "")).lower()
        suspicious_sw = [
            "canva", "photoshop", "gimp", "paint.net", "snapseed",
            "picsart", "fake", "generator", "html2canvas", "puppeteer",
            "wkhtmlto", "android fake", "screenshot_tool"
        ]
        for sw in suspicious_sw:
            if sw in software:
                signals.append({
                    "type": "red_flag", "weight": 50,
                    "en": f"EXIF reveals editing tool: '{exif.get('Software', software)}'",
                    "hi": f"EXIF में editing software fingerprint मिला"
                })
                return signals
        make = str(exif.get("Make", "")).strip()
        model = str(exif.get("Model", "")).strip()
        if make or model:
            signals.append({
                "type": "green_flag", "weight": -18,
                "en": f"EXIF shows real device: {make} {model}".strip(),
                "hi": f"EXIF में real device: {make} {model}".strip()
            })
        if exif.get("DateTime"):
            signals.append({
                "type": "green_flag", "weight": -8,
                "en": "EXIF capture timestamp present",
                "hi": "EXIF capture timestamp मौजूद है"
            })
        return signals
    except Exception as e:
        print(f"EXIF ERROR: {e}")
        return []


# ─────────────────────────────────────────────
# LAYER 0C — IMAGE DIMENSION CHECK
# Real phone screenshots have standard resolutions
# ─────────────────────────────────────────────


def run_dimension_check(image_bytes: bytes) -> list:
    signals = []
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes))
        w, h = img.size
        ratio = h / w if w > 0 else 0
        if w > h:
            signals.append({
                "type": "red_flag", "weight": 25,
                "en": "Landscape screenshot — UPI payment screens are always portrait",
                "hi": "Landscape screenshot — UPI screens हमेशा portrait होते हैं"
            })
            return signals
        REAL_RESOLUTIONS = {
            (1080,2400),(1080,2340),(1080,2280),(1080,2160),
            (1080,1920),(720,1600),(720,1280),(1440,3200),
            (828,1792),(1170,2532),(1179,2556),(1080,2408),(1080,2376),
            (1284,2778),(1125,2436),(750,1334),(640,1136),
        }
        if not (1.55 < ratio < 2.55):
            signals.append({
                "type": "warning", "weight": 15,
                "en": f"Unusual aspect ratio {w}x{h} — not a typical phone resolution",
                "hi": f"Unusual aspect ratio {w}x{h} — phone screenshot के लिए typical नहीं"
            })
        elif w < 350:
            signals.append({
                "type": "warning", "weight": 12,
                "en": f"Very small image {w}x{h} — may be a cropped or resized fake",
                "hi": f"बहुत छोटी image {w}x{h} — cropped/resized हो सकती है"
            })
        elif (w,h) in REAL_RESOLUTIONS or (h,w) in REAL_RESOLUTIONS:
            signals.append({
                "type": "green_flag", "weight": -10,
                "en": f"Resolution {w}x{h} matches a known real phone screen",
                "hi": f"Resolution {w}x{h} known phone screen से match करता है"
            })
        return signals
    except Exception as e:
        print(f"DIMENSION ERROR: {e}")
        return []


# ─────────────────────────────────────────────
# LAYER 0D — NOISE ANALYSIS
# Real phone screenshots have micro-noise; fake HTML generators don't
# ─────────────────────────────────────────────


def run_noise_analysis(image_bytes: bytes) -> list:
    """
    Real phone screenshots have micro-noise. Fake generators produce clean images.
    Fixed: PNG has lower native noise; WhatsApp JPEG recompression destroys noise.
    """
    signals = []
    try:
        import numpy as np
        from PIL import Image

        img = Image.open(io.BytesIO(image_bytes))
        img_format = (img.format or "").upper()
        arr = np.array(img.convert("L"), dtype=np.float32)
        h, w = arr.shape

        variances = []
        step = max(1, min(h, w) // 20)
        for y in range(0, h - 5, step):
            for x in range(0, w - 5, step):
                block = arr[y:y+5, x:x+5]
                variances.append(float(block.var()))

        if not variances:
            return signals

        avg_var = sum(variances) / len(variances)

        # PNG is lossless — naturally lower noise than JPEG
        # JPEG via WhatsApp recompressed to ~70% — legitimately reduces noise
        if img_format == "PNG":
            red_threshold  = 0.3
            warn_threshold = 1.5
        else:
            red_threshold  = 0.5    # was 0.8 — too aggressive for WhatsApp screenshots
            warn_threshold = 2.0

        if avg_var < red_threshold:
            signals.append({
                "type": "red_flag", "weight": 22,
                "en": f"Unnaturally clean image (noise={avg_var:.2f}) — may be generated by fake payment app",
                "hi": f"Image unnaturally clean — fake payment app से generate हो सकता है"
            })
        elif avg_var < warn_threshold:
            signals.append({
                "type": "warning", "weight": 8,
                "en": f"Low image noise ({avg_var:.2f}) — may be WhatsApp-compressed or generated",
                "hi": f"Low noise — WhatsApp compressed या generated हो सकती है"
            })
        else:
            signals.append({
                "type": "green_flag", "weight": -10,
                "en": "Natural image noise — consistent with a real phone screenshot",
                "hi": "Natural noise — real phone screenshot जैसा"
            })
        return signals
    except Exception as e:
        print(f"NOISE ERROR: {e}")
        return []

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
    # Allow masked UPI IDs like navi.******2623@naviaxis (real app receipt format)
    upi_id = (fields.get("upi_id") or "").strip().lower()
    if upi_id:
        upi_for_check = upi_id.replace("*", "a")  # replace asterisks before regex
        if not re.match(r'^[\w.\-]+@[\w.\-]+$', upi_for_check):
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
                    # Cross-app UPI is allowed in India — only flag if app is completely different
                    # e.g. Paytm can pay to @ybl (PhonePe handle) — that's normal
                    cross_app_ok = {
                        ("paytm", "phonepe"), ("paytm", "gpay"), ("paytm", "bhim"),
                        ("gpay", "phonepe"), ("gpay", "paytm"),
                        ("phonepe", "gpay"), ("phonepe", "paytm"),
                        ("bhim", "phonepe"), ("bhim", "gpay"), ("bhim", "paytm"),
                    }
                    if (app_key, other_key) not in cross_app_ok:
                        signals.append({
                            "type": "red_flag", "weight": 40,
                            "en": f"MISMATCH: Screenshot claims {app_info.get('display', app_key)} but UPI handle @{handle} belongs to {other_info['display']}",
                            "hi": f"मिसमैच: Screenshot {app_info.get('display', app_key)} दिखा रहा है लेकिन @{handle} handle {other_info['display']} का है"
                        })
                    else:
                        signals.append({
                            "type": "green_flag", "weight": -5,
                            "en": f"Cross-app UPI payment: {app_info.get('display', app_key)} paying to @{handle} ({other_info['display']} handle) — normal in India",
                            "hi": f"Cross-app UPI payment सामान्य है — {app_info.get('display', app_key)} से {other_info['display']} handle पर payment"
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
    # NOTE: phone-number UPI IDs (9876543210@paytm, q033328366@ybl) are VALID — do not flag
    generic_patterns = [
        r'^test\d*$',               # test account
        r'^demo\d*$',               # demo account
        r'^fake\d*$',               # literally fake
        r'^sample\d*$',             # sample account
        r'^dummy\d*$',              # dummy account
        r'^null\d*$',               # null/placeholder
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

Remember: If unsure → mark suspicious, not genuine.
IMPORTANT REAL-WORLD NOTES:
- In India, Paytm/GPay/BHIM apps CAN pay to @ybl handles (PhonePe). This is normal cross-app UPI — NOT a fake signal.
- Masked UPI IDs like "navi.******2623@naviaxis" are shown by real apps for privacy — NOT fake.
- PhonePe "Transaction Successful" screens shown inside Navi/Paytm = real, the receiving app shows the credit.
- Do NOT flag screenshots just because the UI color looks slightly different from the detected app."""

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
    """Hamming distance between two hex hashes.
    Fixed: auto-detect bit length so MD5 (128-bit) and pHash (256-bit) both work.
    """
    try:
        bit_len = max(len(h1), len(h2)) * 4  # hex chars * 4 bits each
        b1 = bin(int(h1, 16))[2:].zfill(bit_len)
        b2 = bin(int(h2, 16))[2:].zfill(bit_len)
        return sum(c1 != c2 for c1, c2 in zip(b1, b2))
    except Exception:
        return 256



# ─────────────────────────────────────────────
# LAYER 0 — ELA (Error Level Analysis)
# Fixed: PNG lossless→JPEG always fires — skip ELA for PNG
# For JPEG: double-pass recompression to amplify real edits
# ─────────────────────────────────────────────


async def check_fraud_pattern_memory(image_bytes: bytes) -> dict:
    """
    Check if this screenshot matches a known fake template in our DB.
    Returns match info and weight signal.
    """
    result = {"found": False, "match_count": 0, "signal": None}
    try:
        from app.core.database import db
        import asyncio as _asyncio2
        _loop2 = _asyncio2.get_event_loop()
        phash = await _loop2.run_in_executor(None, _perceptual_hash, image_bytes)
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


def signals_to_bayesian_score(signals: list) -> float:
    """
    Bayesian scoring: start at 40% prior (benefit of doubt),
    update multiplicatively with each signal.
    Much more accurate than additive scoring.
    """
    p_fake = 0.40  # Prior: benefit of doubt
    for s in signals:
        w = s.get("weight", 0)
        stype = s.get("type", "")
        if stype == "red_flag":
            lr = 1 + (w / 100) * 3.5
            p_fake = (p_fake * lr) / (p_fake * lr + (1 - p_fake))
        elif stype == "warning":
            lr = 1 + (w / 100) * 1.8
            p_fake = (p_fake * lr) / (p_fake * lr + (1 - p_fake))
        elif stype == "green_flag":
            lr = max(0.05, 1 - (abs(w) / 100) * 2.5)
            p_fake = (p_fake * lr) / (p_fake * lr + (1 - p_fake))
    return max(0.0, min(1.0, p_fake)) * 100


def aggregate_score(
    validation_signals: list,
    rule_signals: list,
    consistency_signals: list,
    upi_signals: list,
    vision_result: dict,
    pattern_result: dict,
    app_confidence: int,
    app_key: str,
    ela_signals: list = None,
    exif_signals: list = None,
    dimension_signals: list = None,
    noise_signals: list = None,
) -> dict:
    """
    Bayesian score aggregation across all layers.
    Higher score = more likely fake.
    """
    ela_signals = ela_signals or []
    exif_signals = exif_signals or []
    dimension_signals = dimension_signals or []
    noise_signals = noise_signals or []

    all_rule = (
        ela_signals + exif_signals + dimension_signals + noise_signals +
        validation_signals + rule_signals + consistency_signals + upi_signals
    )

    # Per-layer Bayesian scores
    forensic_score = signals_to_bayesian_score(ela_signals + exif_signals + dimension_signals + noise_signals)
    rule_score     = signals_to_bayesian_score(validation_signals + rule_signals)
    consist_score  = signals_to_bayesian_score(consistency_signals)
    upi_score      = signals_to_bayesian_score(upi_signals)
    vision_score   = vision_result.get("visual_risk_score", 50)
    memory_score   = 80 if pattern_result.get("found") else 35
    conf_risk      = max(0, 100 - app_confidence)

    # Weighted combination (forensics now 15%, vision still highest)
    final_risk = (
        forensic_score * 0.15 +
        rule_score     * 0.18 +
        consist_score  * 0.12 +
        vision_score   * 0.30 +
        upi_score      * 0.12 +
        memory_score   * 0.05 +
        conf_risk      * 0.08
    )
    final_risk = max(0.0, min(100.0, final_risk))

    # Hard overrides
    all_signals = all_rule
    critical_flags = [s for s in all_signals if s.get("type") == "red_flag" and s.get("weight", 0) >= 35]

    # ELA + EXIF both red = definite tampering
    ela_red = any(s.get("type") == "red_flag" for s in ela_signals)
    exif_red = any(s.get("type") == "red_flag" for s in exif_signals)
    if ela_red and exif_red:
        final_risk = max(final_risk, 75)

    if len(critical_flags) >= 2:
        final_risk = max(final_risk, 66)

    if pattern_result.get("found"):
        final_risk = max(final_risk, 62)

    # Strong forensic green signals prevent false SCAM
    ela_green = any(s.get("type") == "green_flag" for s in ela_signals)
    exif_green = any(s.get("type") == "green_flag" for s in exif_signals)
    noise_green = any(s.get("type") == "green_flag" for s in noise_signals)
    green_count = sum([ela_green, exif_green, noise_green])
    if green_count >= 2 and final_risk > 65:
        # Multiple forensic greens → cap at SUSPICIOUS unless other strong reds
        if len(critical_flags) < 2:
            final_risk = min(final_risk, 64)

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

    all_count = len(all_signals)
    critical_count = len(critical_flags)
    if all_count >= 10 or critical_count >= 2:
        confidence_level = "high"
    elif all_count >= 5:
        confidence_level = "medium"
    else:
        confidence_level = "low"

    layer_scores = {
        "forensics_ela_exif": round(forensic_score),
        "rule_engine": round(rule_score),
        "consistency": round(consist_score),
        "vision_ai": round(vision_score),
        "upi_id_check": round(upi_score),
        "pattern_memory": round(memory_score),
        "app_confidence_risk": round(conf_risk),
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

    import asyncio as _asyncio
    _loop = _asyncio.get_event_loop()

    # ── Layer 0: Forensic Image Analysis (sync, CPU-bound → executor) ──
    ela_signals       = await _loop.run_in_executor(None, run_ela_analysis, image_bytes)
    exif_signals      = await _loop.run_in_executor(None, run_exif_analysis, image_bytes)
    dimension_signals = await _loop.run_in_executor(None, run_dimension_check, image_bytes)
    noise_signals     = await _loop.run_in_executor(None, run_noise_analysis, image_bytes)

    # ── Layer 1: App Detection (Vision AI — sync SDK call → executor) ──
    app_result     = await _loop.run_in_executor(None, detect_app_from_image, image_bytes)
    app_key        = app_result["app_key"]
    app_display    = app_result["display_name"]
    app_confidence = app_result["confidence"]

    # ── Layer 2: Field Extraction (Vision AI → executor) ──
    fields = await _loop.run_in_executor(None, extract_fields_from_image, image_bytes, app_key)

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
    all_rule_signals = validation_signals + rule_signals + consistency_signals + upi_signals
    forensic_reds = [s["en"] for s in (ela_signals+exif_signals+dimension_signals+noise_signals) if s.get("type")=="red_flag"]
    rule_reds     = [s["en"] for s in all_rule_signals if s.get("type") == "red_flag"]
    rule_context  = "\n".join(f"- {r}" for r in (forensic_reds + rule_reds)) or "No critical rule violations detected yet"

    vision_result = await _loop.run_in_executor(None, run_vision_forensics, image_bytes, app_key, app_display, rule_context)

    # ── Layer 7: Pattern Memory ──
    pattern_result = await check_fraud_pattern_memory(image_bytes)

    # ── Layer 8: Bayesian Score Aggregation ──
    score_result = aggregate_score(
        validation_signals=validation_signals,
        rule_signals=rule_signals,
        consistency_signals=consistency_signals,
        upi_signals=upi_signals,
        vision_result=vision_result,
        pattern_result=pattern_result,
        app_confidence=app_confidence,
        app_key=app_key,
        ela_signals=ela_signals,
        exif_signals=exif_signals,
        dimension_signals=dimension_signals,
        noise_signals=noise_signals,
    )

    verdict = score_result["verdict"]
    risk_score = score_result["risk_score"]

    # ── Save to pattern memory ──
    phash = pattern_result.get("current_phash")
    if phash:
        await save_to_pattern_memory(phash, verdict, app_key)

    # ── Build why signals (for frontend) ──
    # Include ALL layers: forensics + rules + vision + pattern
    why_signals = []
    seen_en = set()
    forensic_signals = ela_signals + exif_signals + dimension_signals + noise_signals
    all_signals_combined = (
        forensic_signals                                                          # Layer 0 forensics
        + all_rule_signals                                                        # Layers 2-5 rules
        + vision_result.get("visual_flags", [])                                  # Layer 6 vision
        + (vision_result.get("visual_safe_signals", []) if verdict == "SAFE" else [])
    )
    if pattern_result.get("signal"):
        all_signals_combined.append(pattern_result["signal"])                    # Layer 7 memory

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
        "engine": "PAYMENT SCREENSHOT v2.1 — FULL FORENSICS + BAYESIAN",
    }

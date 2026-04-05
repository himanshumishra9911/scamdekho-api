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
    """Lazy OpenAI client init — avoids crash at import time."""
    return OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


# ─────────────────────────────────────────────
# APP REGISTRY
# ─────────────────────────────────────────────
APP_REGISTRY = {
    "phonepe": {
        "display": "PhonePe",
        "color_hint": "purple",
        # PhonePe TxnID = alphanumeric (T26040518...) OR 12-digit UTR
        "utr_pattern": r"^[A-Za-z0-9]{10,30}$",
        "utr_prefix": None,
        "handles": ["ybl", "ibl", "axl", "oksbi", "okhdfcbank", "okicici", "okaxis"],
        "status_texts": ["payment successful", "paid", "money sent", "transaction successful"],
        "logo_keywords": ["phonepe", "phone pe"],
    },
    "gpay": {
        "display": "Google Pay",
        "color_hint": "any",  # GPay supports dark AND light theme — don't use color
        # GPay shows TWO IDs: UPI transaction ID (12-digit) + Google transaction ID (short alphanumeric)
        "utr_pattern": r"^[A-Za-z0-9]{6,35}$",
        "utr_prefix": None,
        "handles": ["okaxis", "okicici", "oksbi", "okhdfcbank", "okhdfc", "upi"],
        "status_texts": ["completed", "you paid", "payment done", "sent to", "payment successful", "paid"],
        "logo_keywords": ["google pay", "gpay", "g pay"],
    },
    "paytm": {
        "display": "Paytm",
        "color_hint": "blue",
        "utr_pattern": r"^[A-Za-z0-9]{6,50}$",
        "utr_prefix": None,
        "handles": ["paytm", "ptyes", "ptsbi", "ybl", "ibl", "okicici", "oksbi", "okhdfcbank", "okaxis"],
        "status_texts": ["payment successful", "paid successfully", "money transferred", "paid"],
        "logo_keywords": ["paytm"],
    },
    "bhim": {
        "display": "BHIM",
        "color_hint": "blue_dark",
        # BHIM uses standard 12-digit UTR
        "utr_pattern": r"^[A-Za-z0-9]{6,50}$",
        "utr_prefix": None,
        # BHIM is an interface — recipient can have ANY bank handle
        "handles": ["upi", "bhim", "ybl", "okaxis", "okicici", "oksbi", "okhdfcbank"],
        "status_texts": ["transaction successful", "payment done", "paid", "payment successful"],
        "logo_keywords": ["bhim", "bharat interface", "bharat pay"],
    },
    "amazon_pay": {
        "display": "Amazon Pay",
        "color_hint": "orange",
        "utr_pattern": r"^[A-Za-z0-9]{10,30}$",
        "utr_prefix": None,
        "handles": ["apl", "yapl", "amazon", "amazonpay"],
        "status_texts": ["payment successful", "paid", "payment done", "sent successfully"],
        "logo_keywords": ["amazon pay", "amazonpay", "amazon"],
    },
    "airtel": {
        "display": "Airtel Money",
        "color_hint": "red",
        "utr_pattern": r"^[A-Za-z0-9]{6,50}$",
        "utr_prefix": None,
        "handles": ["airtel", "airtelpaymentsbank", "airtelbank"],
        "status_texts": ["transfer successful", "payment done", "payment successful", "paid"],
        "logo_keywords": ["airtel"],
    },
    "cred": {
        "display": "CRED",
        "color_hint": "any",  # CRED supports dark AND light theme
        # CRED often doesn't show explicit UTR — shows transaction flow steps instead
        "utr_pattern": r"^[A-Za-z0-9]{6,50}$",
        "utr_prefix": None,
        "handles": ["cred", "credpay", "ybl", "okaxis", "okicici", "oksbi", "okhdfcbank"],
        "status_texts": ["successful", "paid via cred", "payment done", "paid", "payment successful"],
        "logo_keywords": ["cred", "paid via cred"],
    },
    "whatsapp_pay": {
        "display": "WhatsApp Pay",
        "color_hint": "green",
        "utr_pattern": r"^[A-Za-z0-9]{6,50}$",
        "utr_prefix": None,
        "handles": ["okaxis", "okicici", "oksbi", "okhdfcbank", "ybl"],
        "status_texts": ["payment sent", "sent", "paid", "payment successful", "money sent"],
        "logo_keywords": ["whatsapp", "whatsapp pay"],
    },
    "navi": {
        "display": "Navi",
        "color_hint": "any",  # Navi has green header like PhonePe
        # Navi shows TWO IDs: UPI txn ID (12-digit) + Navi txn ID (PTM-prefixed long hex)
        "utr_pattern": r"^[A-Za-z0-9]{6,50}$",
        "utr_prefix": None,
        "handles": ["navi", "naviaxis", "axisbank", "ptyes", "paytm", "ybl", "okaxis", "okicici", "oksbi"],
        "status_texts": ["payment received", "payment successful", "transaction successful", "received from", "paid"],
        "logo_keywords": ["navi"],
    },
    "mobikwik": {
        "display": "MobiKwik",
        "color_hint": "blue",
        "utr_pattern": r"^[A-Za-z0-9]{6,50}$",
        "utr_prefix": None,
        "handles": ["mbk", "ikwik", "mobikwik", "wal"],
        "status_texts": ["payment successful", "transfer done", "paid", "sent"],
        "logo_keywords": ["mobikwik"],
    },
    "freecharge": {
        "display": "FreeCharge",
        "color_hint": "green",
        "utr_pattern": r"^[A-Za-z0-9]{6,50}$",
        "utr_prefix": None,
        "handles": ["freecharge", "fc", "okaxis"],
        "status_texts": ["payment successful", "paid", "sent"],
        "logo_keywords": ["freecharge"],
    },
    "slice": {
        "display": "Slice",
        "color_hint": "purple_light",
        "utr_pattern": r"^[A-Za-z0-9]{6,50}$",
        "utr_prefix": None,
        "handles": ["slice", "slicepay", "ybl"],
        "status_texts": ["payment done", "sent", "paid", "payment successful"],
        "logo_keywords": ["slice"],
    },
    "yono_sbi": {
        "display": "SBI YONO",
        "color_hint": "blue",
        "utr_pattern": r"^[A-Za-z0-9]{6,50}$",
        "utr_prefix": None,
        "handles": ["sbi", "sbipay", "oksbi", "sbibank"],
        "status_texts": ["transaction successful", "amount debited", "paid", "payment successful"],
        "logo_keywords": ["yono", "sbi yono", "state bank"],
    },
    "imobile": {
        "display": "iMobile (ICICI)",
        "color_hint": "orange_dark",
        "utr_pattern": r"^[A-Za-z0-9]{6,50}$",
        "utr_prefix": None,
        "handles": ["icici", "icicipay", "okicici", "icicibank"],
        "status_texts": ["transaction successful", "payment done", "paid", "payment successful"],
        "logo_keywords": ["imobile", "icici"],
    },
    "hdfc_payzapp": {
        "display": "HDFC PayZapp",
        "color_hint": "red",
        "utr_pattern": r"^[A-Za-z0-9]{6,50}$",
        "utr_prefix": None,
        "handles": ["hdfc", "hdfcbank", "okhdfcbank", "okhdfc"],
        "status_texts": ["payment successful", "transaction complete", "paid", "sent"],
        "logo_keywords": ["payzapp", "hdfc payzapp", "hdfc"],
    },
    "axis_pay": {
        "display": "Axis Pay",
        "color_hint": "maroon",
        "utr_pattern": r"^[A-Za-z0-9]{6,50}$",
        "utr_prefix": None,
        "handles": ["axisbank", "axis", "axisgo", "okaxis"],
        "status_texts": ["payment done", "transfer successful", "paid", "payment successful"],
        "logo_keywords": ["axis pay", "axispay", "axis"],
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
                    "type": "warning", "weight": 8,   # was 18 — WhatsApp strips EXIF from ALL forwarded images
                    "en": "No EXIF metadata — common when screenshot is WhatsApp-forwarded (not conclusive)",
                    "hi": "EXIF नहीं — WhatsApp forwarded screenshots में common है"
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
        elif w < 280:
            signals.append({
                "type": "warning", "weight": 6,   # reduced — WhatsApp often compresses to ~332px wide
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

APP IDENTIFICATION GUIDE:
- PhonePe: green header bar "Transaction Successful / Payment received", "Contact PhonePe Support" button at bottom, purple accent
- Google Pay: "G Pay" colorful logo at BOTTOM, shows "To NAME ₹AMOUNT", "Completed" status, Bank of Baroda/ICICI/SBI logo in card, dark OR light background
- Paytm: "Paid Successfully" / "Payment received" with Paytm logo, blue-white theme, "Paytm UPI" mentioned in notes
- BHIM: "BHIM" government logo, dark blue theme
- Amazon Pay: Amazon logo, orange accents, "Amazon Pay" branding
- Airtel Money: red Airtel logo
- CRED: "Paid via CRED" text visible, white card on dark background, "SUCCESSFUL" badge in green, shows payment flow steps (authenticated by NPCI, amount credited), dark OR light background
- WhatsApp Pay: WhatsApp green theme, chat-style layout
- Navi: green header "Payment received", "Navi transaction ID" label visible, white card layout, shows "PTM..." or alphanumeric Navi ID
- SBI YONO: SBI logo, "YONO" text
- iMobile: ICICI orange, "iMobile" branding
- HDFC PayZapp: HDFC red logo

CRITICAL RULES:
- Identify the SENDER app, NOT the recipient bank
- Background color alone CANNOT identify app — GPay and CRED both support dark AND light themes
- "Powered by UPI" at bottom = ignore, look at app branding
- ANY app can pay to ANY UPI handle — cross-app is normal in India
- If "Paid via CRED" is visible → it's CRED regardless of background
- If "G Pay" logo at bottom → it's Google Pay regardless of background color
- If "Navi transaction ID" label visible → it's Navi app

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
  "transaction_id": "EITHER the Transaction ID (e.g. T260405180450845739875​9) OR UTR number (e.g. 179142498181) — extract BOTH if visible, prefer Transaction ID",
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

    # --- Bill Payment Detection ---
    BILL_PAYMENT_KEYWORDS = [
        "vidyut", "bijli", "electricity", "bsnl", "gas", "water",
        "jal", "metro", "irctc", "railway", "insurance", "fasttag",
        "kshetra", "mpmk", "bescom", "msedcl", "discom", "bses",
        "tata power", "torrent", "wesco", "cesc", "electric", "utility",
        "telecom", "broadband", "municipality", "nagar",
    ]
    recipient = (fields.get("recipient_name") or "").lower()
    is_bill_payment = any(k in recipient for k in BILL_PAYMENT_KEYWORDS)
    # CRED and some other apps don't show UTR explicitly — treat same as bill payment
    is_cred_style = app_key in ("cred", "slice", "freecharge")

    # --- Transaction ID validation ---
    txn_id = (fields.get("transaction_id") or "").strip().replace(" ", "")
    if not txn_id:
        if is_bill_payment or is_cred_style:
            signals.append({
                "type": "warning", "weight": 6,
                "en": "Transaction reference not visible — acceptable for this payment type",
                "hi": "इस payment type में transaction reference न दिखना normal है"
            })
        else:
            signals.append({
                "type": "red_flag", "weight": 25,
                "en": "Transaction ID / UTR not found in screenshot",
                "hi": "स्क्रीनशॉट में Transaction ID / UTR नहीं मिला"
            })
    else:
        utr_pattern = app_info.get("utr_pattern")
        if utr_pattern and not re.match(utr_pattern, txn_id):
            signals.append({
                "type": "warning", "weight": 10,  # reduced from 30 — UTR format varies widely
                "en": f"UTR format slightly unusual for {app_info.get('display', app_key)} (got: {txn_id[:20]})",
                "hi": f"UTR format slightly unusual है — लेकिन real transactions में vary होता है"
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
        if is_bill_payment:
            signals.append({
                "type": "green_flag", "weight": -5,
                "en": "Utility/bill payment — merchant UPI ID not shown is normal",
                "hi": "Bill payment में UPI ID न दिखना सामान्य है"
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
    # CRED, GPay, Amazon Pay, WhatsApp Pay, Navi don't show bank name by design
    APPS_WITHOUT_BANK = {"cred", "gpay", "amazon_pay", "whatsapp_pay", "navi", "slice", "freecharge"}
    if not fields.get("bank_name"):
        if app_key not in APPS_WITHOUT_BANK:
            signals.append({
                "type": "warning", "weight": 8,   # reduced from 15
                "en": "Bank name not visible — genuine receipts usually show bank",
                "hi": "Bank का नाम नहीं दिख रहा — असली receipt में bank दिखता है"
            })

    return signals


# ─────────────────────────────────────────────
# LAYER 3 — RULE ENGINE (Weighted Signals)
# ─────────────────────────────────────────────


def run_rule_engine(fields: dict, app_key: str, app_confidence: int) -> list:
    """Apply all heuristic rules. Returns list of signal dicts with weights."""
    signals = []
    app_info = APP_REGISTRY.get(app_key, {})

    # Rule R1: App detection confidence — two-tier threshold
    if app_confidence < 40:
        signals.append({
            "type": "red_flag", "weight": 20,
            "en": f"Payment app not identifiable (confidence: {app_confidence}%) — very suspicious",
            "hi": f"Payment app identify नहीं हुआ ({app_confidence}%) — बहुत suspicious"
        })
    elif app_confidence < 60:
        signals.append({
            "type": "warning", "weight": 8,
            "en": f"Payment app identified with low confidence ({app_confidence}%) — image may be WhatsApp-compressed",
            "hi": f"Low confidence ({app_confidence}%) — image compressed हो सकती है"
        })
    elif app_key == "unknown":
        signals.append({
            "type": "red_flag", "weight": 25,
            "en": "Unknown payment app — not from any recognized UPI platform",
            "hi": "Unknown payment app — किसी recognized UPI platform का नहीं"
        })

    # Rule R2: Not enough verifiable fields
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
                "type": "warning", "weight": 5,  # reduced — status text varies widely in real apps
                "en": f"Status text '{status[:40]}' slightly unusual for {app_info.get('display', app_key)}",
                "hi": f"Status text slightly unusual है — लेकिन real apps में vary होता है"
            })
        else:
            signals.append({
                "type": "green_flag", "weight": -8,
                "en": "Payment status text matches expected format",
                "hi": "Payment status text सही format में है"
            })

    return signals


def run_consistency_check(fields: dict, app_key: str) -> list:
    """Cross-check fields against each other and the detected app."""
    signals = []
    app_info = APP_REGISTRY.get(app_key, {})

    # C1: UPI handle vs detected app — cross-app UPI is NORMAL in India
    upi_id = (fields.get("upi_id") or "").strip().lower()
    if upi_id and "@" in upi_id:
        handle = upi_id.split("@")[1]
        expected_handles = app_info.get("handles", [])
        if expected_handles and handle not in expected_handles:
            for other_key, other_info in APP_REGISTRY.items():
                if other_key != app_key and handle in other_info.get("handles", []):
                    # Cross-app pairs that are normal in India
                    # In India, ANY UPI app can pay to ANY handle — cross-app is the norm
                    # Only flag truly impossible combinations (e.g. Navi → Paytm-specific handle)
                    # Most cross-app payments are completely normal
                    signals.append({
                        "type": "green_flag", "weight": -5,
                        "en": f"Cross-app payment: {app_info.get('display', app_key)} → @{handle} ({other_info['display']} handle) — normal in India",
                        "hi": f"Cross-app UPI payment सामान्य है"
                    })
                    break
            else:
                signals.append({
                    "type": "warning", "weight": 12,
                    "en": f"UPI handle @{handle} not in expected handles for {app_info.get('display', app_key)}",
                    "hi": f"@{handle} handle expected नहीं है"
                })
        elif expected_handles and handle in expected_handles:
            signals.append({
                "type": "green_flag", "weight": -12,
                "en": f"UPI handle @{handle} matches {app_info.get('display', app_key)}",
                "hi": f"UPI handle @{handle} सही है"
            })

    # C2: UTR format vs app
    txn_id = (fields.get("transaction_id") or "").strip().replace(" ", "")
    if txn_id and app_key != "unknown":
        utr_pattern = app_info.get("utr_pattern")
        if utr_pattern and not re.match(utr_pattern, txn_id):
            for other_key, other_info in APP_REGISTRY.items():
                if other_key != app_key:
                    other_pat = other_info.get("utr_pattern")
                    if other_pat and re.match(other_pat, txn_id):
                        signals.append({
                            "type": "warning", "weight": 12,
                            "en": f"UTR format slightly unusual for {app_info.get('display', app_key)} — verify before accepting",
                            "hi": f"UTR format slightly unusual है — verify करें"
                        })
                        break

    # C3: Amount consistency
    amount_num = fields.get("amount_numeric")
    raw_text = (fields.get("raw_text_visible") or "").lower()
    if amount_num and raw_text:
        other_amounts = re.findall(r'₹\s*(\d[\d,]*(?:\.\d{1,2})?)', raw_text)
        for oa in other_amounts:
            oa_clean = float(oa.replace(",", ""))
            if oa_clean != amount_num and (oa_clean < amount_num * 0.5 or oa_clean > amount_num * 2):
                signals.append({
                    "type": "warning", "weight": 15,
                    "en": f"Amount inconsistency: ₹{amount_num} vs ₹{oa} in text",
                    "hi": f"Amount inconsistency: ₹{amount_num} vs ₹{oa}"
                })
                break

    return signals


# ─────────────────────────────────────────────
# LAYER 5 — UPI ID DEEP CHECK
# ─────────────────────────────────────────────
def run_upi_id_check(upi_id: str) -> list:
    """Check UPI ID for scam patterns."""
    signals = []
    if not upi_id:
        return signals

    upi_lower = upi_id.lower().strip()
    username = upi_lower.split("@")[0] if "@" in upi_lower else upi_lower

    for keyword, weight, reason in SCAM_UPI_KEYWORDS:
        if keyword in username:
            signals.append({
                "type": "red_flag", "weight": weight,
                "en": f"Scam keyword '{keyword}' in UPI ID — {reason}",
                "hi": f"UPI ID में scam keyword '{keyword}'"
            })

    # Generic account patterns — phone-number UPI IDs are VALID, do not flag
    generic_patterns = [
        r'^test\d*$', r'^demo\d*$', r'^fake\d*$',
        r'^sample\d*$', r'^dummy\d*$', r'^null\d*$',
    ]
    for pat in generic_patterns:
        if re.match(pat, username):
            signals.append({
                "type": "warning", "weight": 15,
                "en": f"UPI ID '{upi_id}' looks like a temporary/generic account",
                "hi": f"UPI ID '{upi_id}' temporary/generic account जैसा लगता है"
            })
            break

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
VISION_FORENSICS_SYSTEM = """You are a forensic expert detecting fake UPI payment screenshots in India.
Inspect the image for tampering or fakery and return ONLY valid JSON:
{
  "visual_risk_score": 0-100,
  "logo_authentic": true/false,
  "font_consistent": true/false,
  "color_scheme_correct": true/false,
  "pixel_artifacts_detected": true/false,
  "amount_area_suspicious": true/false,
  "ui_matches_claimed_app": true/false,
  "overall_visual_verdict": "genuine|suspicious|fake",
  "visual_flags": [{"en": "issue", "hi": "Hindi"}],
  "visual_safe_signals": [{"en": "positive signal", "hi": "Hindi"}],
  "visual_reasoning": "explanation"
}
If unsure → mark SUSPICIOUS, NOT genuine."""


def run_vision_forensics(image_bytes: bytes, app_key: str, app_display: str, rule_context: str) -> dict:
    """Deep visual forensics using Vision AI."""
    try:
        image_b64 = base64.b64encode(image_bytes).decode()
        app_info = APP_REGISTRY.get(app_key, {})

        prompt = f"""Analyze this UPI payment screenshot for authenticity.

CLAIMED APP: {app_display}
EXPECTED COLOR: {app_info.get('color_hint', 'unknown')}
EXPECTED STATUS: {', '.join(app_info.get('status_texts', []))}

RULE ENGINE CONTEXT:
{rule_context}

Visual forensic analysis:
- Is this genuinely from {app_display}?
- Any signs of editing, cropping, or template use?
- Does the amount field look native or pasted?
- Is the transaction ID area visually consistent?

IMPORTANT REAL-WORLD NOTES:
- In India, Paytm/GPay/BHIM apps CAN pay to @ybl/@okhdfcbank handles. Cross-app UPI is normal — NOT fake.
- Masked UPI IDs like "navi.******2623@naviaxis" shown by real apps for privacy — NOT fake.
- PhonePe green header "Transaction Successful" + "Contact PhonePe Support" = real PhonePe app.
- Do NOT flag screenshots just because the UI color looks slightly different from the detected app.
- CRITICAL: If the image is small (<400px wide) or heavily JPEG-compressed, pixelation/blur/font softness are from COMPRESSION, NOT editing. Only flag font inconsistency if you see it in ONE localized area (e.g. amount text looks pasted on different background). Uniform compression artifacts across the whole image = genuine screenshot, NOT fake.
- If unsure → mark suspicious, not genuine."""

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
            "visual_risk_score":      int(data.get("visual_risk_score", 50)),
            "logo_authentic":         data.get("logo_authentic"),
            "font_consistent":        data.get("font_consistent"),
            "color_scheme_correct":   data.get("color_scheme_correct"),
            "pixel_artifacts_detected": data.get("pixel_artifacts_detected", False),
            "amount_area_suspicious": data.get("amount_area_suspicious", False),
            "ui_matches_claimed_app": data.get("ui_matches_claimed_app"),
            "overall_visual_verdict": data.get("overall_visual_verdict", "suspicious"),
            "visual_flags":           data.get("visual_flags", []),
            "visual_safe_signals":    data.get("visual_safe_signals", []),
            "visual_reasoning":       data.get("visual_reasoning", ""),
        }
    except Exception as e:
        print(f"VISION FORENSICS ERROR: {e}")
        return {
            "visual_risk_score": 50, "overall_visual_verdict": "suspicious",
            "visual_flags": [], "visual_safe_signals": [], "visual_reasoning": "Failed",
            "logo_authentic": None, "font_consistent": None, "color_scheme_correct": None,
            "pixel_artifacts_detected": False, "amount_area_suspicious": False,
            "ui_matches_claimed_app": None,
        }


# ─────────────────────────────────────────────
# LAYER 7 — FRAUD PATTERN MEMORY
# ─────────────────────────────────────────────
def _perceptual_hash(image_bytes: bytes) -> str:
    """Simple perceptual hash — same fake template = similar hash."""
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(image_bytes)).convert("L").resize((16, 16), Image.LANCZOS)
        pixels = list(img.getdata())
        avg = sum(pixels) / len(pixels)
        bits = "".join("1" if p > avg else "0" for p in pixels)
        return hex(int(bits, 2))[2:].zfill(64)
    except Exception:
        return hashlib.md5(image_bytes[:1024]).hexdigest()


def _hamming_distance(h1: str, h2: str) -> int:
    """Hamming distance — auto-detect bit length for MD5 (128-bit) vs pHash (256-bit)."""
    try:
        bit_len = max(len(h1), len(h2)) * 4
        b1 = bin(int(h1, 16))[2:].zfill(bit_len)
        b2 = bin(int(h2, 16))[2:].zfill(bit_len)
        return sum(c1 != c2 for c1, c2 in zip(b1, b2))
    except Exception:
        return 256


async def check_fraud_pattern_memory(image_bytes: bytes) -> dict:
    """Check if screenshot matches a known fake template in DB."""
    result = {"found": False, "match_count": 0, "signal": None}
    try:
        from app.core.database import db
        _loop2 = asyncio.get_running_loop()
        phash = await _loop2.run_in_executor(None, _perceptual_hash, image_bytes)

        cursor = db.fake_screenshot_hashes.find(
            {"verdict": "SCAM"}, {"phash": 1, "count": 1, "app": 1}
        ).limit(200)

        async for doc in cursor:
            stored_hash = doc.get("phash", "")
            if not stored_hash:
                continue
            dist = _hamming_distance(phash, stored_hash)
            if dist < 20:
                result["found"] = True
                result["match_count"] = doc.get("count", 1)
                result["matched_app"] = doc.get("app", "unknown")
                result["signal"] = {
                    "type": "red_flag", "weight": 25,
                    "en": f"Matches known fake template seen {result['match_count']} times",
                    "hi": f"Known fake template से match — {result['match_count']} बार पहले देखा"
                }
                break

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
                "phash": phash, "verdict": verdict, "app": app_key,
                "count": 1, "created_at": datetime.utcnow(), "last_seen": datetime.utcnow(),
            })
    except Exception as e:
        print(f"SAVE PATTERN ERROR: {e}")


def signals_to_bayesian_score(signals: list) -> float:
    """Bayesian scoring: start at 40% prior, update multiplicatively."""
    p_fake = 0.40
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
    """Bayesian score aggregation across all layers."""
    ela_signals       = ela_signals or []
    exif_signals      = exif_signals or []
    dimension_signals = dimension_signals or []
    noise_signals     = noise_signals or []

    all_rule = (
        ela_signals + exif_signals + dimension_signals + noise_signals +
        validation_signals + rule_signals + consistency_signals + upi_signals
    )

    forensic_score = signals_to_bayesian_score(ela_signals + exif_signals + dimension_signals + noise_signals)
    rule_score     = signals_to_bayesian_score(validation_signals + rule_signals)
    consist_score  = signals_to_bayesian_score(consistency_signals)
    upi_score      = signals_to_bayesian_score(upi_signals)
    vision_score   = vision_result.get("visual_risk_score", 50)
    memory_score   = 80 if pattern_result.get("found") else 35
    conf_risk      = max(0, (100 - app_confidence) * 0.5)

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

    all_signals    = all_rule
    critical_flags = [s for s in all_signals if s.get("type") == "red_flag" and s.get("weight", 0) >= 35]

    ela_red  = any(s.get("type") == "red_flag" for s in ela_signals)
    exif_red = any(s.get("type") == "red_flag" for s in exif_signals)
    if ela_red and exif_red:
        final_risk = max(final_risk, 75)

    if len(critical_flags) >= 2:
        final_risk = max(final_risk, 66)

    if pattern_result.get("found"):
        final_risk = max(final_risk, 62)

    ela_green   = any(s.get("type") == "green_flag" for s in ela_signals)
    exif_green  = any(s.get("type") == "green_flag" for s in exif_signals)
    noise_green = any(s.get("type") == "green_flag" for s in noise_signals)
    green_count = sum([ela_green, exif_green, noise_green])
    if green_count >= 2 and final_risk > 65:
        if len(critical_flags) < 2:
            final_risk = min(final_risk, 64)

    risk_int = round(final_risk)
    if risk_int <= 35:
        verdict, verdict_hi = "SAFE", "सुरक्षित"
    elif risk_int <= 65:
        verdict, verdict_hi = "SUSPICIOUS", "संदिग्ध"
    else:
        verdict, verdict_hi = "SCAM", "धोखाधड़ी"

    all_count     = len(all_signals)
    critical_count = len(critical_flags)
    if all_count >= 10 or critical_count >= 2:
        confidence_level = "high"
    elif all_count >= 5:
        confidence_level = "medium"
    else:
        confidence_level = "low"

    return {
        "risk_score":        risk_int,
        "verdict":           verdict,
        "verdict_hi":        verdict_hi,
        "confidence_level":  confidence_level,
        "layer_scores": {
            "forensics_ela_exif":  round(forensic_score),
            "rule_engine":         round(rule_score),
            "consistency":         round(consist_score),
            "vision_ai":           round(vision_score),
            "upi_id_check":        round(upi_score),
            "pattern_memory":      round(memory_score),
            "app_confidence_risk": round(conf_risk),
        },
        "critical_flag_count": critical_count,
    }


# ─────────────────────────────────────────────
# MASTER FUNCTION — Full Pipeline
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
# ADVICE — What to do per verdict
# ─────────────────────────────────────────────
def get_advice(verdict: str, app_display: str) -> dict:
    if verdict == "SAFE":
        return {
            "what_to_do": [
                {"en": "Still verify the payment in YOUR bank app or UPI app before handing over goods", "hi": "Goods देने से पहले अपने bank app में payment verify करें"},
                {"en": "Check your account balance or transaction history for the credited amount", "hi": "अपने account में credited amount check करें"},
                {"en": "A SAFE verdict means low risk — always confirm in your own app", "hi": "SAFE verdict का मतलब कम risk है — अपने app में confirm करें"},
            ],
            "how_to_avoid": [
                {"en": "Always verify payments in YOUR bank app, not the buyer's screenshot", "hi": "हमेशा अपने bank app में verify करें, buyer के screenshot से नहीं"},
                {"en": "Enable transaction SMS alerts from your bank for instant confirmation", "hi": "Bank से transaction SMS alerts enable करें"},
                {"en": "Never rely solely on a screenshot as payment proof", "hi": "Screenshot को कभी भी payment proof न मानें"},
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


async def analyze_payment_screenshot(image_bytes: bytes) -> dict:
    """
    Full 8-layer analysis pipeline for fake UPI payment screenshot detection.
    Input: raw image bytes (JPEG/PNG)
    Output: structured verdict with risk%, signals, advice in EN+HI
    """

    _loop = asyncio.get_running_loop()

    # ── Layer 0: Forensic Image Analysis — all 4 run in PARALLEL ──
    ela_signals, exif_signals, dimension_signals, noise_signals = await asyncio.gather(
        _loop.run_in_executor(None, run_ela_analysis, image_bytes),
        _loop.run_in_executor(None, run_exif_analysis, image_bytes),
        _loop.run_in_executor(None, run_dimension_check, image_bytes),
        _loop.run_in_executor(None, run_noise_analysis, image_bytes),
    )

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

    # ── Save to pattern memory — fire and forget, don't block response ──
    phash = pattern_result.get("current_phash")
    if phash:
        asyncio.create_task(save_to_pattern_memory(phash, verdict, app_key))

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

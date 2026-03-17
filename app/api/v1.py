from fastapi import APIRouter, UploadFile, File
from pydantic import BaseModel

# Services
from app.services.ai_engine import call_ai_analysis, call_ai_vision_analysis, call_ai_vision_analysis_with_context
from app.services.ocr_engine import extract_text_from_image
from app.services.website_screenshot import capture_website_screenshot
from app.services.db_service import save_scan
from app.services.url_checker import analyze_url_full
from app.api.report import router as report_router
from app.api.contact import router as contact_router
from app.api.upi_checker import analyze_upi_full
from app.api.qr_checker import decode_qr_image

router = APIRouter()

router.include_router(report_router, prefix="/report", tags=["Report"])
router.include_router(contact_router, prefix="/contact", tags=["Contact"])


# ======================================================
# MODELS
# ======================================================
class TextCheckRequest(BaseModel):
    text: str

class UrlCheckRequest(BaseModel):
    url: str

class UpiCheckRequest(BaseModel):
    upi_id: str


# ======================================================
# TEXT CHECK
# ======================================================
@router.post("/check/text")
async def check_text(data: TextCheckRequest):

    text = data.text.strip()

    ai = call_ai_analysis(text)
    verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"

    await save_scan("text", text, verdict, ai["risk_score"])

    return {
        "verdict": verdict,
        "confidence": ai["confidence"],
        "why": ai["why"],
        "what_to_do": ai["what_to_do"],
        "how_to_avoid": ai["how_to_avoid"]
    }


# ======================================================
# IMAGE CHECK
# ======================================================
@router.post("/check/image")
async def check_image(file: UploadFile = File(...)):

    image_bytes = await file.read()

    extracted_text = extract_text_from_image(image_bytes)

    # -------------------------
    # OCR FIRST
    # -------------------------
    if extracted_text and len(extracted_text.strip()) > 25:

        ai = call_ai_analysis(extracted_text)
        verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"

        await save_scan("image", extracted_text, verdict, ai["risk_score"])

        return {
            "verdict": verdict,
            "confidence": ai["confidence"],
            "why": ai["why"],
            "what_to_do": ai["what_to_do"],
            "how_to_avoid": ai["how_to_avoid"],
            "engine": "OCR + TEXT AI"
        }

    # -------------------------
    # VISION FALLBACK
    # -------------------------
    vision_ai = call_ai_vision_analysis(image_bytes)

    if vision_ai:

        verdict = "SCAM" if vision_ai["risk_score"] >= 70 else "SAFE"

        await save_scan("image", "vision_image", verdict, vision_ai["risk_score"])

        return {
            "verdict": verdict,
            "confidence": vision_ai["confidence"],
            "why": vision_ai["why"],
            "what_to_do": vision_ai["what_to_do"],
            "how_to_avoid": vision_ai["how_to_avoid"],
            "engine": "VISION AI"
        }

    # fallback
    await save_scan("image", "unknown", "SAFE", 0)
    return {"verdict": "SAFE"}


# ======================================================
# URL CHECK — Technical Analysis + AI
# ======================================================
@router.post("/check/url")
async def check_url(data: UrlCheckRequest):
    url = data.url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    # STEP 1 — All technical checks parallel
    intel = await analyze_url_full(url)

    # STEP 2 — Blacklisted = instant SCAM
    if intel["blacklisted"]:
        prompt = f"""You are analyzing a URL for scam risk.

TECHNICAL ANALYSIS REPORT:
{intel["technical_report"]}

This URL is confirmed dangerous by security databases. Explain why it is dangerous."""

        ai = call_ai_analysis(prompt)
        await save_scan("url", url, "SCAM", 95)
        return {
            "verdict": "SCAM",
            "confidence": ai["confidence"],
            "why": ai["why"],
            "what_to_do": ai["what_to_do"],
            "how_to_avoid": ai["how_to_avoid"],
            "engine": "BLACKLIST + AI"
        }

    # STEP 3 — Screenshot + full technical report → AI decides
    screenshot = await capture_website_screenshot(url)

    if screenshot:
        vision_ai = call_ai_vision_analysis_with_context(
            screenshot,
            intel["technical_report"]
        )
        if vision_ai:
            verdict = "SCAM" if vision_ai["risk_score"] >= 70 else "SAFE"
            await save_scan("url", url, verdict, vision_ai["risk_score"])
            return {
                "verdict": verdict,
                "confidence": vision_ai["confidence"],
                "why": vision_ai["why"],
                "what_to_do": vision_ai["what_to_do"],
                "how_to_avoid": vision_ai["how_to_avoid"],
                "engine": "SCREENSHOT + TECHNICAL AI"
            }

    # STEP 4 — Screenshot failed — technical report only → AI decides
    prompt = f"""You are analyzing a URL for scam risk.

TECHNICAL ANALYSIS REPORT:
{intel["technical_report"]}

Screenshot could not be taken. Based only on these technical signals, determine if this URL is safe or a scam."""

    ai = call_ai_analysis(prompt)
    verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
    await save_scan("url", url, verdict, ai["risk_score"])
    return {
        "verdict": verdict,
        "confidence": ai["confidence"],
        "why": ai["why"],
        "what_to_do": ai["what_to_do"],
        "how_to_avoid": ai["how_to_avoid"],
        "engine": "TECHNICAL AI"
    }


# ======================================================
# UPI CHECK
# ======================================================
@router.post("/check/upi")
async def check_upi(data: UpiCheckRequest):
    upi_id = data.upi_id.strip()

    intel = await analyze_upi_full(upi_id)

    prompt = f"""You are analyzing a UPI ID for scam risk in India.

TECHNICAL ANALYSIS REPORT:
{intel["technical_report"]}

Analyze this UPI ID carefully. Consider:
1. Scam patterns in the username
2. Bank handle validity
3. Community reports
4. Indian UPI fraud patterns (KYC fraud, fake support, lottery, refund fraud)

Be decisive — if scam patterns exist, mark as SCAM."""

    ai = call_ai_analysis(prompt)
    verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"

    await save_scan("upi", upi_id, verdict, ai["risk_score"])

    return {
        "verdict": verdict,
        "confidence": ai["confidence"],
        "why": ai["why"],
        "what_to_do": ai["what_to_do"],
        "how_to_avoid": ai["how_to_avoid"],
        "engine": "UPI TECHNICAL + AI",
        "bank_name": intel["bank_name"],
        "community_reports": intel["community_reports"]
    }


# ======================================================
# QR CODE CHECK
# ======================================================
@router.post("/check/qr")
async def check_qr(file: UploadFile = File(...)):
    image_bytes = await file.read()

    decoded = decode_qr_image(image_bytes)

    if not decoded["success"]:
        return {
            "verdict": "UNKNOWN",
            "confidence": {
                "en": "Could not read QR/Barcode from image",
                "hi": "QR/Barcode पढ़ने में असमर्थ"
            },
            "why": [],
            "what_to_do": [{"en": "Try a clearer image", "hi": "साफ़ तस्वीर लें"}],
            "how_to_avoid": [],
            "engine": "QR DECODE FAILED"
        }

    content = decoded["content"]
    content_type = decoded["content_type"]

    # UPI QR
    if content_type == "upi":
        upi_id = decoded.get("upi_id", content)
        intel = await analyze_upi_full(upi_id)

        prompt = f"""You are analyzing a UPI QR Code for scam risk in India.

QR Code decoded content: {content}
Extracted UPI ID: {upi_id}

TECHNICAL ANALYSIS REPORT:
{intel["technical_report"]}

Analyze this UPI QR code. Is it safe to pay?"""

        ai = call_ai_analysis(prompt)
        verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
        await save_scan("qr", upi_id, verdict, ai["risk_score"])

        return {
            "verdict": verdict,
            "decoded_content": content,
            "content_type": "UPI Payment",
            "upi_id": upi_id,
            "bank_name": intel["bank_name"],
            "confidence": ai["confidence"],
            "why": ai["why"],
            "what_to_do": ai["what_to_do"],
            "how_to_avoid": ai["how_to_avoid"],
            "engine": "QR → UPI TECHNICAL + AI"
        }

    # URL QR
    elif content_type == "url":
        url = content
        intel = await analyze_url_full(url)

        if intel["blacklisted"]:
            prompt = f"""This QR code contains a dangerous URL.

URL: {url}
TECHNICAL REPORT:
{intel["technical_report"]}

Explain why this QR code URL is dangerous."""

            ai = call_ai_analysis(prompt)
            await save_scan("qr", url, "SCAM", 95)
            return {
                "verdict": "SCAM",
                "decoded_content": content,
                "content_type": "URL",
                "confidence": ai["confidence"],
                "why": ai["why"],
                "what_to_do": ai["what_to_do"],
                "how_to_avoid": ai["how_to_avoid"],
                "engine": "QR → BLACKLIST + AI"
            }

        screenshot = await capture_website_screenshot(url)
        if screenshot:
            vision_ai = call_ai_vision_analysis_with_context(
                screenshot,
                intel["technical_report"]
            )
            if vision_ai:
                verdict = "SCAM" if vision_ai["risk_score"] >= 70 else "SAFE"
                await save_scan("qr", url, verdict, vision_ai["risk_score"])
                return {
                    "verdict": verdict,
                    "decoded_content": content,
                    "content_type": "URL",
                    "confidence": vision_ai["confidence"],
                    "why": vision_ai["why"],
                    "what_to_do": vision_ai["what_to_do"],
                    "how_to_avoid": vision_ai["how_to_avoid"],
                    "engine": "QR → SCREENSHOT + TECHNICAL AI"
                }

        prompt = f"""This QR code contains a URL. Analyze for scam risk.

URL: {url}
TECHNICAL REPORT:
{intel["technical_report"]}"""

        ai = call_ai_analysis(prompt)
        verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
        await save_scan("qr", url, verdict, ai["risk_score"])
        return {
            "verdict": verdict,
            "decoded_content": content,
            "content_type": "URL",
            "confidence": ai["confidence"],
            "why": ai["why"],
            "what_to_do": ai["what_to_do"],
            "how_to_avoid": ai["how_to_avoid"],
            "engine": "QR → TECHNICAL AI"
        }

    # TEXT QR
    else:
        ai = call_ai_analysis(f"""This QR code contains the following content:

{content}

Analyze if this QR code content is suspicious or a scam.""")

        verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
        await save_scan("qr", content[:200], verdict, ai["risk_score"])
        return {
            "verdict": verdict,
            "decoded_content": content,
            "content_type": content_type.upper(),
            "confidence": ai["confidence"],
            "why": ai["why"],
            "what_to_do": ai["what_to_do"],
            "how_to_avoid": ai["how_to_avoid"],
            "engine": "QR → TEXT AI"
        }

from fastapi import APIRouter, UploadFile, File
from pydantic import BaseModel

# Services
from app.services.ai_engine import (
    call_ai_analysis,
    call_ai_vision_analysis,
    call_ai_vision_analysis_with_context,
    call_ai_url_full_analysis,          # NEW
)
from app.services.ocr_engine import extract_text_from_image
from app.services.website_screenshot import capture_website_screenshot
from app.services.db_service import save_scan
from app.services.url_checker import analyze_url_full
from app.api.report import router as report_router
from app.api.contact import router as contact_router
from app.api.offer_letter import router as offer_letter_router
from app.api.upi_checker import analyze_upi_full
from app.api.qr_checker import decode_qr_image

router = APIRouter()

router.include_router(report_router, prefix="/report", tags=["Report"])
router.include_router(contact_router, prefix="/contact", tags=["Contact"])
router.include_router(offer_letter_router, tags=["Offer Letter"])


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
# TEXT CHECK (unchanged)
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
# IMAGE CHECK (unchanged)
# ======================================================
@router.post("/check/image")
async def check_image(file: UploadFile = File(...)):
    image_bytes = await file.read()
    extracted_text = extract_text_from_image(image_bytes)

    if extracted_text and len(extracted_text.strip()) > 25:
        ai = call_ai_analysis(extracted_text)
        verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
        await save_scan("image", extracted_text, verdict, ai["risk_score"])
        return {"verdict": verdict, "confidence": ai["confidence"], "why": ai["why"], "what_to_do": ai["what_to_do"], "how_to_avoid": ai["how_to_avoid"], "engine": "OCR + TEXT AI"}

    vision_ai = call_ai_vision_analysis(image_bytes)
    if vision_ai:
        verdict = "SCAM" if vision_ai["risk_score"] >= 70 else "SAFE"
        await save_scan("image", "vision_image", verdict, vision_ai["risk_score"])
        return {"verdict": verdict, "confidence": vision_ai["confidence"], "why": vision_ai["why"], "what_to_do": vision_ai["what_to_do"], "how_to_avoid": vision_ai["how_to_avoid"], "engine": "VISION AI"}

    await save_scan("image", "unknown", "SAFE", 0)
    return {"verdict": "SAFE"}


# ======================================================
# URL CHECK — v2.0 — 12 Sources + Screenshot → AI
# ======================================================
@router.post("/check/url")
async def check_url(data: UrlCheckRequest):
    url = data.url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    # ── STEP 1: Run all 12 intelligence checks in parallel ──
    intel = await analyze_url_full(url)

    # ── STEP 2: Blacklisted = instant SCAM, still get AI explanation ──
    if intel["blacklisted"]:
        # Still take screenshot for AI to explain visually
        screenshot = await capture_website_screenshot(url)
        ai = call_ai_url_full_analysis(screenshot, intel)

        if ai:
            await save_scan("url", url, "SCAM", max(ai["risk_score"], 90))
            return {
                "verdict": "SCAM",
                "confidence": ai["confidence"],
                "why": ai["why"],
                "what_to_do": ai["what_to_do"],
                "how_to_avoid": ai["how_to_avoid"],
                "engine": "BLACKLIST + 12-SOURCE + AI",
                # ScamAdvisor-style data
                "trust_score": intel["trust_score"],
                "verdict_hi": intel["verdict_hi"],
                "sources": intel["sources"],
                "summary": intel["summary"],
                "top_risks": intel["top_risks"],
                "explanation": intel["explanation"],
                "other_info": intel["other_info"],
            }

        # AI failed — still return blacklist verdict
        await save_scan("url", url, "SCAM", 95)
        return {
            "verdict": "SCAM",
            "confidence": {"en": "This URL is confirmed dangerous by security databases.", "hi": "यह URL सुरक्षा डेटाबेस में खतरनाक के रूप में सूचीबद्ध है।"},
            "why": [{"en": r, "hi": r} for r in intel.get("top_risks", ["Blacklisted by security databases"])[:3]],
            "what_to_do": [{"en": "Do not visit this website", "hi": "इस वेबसाइट पर न जाएं"}],
            "how_to_avoid": [{"en": "Always verify URLs before clicking", "hi": "क्लिक करने से पहले URL सत्यापित करें"}],
            "engine": "BLACKLIST + 12-SOURCE",
            "trust_score": intel["trust_score"],
            "verdict_hi": intel["verdict_hi"],
            "sources": intel["sources"],
            "summary": intel["summary"],
            "top_risks": intel["top_risks"],
            "explanation": intel["explanation"],
            "other_info": intel["other_info"],
        }

    # ── STEP 3: Not blacklisted — Screenshot + ALL intel → AI decides ──
    screenshot = await capture_website_screenshot(url)

    ai = call_ai_url_full_analysis(screenshot, intel)

    if ai:
        verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
        engine = "SCREENSHOT + 12-SOURCE + AI" if screenshot else "12-SOURCE + AI (no screenshot)"
        await save_scan("url", url, verdict, ai["risk_score"])
        return {
            "verdict": verdict,
            "confidence": ai["confidence"],
            "why": ai["why"],
            "what_to_do": ai["what_to_do"],
            "how_to_avoid": ai["how_to_avoid"],
            "engine": engine,
            # ScamAdvisor-style data
            "trust_score": intel["trust_score"],
            "verdict_hi": intel["verdict_hi"],
            "sources": intel["sources"],
            "summary": intel["summary"],
            "top_risks": intel["top_risks"],
            "explanation": intel["explanation"],
            "other_info": intel["other_info"],
        }

    # ── STEP 4: AI failed — use scoring engine verdict ──
    ts = intel["trust_score"]
    verdict = "SCAM" if ts < 40 else "SAFE"
    await save_scan("url", url, verdict, 100 - ts)
    return {
        "verdict": verdict,
        "confidence": {"en": f"Trust score: {ts}/100 — {intel['verdict']}", "hi": intel["verdict_hi"]},
        "why": [{"en": r, "hi": r} for r in intel.get("explanation", [])[:3]],
        "what_to_do": [{"en": "Exercise caution with this website", "hi": "इस वेबसाइट के साथ सावधानी बरतें"}],
        "how_to_avoid": [{"en": "Verify website authenticity before sharing data", "hi": "डेटा साझा करने से पहले वेबसाइट सत्यापित करें"}],
        "engine": "12-SOURCE SCORING ENGINE",
        "trust_score": ts,
        "verdict_hi": intel["verdict_hi"],
        "sources": intel["sources"],
        "summary": intel["summary"],
        "top_risks": intel["top_risks"],
        "explanation": intel["explanation"],
        "other_info": intel["other_info"],
    }


# ======================================================
# UPI CHECK (unchanged)
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
# QR CODE CHECK (unchanged)
# ======================================================
@router.post("/check/qr")
async def check_qr(file: UploadFile = File(...)):
    image_bytes = await file.read()
    decoded = decode_qr_image(image_bytes)

    if not decoded["success"]:
        return {
            "verdict": "UNKNOWN",
            "confidence": {"en": "Could not read QR/Barcode from image", "hi": "QR/Barcode पढ़ने में असमर्थ"},
            "why": [], "what_to_do": [{"en": "Try a clearer image", "hi": "साफ़ तस्वीर लें"}],
            "how_to_avoid": [], "engine": "QR DECODE FAILED"
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
            "verdict": verdict, "decoded_content": content, "content_type": "UPI Payment",
            "upi_id": upi_id, "bank_name": intel["bank_name"],
            "confidence": ai["confidence"], "why": ai["why"],
            "what_to_do": ai["what_to_do"], "how_to_avoid": ai["how_to_avoid"],
            "engine": "QR → UPI TECHNICAL + AI"
        }

    # URL QR
    elif content_type == "url":
        qr_url = content
        intel = await analyze_url_full(qr_url)

        screenshot = await capture_website_screenshot(qr_url)
        ai = call_ai_url_full_analysis(screenshot, intel)

        if ai:
            # Override if blacklisted
            if intel["blacklisted"]:
                ai["risk_score"] = max(ai["risk_score"], 90)

            verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
            await save_scan("qr", qr_url, verdict, ai["risk_score"])
            return {
                "verdict": verdict, "decoded_content": content, "content_type": "URL",
                "confidence": ai["confidence"], "why": ai["why"],
                "what_to_do": ai["what_to_do"], "how_to_avoid": ai["how_to_avoid"],
                "engine": "QR → 12-SOURCE + AI",
                "trust_score": intel["trust_score"],
                "sources": intel["sources"],
                "summary": intel["summary"],
            }

        # AI failed fallback
        prompt = f"""QR code contains URL. Technical report:\n{intel['technical_report']}"""
        ai = call_ai_analysis(prompt)
        verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
        await save_scan("qr", qr_url, verdict, ai["risk_score"])
        return {
            "verdict": verdict, "decoded_content": content, "content_type": "URL",
            "confidence": ai["confidence"], "why": ai["why"],
            "what_to_do": ai["what_to_do"], "how_to_avoid": ai["how_to_avoid"],
            "engine": "QR → TECHNICAL AI FALLBACK"
        }

    # TEXT QR
    else:
        ai = call_ai_analysis(f"QR code content:\n{content}\n\nAnalyze for scam risk.")
        verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
        await save_scan("qr", content[:200], verdict, ai["risk_score"])
        return {
            "verdict": verdict, "decoded_content": content, "content_type": content_type.upper(),
            "confidence": ai["confidence"], "why": ai["why"],
            "what_to_do": ai["what_to_do"], "how_to_avoid": ai["how_to_avoid"],
            "engine": "QR → TEXT AI"
        }

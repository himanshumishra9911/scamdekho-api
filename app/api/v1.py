from fastapi import APIRouter, UploadFile, File
from pydantic import BaseModel

# Services
from app.services.ai_engine import call_ai_analysis, call_ai_vision_analysis
from app.services.ocr_engine import extract_text_from_image
from app.services.website_screenshot import capture_website_screenshot
from app.services.db_service import save_scan
from app.api.report import router as report_router
from app.api.contact import router as contact_router



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


# ======================================================
# TEXT CHECK
# ======================================================
@router.post("/check/text")
async def check_text(data: TextCheckRequest):

    text = data.text.strip()

    ai = call_ai_analysis(text)
    verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"

    # ✅ SAVE ONLY ONCE
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
# URL CHECK
# ======================================================
@router.post("/check/url")
async def check_url(data: UrlCheckRequest):

    url = data.url.strip()

    screenshot = await capture_website_screenshot(url)

    # -------------------------
    # Website loaded → Vision AI
    # -------------------------
    if screenshot:

        ai = call_ai_vision_analysis(screenshot)
        verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"

        await save_scan("url", url, verdict, ai["risk_score"])

        return {
            "verdict": verdict,
            "confidence": ai["confidence"],
            "why": ai["why"],
            "what_to_do": ai["what_to_do"],
            "how_to_avoid": ai["how_to_avoid"],
            "engine": "VISION WEBSITE"
        }

    # -------------------------
    # Website failed → SCAM
    # -------------------------
    verdict = "SCAM"

    await save_scan("url", url, verdict, 95)

    return {
        "verdict": "SCAM",
        "confidence": {
            "en": "Website could not be loaded. Domain looks suspicious or fake.",
            "hi": "वेबसाइट खुल नहीं पाई। डोमेन संदिग्ध या नकली हो सकता है।"
        },
        "why": [
            {"en": "Domain failed to load", "hi": "डोमेन खुल नहीं रहा"},
            {"en": "Most phishing sites behave like this", "hi": "अधिकतर फिशिंग साइट्स ऐसे ही व्यवहार करती हैं"}
        ],
        "what_to_do": [
            {"en": "Do not open or share this link", "hi": "इस लिंक को न खोलें और न शेयर करें"}
        ],
        "how_to_avoid": []
    }

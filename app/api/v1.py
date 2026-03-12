from fastapi import APIRouter, UploadFile, File
from pydantic import BaseModel

# Services
from app.services.ai_engine import call_ai_analysis, call_ai_vision_analysis
from app.services.ocr_engine import extract_text_from_image
from app.services.website_screenshot import capture_website_screenshot
from app.services.db_service import save_scan
from app.services.url_checker import analyze_url_full
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
# URL CHECK — Multi Signal + AI
# ======================================================
@router.post("/check/url")
async def check_url(data: UrlCheckRequest):
    url = data.url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    # STEP 1 — Run all checks parallel
    intel = await analyze_url_full(url)
    signals_text = ", ".join(intel["signals"]) if intel["signals"] else "None"

    base_prompt = f"""URL: {url}
Risk score from security checks: {intel["total_score"]}/100
Security signals found: {signals_text}
Blacklisted by security databases: {intel["blacklisted"]}
Analyze this URL for scam risk and give full explanation."""

    # STEP 2 — Blacklisted = instant SCAM
    if intel["blacklisted"]:
        ai = call_ai_analysis(base_prompt)
        await save_scan("url", url, "SCAM", 95)
        return {
            "verdict": "SCAM",
            "confidence": ai["confidence"],
            "why": ai["why"],
            "what_to_do": ai["what_to_do"],
            "how_to_avoid": ai["how_to_avoid"],
            "engine": "BLACKLIST + AI"
        }

    # STEP 3 — High score = SCAM, no screenshot needed
    if intel["total_score"] >= 70:
        ai = call_ai_analysis(base_prompt)
        verdict = "SCAM" if ai["risk_score"] >= 60 else "SAFE"
        await save_scan("url", url, verdict, max(intel["total_score"], ai["risk_score"]))
        return {
            "verdict": verdict,
            "confidence": ai["confidence"],
            "why": ai["why"],
            "what_to_do": ai["what_to_do"],
            "how_to_avoid": ai["how_to_avoid"],
            "engine": "MULTI-SIGNAL AI"
        }

    # STEP 4 — Low score = likely SAFE, no screenshot needed
    if intel["total_score"] <= 15 and not intel["signals"]:
        ai = call_ai_analysis(base_prompt)
        verdict = "SCAM" if ai["risk_score"] >= 75 else "SAFE"
        await save_scan("url", url, verdict, ai["risk_score"])
        return {
            "verdict": verdict,
            "confidence": ai["confidence"],
            "why": ai["why"],
            "what_to_do": ai["what_to_do"],
            "how_to_avoid": ai["how_to_avoid"],
            "engine": "URL AI"
        }

    # STEP 5 — Inconclusive = Screenshot lo
    screenshot = await capture_website_screenshot(url)
    if screenshot:
        vision_ai = call_ai_vision_analysis(screenshot)
        if vision_ai:
            combined = (intel["total_score"] * 0.4) + (vision_ai["risk_score"] * 0.6)
            verdict = "SCAM" if combined >= 65 else "SAFE"
            await save_scan("url", url, verdict, combined)
            return {
                "verdict": verdict,
                "confidence": vision_ai["confidence"],
                "why": vision_ai["why"],
                "what_to_do": vision_ai["what_to_do"],
                "how_to_avoid": vision_ai["how_to_avoid"],
                "engine": "FULL ANALYSIS"
            }

    # STEP 6 — Screenshot fail — AI fallback
    ai = call_ai_analysis(base_prompt)
    verdict = "SCAM" if max(intel["total_score"], ai["risk_score"]) >= 65 else "SAFE"
    await save_scan("url", url, verdict, max(intel["total_score"], ai["risk_score"]))
    return {
        "verdict": verdict,
        "confidence": ai["confidence"],
        "why": ai["why"],
        "what_to_do": ai["what_to_do"],
        "how_to_avoid": ai["how_to_avoid"],
        "engine": "AI FALLBACK"
    }

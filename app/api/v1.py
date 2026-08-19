from fastapi import APIRouter, UploadFile, File, Depends, Request, HTTPException
from pydantic import BaseModel
import asyncio

# Services
from app.services.ai_engine import (
    call_ai_analysis,
    call_ai_vision_analysis,
    call_ai_vision_analysis_with_context,
    call_ai_url_full_analysis,
)
from app.services.ocr_engine import extract_text_from_image
from app.services.website_screenshot import capture_website_screenshot
from app.services.db_service import save_scan
from app.services.url_checker import analyze_url_full
from app.services.cache_service import (
    get_cached_result,
    set_cached_result,
    get_cached_scan,
    set_cached_scan,
    get_cached_message_check,
    set_cached_message_check,
)
from app.services.rate_limiter import check_url_rate_limit
from app.services.security import get_client_ip, require_public_client, is_scammer_testing_url
from app.services.turnstile_service import verify_turnstile_token
from app.api.report import router as report_router
from app.api.contact import router as contact_router
from app.api.offer_letter import router as offer_letter_router
from app.api.upi_checker import analyze_upi_full
from app.api.qr_checker import decode_qr_image
from app.api.payment_screenshot import router as payment_screenshot_router


router = APIRouter()

router.include_router(report_router, prefix="/report", tags=["Report"])
router.include_router(contact_router, prefix="/contact", tags=["Contact"])
router.include_router(offer_letter_router, tags=["Offer Letter"])
router.include_router(payment_screenshot_router, tags=["Payment Screenshot"])


def scan_meta(request: Request) -> dict:
    return {
        "client_ip": get_client_ip(request),
        "user_agent": request.headers.get("user-agent", "")[:300],
    }


# ======================================================
# MODELS
# ======================================================
class TextCheckRequest(BaseModel):
    text: str
    turnstile_token: str | None = None

class UrlCheckRequest(BaseModel):
    url: str

class UpiCheckRequest(BaseModel):
    upi_id: str


# ======================================================
# TEXT CHECK
# ======================================================
@router.post("/check/text")
async def check_text(data: TextCheckRequest, request: Request):
    text = data.text.strip()
    turnstile_token = (data.turnstile_token or "").strip()

    # Verify Turnstile before any cache lookup or paid AI call.
    if not turnstile_token:
        raise HTTPException(status_code=403, detail="Turnstile verification required")

    is_human = await verify_turnstile_token(turnstile_token, get_client_ip(request))
    if not is_human:
        raise HTTPException(status_code=403, detail="Turnstile verification failed")

    # Reuse a 24-hour cached verdict for the normalized text hash.
    cached = await get_cached_message_check(text)
    if cached:
        cached["from_cache"] = True
        return cached

    # Call the existing AI workflow only after Turnstile and cache checks pass.
    ai = call_ai_analysis(text)
    verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
    response = {
        "verdict": verdict,
        "confidence": ai["confidence"],
        "why": ai["why"],
        "what_to_do": ai["what_to_do"],
        "how_to_avoid": ai["how_to_avoid"]
    }
    await save_scan("text", text, verdict, ai["risk_score"], scan_meta(request))
    await set_cached_message_check(text, response)
    return response


# ======================================================
# IMAGE CHECK
# ======================================================
@router.post("/check/image")
async def check_image(request: Request, file: UploadFile = File(...)):
    image_bytes = await file.read()
    cached = await get_cached_scan("image", image_bytes)
    if cached:
        cached["from_cache"] = True
        return cached

    extracted_text = extract_text_from_image(image_bytes)

    if extracted_text and len(extracted_text.strip()) > 25:
        ai = call_ai_analysis(extracted_text)
        verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
        response = {"verdict": verdict, "confidence": ai["confidence"], "why": ai["why"], "what_to_do": ai["what_to_do"], "how_to_avoid": ai["how_to_avoid"], "engine": "OCR + TEXT AI"}
        await save_scan("image", extracted_text, verdict, ai["risk_score"], scan_meta(request))
        await set_cached_scan("image", image_bytes, response)
        return response

    vision_ai = call_ai_vision_analysis(image_bytes)
    if vision_ai:
        verdict = "SCAM" if vision_ai["risk_score"] >= 70 else "SAFE"
        response = {"verdict": verdict, "confidence": vision_ai["confidence"], "why": vision_ai["why"], "what_to_do": vision_ai["what_to_do"], "how_to_avoid": vision_ai["how_to_avoid"], "engine": "VISION AI"}
        await save_scan("image", "vision_image", verdict, vision_ai["risk_score"], scan_meta(request))
        await set_cached_scan("image", image_bytes, response)
        return response

    await save_scan("image", "unknown", "SAFE", 0, scan_meta(request))
    response = {"verdict": "SAFE"}
    await set_cached_scan("image", image_bytes, response)
    return response


# ======================================================
# URL CHECK — with Rate Limiting + Caching
# ======================================================
@router.post("/check/url")
async def check_url(
    data: UrlCheckRequest,
    request: Request,
    _: None = Depends(require_public_client),
    __: None = Depends(check_url_rate_limit),
):
    url = data.url.strip()
    if not url.startswith("http"):
        url = "https://" + url

    # ── SCAMMER BLOCK — census/nha fake domains ──
    if is_scammer_testing_url(url):
        raise HTTPException(status_code=400, detail="Invalid URL")

    # ── STEP 1: Cache check ──
    cached = await get_cached_result(url)
    if cached:
        cached["from_cache"] = True
        return cached

    # ── STEP 2: Run all 14 intelligence checks in parallel ──
    intel = await analyze_url_full(url)

    # ── STEP 3: Blacklisted = instant SCAM ──
    if intel["blacklisted"]:
        screenshot = await capture_website_screenshot(url)
        ai = call_ai_url_full_analysis(screenshot, intel)

        if ai:
            response = {
                "verdict": "SCAM",
                "confidence": ai["confidence"],
                "why": ai["why"],
                "what_to_do": ai["what_to_do"],
                "how_to_avoid": ai["how_to_avoid"],
                "engine": "BLACKLIST + 14-SOURCE + AI",
                "trust_score": intel["trust_score"],
                "verdict_hi": intel["verdict_hi"],
                "sources": intel["sources"],
                "summary": intel["summary"],
                "top_risks": intel["top_risks"],
                "explanation": intel["explanation"],
                "other_info": intel["other_info"],
            }
            await save_scan("url", url, "SCAM", max(ai["risk_score"], 90), scan_meta(request))
            await set_cached_result(url, response)
            return response

        response = {
            "verdict": "SCAM",
            "confidence": {"en": "This URL is confirmed dangerous by security databases.", "hi": "यह URL सुरक्षा डेटाबेस में खतरनाक के रूप में सूचीबद्ध है।"},
            "why": [{"en": r, "hi": r} for r in intel.get("top_risks", ["Blacklisted by security databases"])[:3]],
            "what_to_do": [{"en": "Do not visit this website", "hi": "इस वेबसाइट पर न जाएं"}],
            "how_to_avoid": [{"en": "Always verify URLs before clicking", "hi": "क्लिक करने से पहले URL सत्यापित करें"}],
            "engine": "BLACKLIST + 14-SOURCE",
            "trust_score": intel["trust_score"],
            "verdict_hi": intel["verdict_hi"],
            "sources": intel["sources"],
            "summary": intel["summary"],
            "top_risks": intel["top_risks"],
            "explanation": intel["explanation"],
            "other_info": intel["other_info"],
        }
        await save_scan("url", url, "SCAM", 95, scan_meta(request))
        await set_cached_result(url, response)
        return response

    # ── STEP 4: Screenshot + ALL intel → AI decides ──
    screenshot = await capture_website_screenshot(url)
    ai = call_ai_url_full_analysis(screenshot, intel)

    if ai:
        verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
        engine = "SCREENSHOT + 14-SOURCE + AI" if screenshot else "14-SOURCE + AI (no screenshot)"
        response = {
            "verdict": verdict,
            "confidence": ai["confidence"],
            "why": ai["why"],
            "what_to_do": ai["what_to_do"],
            "how_to_avoid": ai["how_to_avoid"],
            "engine": engine,
            "trust_score": intel["trust_score"],
            "verdict_hi": intel["verdict_hi"],
            "sources": intel["sources"],
            "summary": intel["summary"],
            "top_risks": intel["top_risks"],
            "explanation": intel["explanation"],
            "other_info": intel["other_info"],
        }
        await save_scan("url", url, verdict, ai["risk_score"], scan_meta(request))
        await set_cached_result(url, response)
        return response

    # ── STEP 5: AI failed — scoring engine verdict ──
    ts = intel["trust_score"]
    verdict = "SCAM" if ts < 40 else "SAFE"
    response = {
        "verdict": verdict,
        "confidence": {"en": f"Trust score: {ts}/100 — {intel['verdict']}", "hi": intel["verdict_hi"]},
        "why": [{"en": r, "hi": r} for r in intel.get("explanation", [])[:3]],
        "what_to_do": [{"en": "Exercise caution with this website", "hi": "इस वेबसाइट के साथ सावधानी बरतें"}],
        "how_to_avoid": [{"en": "Verify website authenticity before sharing data", "hi": "डेटा साझा करने से पहले वेबसाइट सत्यापित करें"}],
        "engine": "14-SOURCE SCORING ENGINE",
        "trust_score": ts,
        "verdict_hi": intel["verdict_hi"],
        "sources": intel["sources"],
        "summary": intel["summary"],
        "top_risks": intel["top_risks"],
        "explanation": intel["explanation"],
        "other_info": intel["other_info"],
    }
    await save_scan("url", url, verdict, 100 - ts, scan_meta(request))
    await set_cached_result(url, response)
    return response


# ======================================================
# UPI CHECK
# ======================================================
@router.post("/check/upi")
async def check_upi(data: UpiCheckRequest, request: Request):
    upi_id = data.upi_id.strip()
    cached = await get_cached_scan("upi", upi_id)
    if cached:
        cached["from_cache"] = True
        return cached

    intel = await analyze_upi_full(upi_id)

    if intel.get("govt_confirmed"):
        verdict = "SCAM"
        await save_scan("upi", upi_id, verdict, 100, scan_meta(request))
        response = {
            "verdict": verdict,
            "verdict_state": "SCAM",
            "confidence": {
                "en": f"This UPI ID is confirmed in {intel['govt_source']} as a scam.",
                "hi": f"यह UPI ID {intel['govt_source']} में confirmed scam है।"
            },
            "why": [{"en": f"Found in government scam database: {intel['govt_source']}", "hi": "सरकारी scam database में मिला"}],
            "what_to_do": [{"en": "Do not make any payment to this UPI ID", "hi": "इस UPI ID पर कोई payment न करें"}],
            "how_to_avoid": [{"en": "Always verify UPI IDs before payment", "hi": "Payment से पहले UPI ID verify करें"}],
            "engine": "GOVT SCAM DB — CONFIRMED",
            "bank_name": intel["bank_name"],
            "community_reports": intel["community_reports"]
        }
        await set_cached_scan("upi", upi_id, response)
        return response

    prompt = f"""You are analyzing a UPI ID for scam risk in India.

TECHNICAL ANALYSIS REPORT:
{intel["technical_report"]}

Analyze this UPI ID carefully. Consider:
1. Scam patterns in the username
2. Bank handle validity
3. Community and government database reports
4. Indian UPI fraud patterns (KYC fraud, fake support, lottery, refund fraud)

IMPORTANT:
- Phone-number usernames (10 digits) are NORMAL — do not flag them
- Generic words like 'bank' or 'care' alone are NOT scam proof
- Only mark SCAM if you see CLEAR, SPECIFIC fraud evidence"""

    loop = asyncio.get_running_loop()
    ai = await loop.run_in_executor(None, call_ai_analysis, prompt)

    risk = ai["risk_score"]
    if risk >= 70:
        verdict = "SCAM"
        verdict_state = "SCAM"
    elif risk >= 45:
        verdict = "SUSPICIOUS"
        verdict_state = "SUSPICIOUS"
    else:
        verdict = "SAFE"
        verdict_state = "SAFE"

    response = {
        "verdict": verdict,
        "verdict_state": verdict_state,
        "confidence": ai["confidence"],
        "why": ai["why"],
        "what_to_do": ai["what_to_do"],
        "how_to_avoid": ai["how_to_avoid"],
        "engine": "UPI TECHNICAL + GOVT DB + AI",
        "bank_name": intel["bank_name"],
        "community_reports": intel["community_reports"],
        "govt_confirmed": intel["govt_confirmed"],
    }
    await save_scan("upi", upi_id, verdict, ai["risk_score"], scan_meta(request))
    await set_cached_scan("upi", upi_id, response)
    return response


# ======================================================
# QR CODE CHECK
# ======================================================
@router.post("/check/qr")
async def check_qr(request: Request, file: UploadFile = File(...)):
    image_bytes = await file.read()
    cached = await get_cached_scan("qr", image_bytes)
    if cached:
        cached["from_cache"] = True
        return cached

    decoded = decode_qr_image(image_bytes)

    if not decoded["success"]:
        response = {
            "verdict": "UNKNOWN",
            "confidence": {"en": "Could not read QR/Barcode from image", "hi": "QR/Barcode पढ़ने में असमर्थ"},
            "why": [], "what_to_do": [{"en": "Try a clearer image", "hi": "साफ़ तस्वीर लें"}],
            "how_to_avoid": [], "engine": "QR DECODE FAILED"
        }
        await set_cached_scan("qr", image_bytes, response)
        return response

    content = decoded["content"]
    content_type = decoded["content_type"]

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
        response = {
            "verdict": verdict, "decoded_content": content, "content_type": "UPI Payment",
            "upi_id": upi_id, "bank_name": intel["bank_name"],
            "confidence": ai["confidence"], "why": ai["why"],
            "what_to_do": ai["what_to_do"], "how_to_avoid": ai["how_to_avoid"],
            "engine": "QR → UPI TECHNICAL + AI"
        }
        await save_scan("qr", upi_id, verdict, ai["risk_score"], scan_meta(request))
        await set_cached_scan("qr", image_bytes, response)
        return response

    elif content_type == "url":
        qr_url = content
        intel = await analyze_url_full(qr_url)
        screenshot = await capture_website_screenshot(qr_url)
        ai = call_ai_url_full_analysis(screenshot, intel)

        if ai:
            if intel["blacklisted"]:
                ai["risk_score"] = max(ai["risk_score"], 90)
            verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
            response = {
                "verdict": verdict, "decoded_content": content, "content_type": "URL",
                "confidence": ai["confidence"], "why": ai["why"],
                "what_to_do": ai["what_to_do"], "how_to_avoid": ai["how_to_avoid"],
                "engine": "QR → 14-SOURCE + AI",
                "trust_score": intel["trust_score"],
                "sources": intel["sources"],
                "summary": intel["summary"],
            }
            await save_scan("qr", qr_url, verdict, ai["risk_score"], scan_meta(request))
            await set_cached_scan("qr", image_bytes, response)
            return response

        prompt = f"""QR code contains URL. Technical report:\n{intel['technical_report']}"""
        ai = call_ai_analysis(prompt)
        verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
        response = {
            "verdict": verdict, "decoded_content": content, "content_type": "URL",
            "confidence": ai["confidence"], "why": ai["why"],
            "what_to_do": ai["what_to_do"], "how_to_avoid": ai["how_to_avoid"],
            "engine": "QR → TECHNICAL AI FALLBACK"
        }
        await save_scan("qr", qr_url, verdict, ai["risk_score"], scan_meta(request))
        await set_cached_scan("qr", image_bytes, response)
        return response

    else:
        ai = call_ai_analysis(f"QR code content:\n{content}\n\nAnalyze for scam risk.")
        verdict = "SCAM" if ai["risk_score"] >= 70 else "SAFE"
        response = {
            "verdict": verdict, "decoded_content": content, "content_type": content_type.upper(),
            "confidence": ai["confidence"], "why": ai["why"],
            "what_to_do": ai["what_to_do"], "how_to_avoid": ai["how_to_avoid"],
            "engine": "QR → TEXT AI"
        }
        await save_scan("qr", content[:200], verdict, ai["risk_score"], scan_meta(request))
        await set_cached_scan("qr", image_bytes, response)
        return response

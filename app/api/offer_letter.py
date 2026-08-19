from fastapi import APIRouter, UploadFile, File, HTTPException, Form, Request
import httpx
import os
from app.services.offer_letter_engine import (
    extract_text_from_pdf,
    extract_text_from_doc,
    run_full_analysis,
    run_vision_analysis,
)
from app.services.db_service import save_scan
from app.services.cache_service import get_cached_scan, set_cached_scan
from app.services.security import request_meta

router = APIRouter()

ALLOWED_TYPES = {
    "application/pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/msword": "doc",
}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


async def verify_recaptcha(token: str) -> bool:
    try:
        secret = os.getenv("RECAPTCHA_SECRET_KEY")
        async with httpx.AsyncClient(timeout=5) as client:
            res = await client.post(
                "https://www.googleapis.com/recaptcha/api/siteverify",
                data={"secret": secret, "response": token}
            )
            data = res.json()
            return data.get("success") and data.get("score", 0) >= 0.5
    except Exception as e:
        print(f"reCAPTCHA error: {e}")
        return True


@router.post("/check/offer-letter")
async def check_offer_letter(
    request: Request,
    file: UploadFile = File(...),
    recaptcha_token: str = Form(default="")
):
    is_human = await verify_recaptcha(recaptcha_token)
    if not is_human:
        raise HTTPException(status_code=400, detail="Bot detected. Please try again.")

    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(status_code=400, detail="Only PDF, DOC, or DOCX files are allowed.")

    file_bytes = await file.read()
    if len(file_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File size must be under 10MB.")

    file_type = ALLOWED_TYPES[file.content_type]
    cache_payload = {
        "file_type": file_type,
        "file_bytes": file_bytes,
    }
    cached = await get_cached_scan("offer_letter", cache_payload)
    if cached:
        cached["from_cache"] = True
        return cached

    if file_type == "pdf":
        extracted_text = extract_text_from_pdf(file_bytes)
    else:
        extracted_text = extract_text_from_doc(file_bytes)

    if not extracted_text or len(extracted_text.strip()) < 50:
        if file_type == "pdf":
            result = run_vision_analysis(file_bytes)
            await save_scan("offer_letter", file.filename or "unknown", result["verdict"], result["trust_score"], request_meta(request))
            await set_cached_scan("offer_letter", cache_payload, result)
            return result
        response = {
            "trust_score": 50,
            "confidence": "low",
            "verdict": "UNKNOWN",
            "verdict_detail": {
                "en": "Could not extract text. Please try a clearer file.",
                "hi": "टेक्स्ट नहीं निकाला जा सका। स्पष्ट फ़ाइल अपलोड करें।"
            },
            "categories": {},
            "red_flags": [],
            "safe_signals": [],
            "info_flags": [],
            "what_to_do": [
                {"en": "Upload a clearer PDF or DOCX file", "hi": "स्पष्ट PDF या DOCX फ़ाइल अपलोड करें"}
            ],
            "analysis_info": {"engine": "TEXT EXTRACT FAILED", "confidence": "low"}
        }
        await set_cached_scan("offer_letter", cache_payload, response)
        return response

    result = run_full_analysis(extracted_text, file_bytes, file_type)
    await save_scan("offer_letter", file.filename or "unknown", result["verdict"], result["trust_score"], request_meta(request))
    await set_cached_scan("offer_letter", cache_payload, result)
    return result

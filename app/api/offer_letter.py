from fastapi import APIRouter, UploadFile, File, HTTPException
from app.services.offer_letter_engine import (
    extract_text_from_pdf,
    extract_text_from_doc,
    run_full_analysis,
    run_vision_analysis,
)
from app.services.db_service import save_scan

router = APIRouter()

ALLOWED_TYPES = {
    "application/pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/msword": "doc",
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


@router.post("/check/offer-letter")
async def check_offer_letter(file: UploadFile = File(...)):
    """
    Offer Letter Trust Score API v3.0

    Trust Score (0-100):
      70+  = Likely Genuine
      50-70 = Needs Verification
      <50  = High Risk Scam

    Confidence: low / medium / high

    6 analysis layers:
      1. PDF metadata forensics
      2. Domain + WHOIS age check
      3. Context-based salary analysis
      4. Rule-based signal detection
      5. AI analysis (GPT-4o-mini)
      6. Soft weighted trust score calculator
    """

    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(status_code=400, detail="Only PDF, DOC, or DOCX files are allowed.")

    file_bytes = await file.read()

    if len(file_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File size must be under 10MB.")

    file_type = ALLOWED_TYPES[file.content_type]

    # Extract text
    if file_type == "pdf":
        extracted_text = extract_text_from_pdf(file_bytes)
    else:
        extracted_text = extract_text_from_doc(file_bytes)

    # Vision fallback for scanned PDFs
    if not extracted_text or len(extracted_text.strip()) < 50:
        if file_type == "pdf":
            result = run_vision_analysis(file_bytes)
            await save_scan("offer_letter", file.filename or "unknown", result["verdict"], result["trust_score"])
            return result

        return {
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

    # Full 6-layer analysis
    result = run_full_analysis(extracted_text, file_bytes, file_type)

    await save_scan("offer_letter", file.filename or "unknown", result["verdict"], result["trust_score"])

    return result

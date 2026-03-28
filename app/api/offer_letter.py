from fastapi import APIRouter, UploadFile, File, HTTPException
from app.services.offer_letter_engine import (
    extract_text_from_pdf,
    extract_text_from_doc,
    analyze_offer_letter_ai,
    analyze_offer_letter_pdf_vision
)
from app.services.db_service import save_scan

router = APIRouter()

ALLOWED_TYPES = {
    "application/pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/msword": "doc",
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


# ======================================================
# OFFER LETTER CHECK
# ======================================================
@router.post("/check/offer-letter")
async def check_offer_letter(file: UploadFile = File(...)):

    # Validate file type
    if file.content_type not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=400,
            detail="Only PDF, DOC, or DOCX files are allowed."
        )

    file_bytes = await file.read()

    # Validate file size
    if len(file_bytes) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail="File size must be under 10MB."
        )

    # Extract text based on file type
    file_type = ALLOWED_TYPES[file.content_type]

    if file_type == "pdf":
        extracted_text = extract_text_from_pdf(file_bytes)
    else:
        extracted_text = extract_text_from_doc(file_bytes)

    # If text extraction failed — Vision AI fallback
    if not extracted_text or len(extracted_text.strip()) < 50:
        if file_type == "pdf":
            ai = analyze_offer_letter_pdf_vision(file_bytes)
            verdict = "SCAM" if ai["risk_score"] >= 70 else "SUSPICIOUS" if ai["risk_score"] >= 31 else "SAFE"
            await save_scan("offer_letter", file.filename or "offer_letter", verdict, ai["risk_score"])
            return {
                "verdict": verdict,
                "confidence": ai["confidence"],
                "why": ai["why"],
                "what_to_do": ai["what_to_do"],
                "how_to_avoid": ai["how_to_avoid"],
                "engine": "OFFER LETTER VISION AI"
            }
        return {
            "verdict": "UNKNOWN",
            "confidence": {
                "en": "Could not extract enough text from the document. Please try a different file.",
                "hi": "दस्तावेज़ से पर्याप्त टेक्स्ट नहीं निकाला जा सका। कृपया दूसरी फ़ाइल आज़माएं।"
            },
            "why": [],
            "what_to_do": [
                {"en": "Make sure the PDF is not scanned/image-based", "hi": "सुनिश्चित करें कि PDF स्कैन की हुई न हो"}
            ],
            "how_to_avoid": [],
            "engine": "TEXT EXTRACT FAILED"
        }

    # AI Analysis
    ai = analyze_offer_letter_ai(extracted_text)

    # Verdict
    if ai["risk_score"] >= 70:
        verdict = "SCAM"
    elif ai["risk_score"] >= 31:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    await save_scan("offer_letter", file.filename or "offer_letter", verdict, ai["risk_score"])

    return {
        "verdict": verdict,
        "confidence": ai["confidence"],
        "why": ai["why"],
        "what_to_do": ai["what_to_do"],
        "how_to_avoid": ai["how_to_avoid"],
        "engine": f"OFFER LETTER AI ({file_type.upper()})"
    }

from fastapi import APIRouter, UploadFile, File, HTTPException
from app.services.offer_letter_engine import (
    extract_text_from_pdf,
    extract_text_from_doc,
    run_full_analysis,
    run_vision_analysis,
)
from app.services.db_service import save_scan
from app.services.notifier import send_failure_alert  # ← ADD THIS
import traceback                                        # ← ADD THIS

router = APIRouter()
ALLOWED_TYPES = {
    "application/pdf": "pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/msword": "doc",
}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

@router.post("/check/offer-letter")
async def check_offer_letter(file: UploadFile = File(...)):
    # ❌ Wrong file type
    if file.content_type not in ALLOWED_TYPES:
        send_failure_alert(        # ← ADD
            check_type="offer_letter",
            input_data=file.filename or "unknown",
            reason=f"Invalid file type: {file.content_type}",
        )
        raise HTTPException(status_code=400, detail="Only PDF, DOC, or DOCX files are allowed.")

    file_bytes = await file.read()

    # ❌ File too large
    if len(file_bytes) > MAX_FILE_SIZE:
        send_failure_alert(        # ← ADD
            check_type="offer_letter",
            input_data=file.filename or "unknown",
            reason=f"File too large: {len(file_bytes)} bytes",
        )
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

        send_failure_alert(        # ← ADD
            check_type="offer_letter",
            input_data=file.filename or "unknown",
            reason="Text extraction failed — unclear or empty file",
        )
        return {
            "trust_score": 50,
            "confidence": "low",
            "verdict": "UNKNOWN",
            # ... baaki sab same rehne do
        }

    # Full 6-layer analysis
    try:                           # ← ADD try/except
        result = run_full_analysis(extracted_text, file_bytes, file_type)
        await save_scan("offer_letter", file.filename or "unknown", result["verdict"], result["trust_score"])
        return result
    except Exception as e:         # ← ADD
        send_failure_alert(
            check_type="offer_letter",
            input_data=file.filename or "unknown",
            reason=f"Analysis engine crashed: {str(e)}",
            extra={"traceback": traceback.format_exc()}
        )
        raise HTTPException(status_code=500, detail="Analysis failed.")

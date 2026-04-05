from fastapi import APIRouter, UploadFile, File, HTTPException
from app.services.db_service import save_scan

router = APIRouter()

ALLOWED_IMAGE_TYPES = {
    "image/jpeg", "image/jpg", "image/png",
    "image/webp", "image/heic", "image/heif"
}

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


@router.post("/check/payment-screenshot")
async def check_payment_screenshot(file: UploadFile = File(...)):
    # Validate file type
    content_type = file.content_type or ""
    filename = (file.filename or "").lower()

    is_valid_type = content_type in ALLOWED_IMAGE_TYPES
    is_valid_ext = any(filename.endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".webp", ".heic"])

    if not is_valid_type and not is_valid_ext:
        raise HTTPException(
            status_code=400,
            detail="Only image files are allowed (JPEG, PNG, WebP)."
        )

    image_bytes = await file.read()

    if len(image_bytes) == 0:
        raise HTTPException(status_code=400, detail="Empty file uploaded.")

    if len(image_bytes) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File size must be under 10MB.")

    try:
        from app.services.payment_screenshot_engine import analyze_payment_screenshot
        result = await analyze_payment_screenshot(image_bytes)

        content_label = (
            result.get("detected_app", {}).get("name", "unknown")
            + " | "
            + str(result.get("extracted_fields", {}).get("amount", ""))
            + " | "
            + str(result.get("extracted_fields", {}).get("transaction_id", ""))
        )
        await save_scan(
            "payment_screenshot",
            content_label[:500],
            result["verdict"],
            result["risk_percentage"],
        )
        return result

    except Exception as e:
        print(f"PAYMENT SCREENSHOT ERROR: {e}")
        raise HTTPException(
            status_code=500,
            detail="Analysis failed. Please try again with a clearer screenshot."
        )

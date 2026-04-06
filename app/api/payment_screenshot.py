"""
Payment Screenshot API Router - ScamDekho
"""

import asyncio
import base64
import logging
import uuid
from fastapi import APIRouter, UploadFile, File, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.services.db_service import save_scan
from app.services.payment_screenshot_engine import analyze_payment_screenshot

logger   = logging.getLogger(__name__)
router   = APIRouter()
limiter  = Limiter(key_func=get_remote_address)

ALLOWED_MIME_TYPES = {
    "image/jpeg", "image/jpg", "image/png",
    "image/webp", "image/heic", "image/heif"
}
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".heic", ".heif"}
MAX_FILE_SIZE    = 10 * 1024 * 1024
MIN_FILE_SIZE    = 5  * 1024
ANALYSIS_TIMEOUT = 60
CHUNK_SIZE       = 64 * 1024

MAGIC_SIGNATURES = {
    b"\xff\xd8\xff":          "image/jpeg",
    b"\x89PNG\r\n\x1a\n":    "image/png",
    b"RIFF":                  "image/webp",
    b"\x00\x00\x00\x18ftyp": "image/heic",
    b"\x00\x00\x00\x1cftyp": "image/heic",
    b"ftypheic":              "image/heic",
    b"ftypheix":              "image/heic",
    b"ftypmif1":              "image/heif",
}


def get_real_mime_type(header_bytes: bytes) -> str | None:
    for magic, mime in MAGIC_SIGNATURES.items():
        if header_bytes[:len(magic)] == magic:
            if magic == b"RIFF" and header_bytes[8:12] != b"WEBP":
                continue
            return mime
    return None


@router.post("/check/payment-screenshot")
@limiter.limit("8/minute")
@limiter.limit("30/hour")
async def check_payment_screenshot(
    request: Request,
    file: UploadFile = File(...),
):
    request_id = str(uuid.uuid4())[:8]
    client_ip  = request.client.host if request.client else "unknown"
    logger.info(
        f"[{request_id}] Screenshot upload - "
        f"IP:{client_ip} file:{file.filename} type:{file.content_type}"
    )

    filename  = (file.filename or "").lower().strip()
    mime_type = (file.content_type or "").strip().lower()
    if not any(filename.endswith(ext) for ext in ALLOWED_EXTENSIONS):
        raise HTTPException(
            status_code=415,
            detail="Unsupported file type. Upload a JPEG, PNG, WebP or HEIC screenshot."
        )
    if mime_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported content type '{mime_type}'. Upload an image file."
        )

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_FILE_SIZE:
                raise HTTPException(status_code=413, detail="File too large. Maximum is 10MB.")
        except ValueError:
            pass

    chunks     = []
    total_size = 0
    try:
        while True:
            chunk = await file.read(CHUNK_SIZE)
            if not chunk:
                break
            total_size += len(chunk)
            if total_size > MAX_FILE_SIZE:
                raise HTTPException(status_code=413, detail="File exceeds 10MB limit.")
            chunks.append(chunk)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[{request_id}] File read error: {e}")
        raise HTTPException(status_code=400, detail="Could not read uploaded file.")

    image_bytes = b"".join(chunks)

    if total_size < MIN_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"File too small ({total_size} bytes). Upload a full screenshot (min 5KB)."
        )

    real_mime = get_real_mime_type(image_bytes[:20])
    if not real_mime:
        logger.warning(
            f"[{request_id}] BLOCKED: magic bytes mismatch - "
            f"claimed '{mime_type}' IP:{client_ip}"
        )
        raise HTTPException(
            status_code=415,
            detail="File content does not match an image. Only real image files are accepted."
        )

    try:
        result = await asyncio.wait_for(
            analyze_payment_screenshot(image_bytes),
            timeout=ANALYSIS_TIMEOUT
        )
    except asyncio.TimeoutError:
        logger.error(f"[{request_id}] Timed out after {ANALYSIS_TIMEOUT}s")
        raise HTTPException(
            status_code=504,
            detail="Analysis timed out. Try again with a smaller or clearer image."
        )
    except ValueError as e:
        logger.warning(f"[{request_id}] Validation error: {e}")
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logger.error(f"[{request_id}] Engine error: {type(e).__name__}: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="Analysis failed. Please try again with a clearer screenshot."
        )

    # ── Save to MongoDB with image ──────────────────────────────────────────
    try:
        fields = result.get("extracted_fields", {})
        app    = result.get("detected_app", {})

        content_label = " | ".join(filter(None, [
            app.get("name"),
            str(fields.get("amount") or ""),
            str(fields.get("transaction_id") or ""),
        ]))

        image_b64 = base64.b64encode(image_bytes).decode("utf-8")

        await save_scan(
            scan_type    = "payment_screenshot",
            content      = content_label[:500],
            verdict      = result.get("verdict", "UNKNOWN"),
            risk_score   = result.get("risk_percentage", 0),
            extra        = {
                "request_id":       request_id,
                "client_ip":        client_ip,
                "filename":         file.filename,
                "file_size_bytes":  total_size,
                "mime_type":        real_mime,
                "image_base64":     image_b64,
                "app_name":         app.get("name"),
                "app_key":          app.get("app_key"),
                "app_confidence":   app.get("detection_confidence"),
                "extracted_fields": fields,
                "reasons":          result.get("reasons", []),
                "visual_signals":   result.get("visual_signals", []),
            }
        )
    except Exception as e:
        logger.error(f"[{request_id}] DB save failed (non-fatal): {e}")
    # ────────────────────────────────────────────────────────────────────────

    logger.info(
        f"[{request_id}] verdict:{result.get('verdict')} "
        f"risk:{result.get('risk_percentage')}% "
        f"app:{result.get('detected_app', {}).get('name', '?')}"
    )
    return {**result, "_request_id": request_id}
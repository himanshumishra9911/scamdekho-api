"""
Payment Screenshot API Router — ScamDekho v2.1
Production-ready with all security fixes.
"""

import asyncio
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
MAX_FILE_SIZE    = 10 * 1024 * 1024   # 10 MB
MIN_FILE_SIZE    = 5  * 1024          # 5 KB
ANALYSIS_TIMEOUT = 60                 # seconds
CHUNK_SIZE       = 64 * 1024          # 64 KB

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
        f"[{request_id}] Screenshot upload — "
        f"IP:{client_ip} file:{file.filename} type:{file.content_type}"
    )

    # ── Step 1: Extension + MIME — AND logic (both must be valid) ────────
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

    # ── Step 2: Content-Length fast reject ───────────────────────────────
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_FILE_SIZE:
                raise HTTPException(status_code=413, detail="File too large. Maximum is 10MB.")
        except ValueError:
            pass

    # ── Step 3: Chunked read — prevents memory DoS ───────────────────────
    # FIXED: use await file.read(CHUNK_SIZE) — NOT async for chunk in file
    # The latter raises TypeError in FastAPI's UploadFile implementation
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

    # ── Step 4: Magic bytes — real content validation ─────────────────────
    real_mime = get_real_mime_type(image_bytes[:20])
    if not real_mime:
        logger.warning(
            f"[{request_id}] BLOCKED: magic bytes mismatch — "
            f"claimed '{mime_type}' IP:{client_ip}"
        )
        raise HTTPException(
            status_code=415,
            detail="File content does not match an image. Only real image files are accepted."
        )

    # ── Step 5: Analysis with timeout ────────────────────────────────────
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

    # ── Step 6: DB save — non-fatal (won't block user response) ──────────
    try:
        content_label = " | ".join(filter(None, [
            result.get("detected_app", {}).get("name"),
            str(result.get("extracted_fields", {}).get("amount") or ""),
            str(result.get("extracted_fields", {}).get("transaction_id") or ""),
        ]))
        await save_scan(
            "payment_screenshot",
            content_label[:500],
            result.get("verdict", "UNKNOWN"),       # FIXED: safe .get() — no KeyError crash
            result.get("risk_percentage", 0),        # FIXED: safe .get() — no KeyError crash
        )
    except Exception as e:
        logger.error(f"[{request_id}] DB save failed (non-fatal): {e}")

    # ── Step 7: Return ────────────────────────────────────────────────────
    logger.info(
        f"[{request_id}] verdict:{result.get('verdict')} "
        f"risk:{result.get('risk_percentage')}% "
        f"app:{result.get('detected_app', {}).get('name', '?')}"
    )
    return {**result, "_request_id": request_id}   # FIXED: non-mutating spread

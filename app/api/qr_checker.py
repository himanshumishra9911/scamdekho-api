import io
import re
import cv2
import numpy as np
from PIL import Image, ImageEnhance
from urllib.parse import unquote, parse_qs, urlparse
from app.api.upi_checker import VALID_BANK_HANDLES

# WeChatQRCode is 10x better than cv2.QRCodeDetector for real photos
# Available in opencv-contrib-python (no system deps needed)
try:
    _wechat = cv2.wechat_qrcode.WeChatQRCode()
    HAS_WECHAT = True
except Exception:
    HAS_WECHAT = False

SUSPICIOUS_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "rb.gy", "cutt.ly", "is.gd", "v.gd", "shorturl.at",
    "tiny.cc", "t2m.io", "shorte.st", "bc.vc", "adf.ly",
}


# ── Decoder helpers ──────────────────────────────────────────

def _try_wechat(img: np.ndarray) -> str:
    """WeChatQRCode — handles angles, noise, real-world photos."""
    if not HAS_WECHAT:
        return ""
    try:
        results, _ = _wechat.detectAndDecode(img)
        for r in results:
            if r and r.strip():
                return r.strip()
    except Exception:
        pass
    return ""


def _try_cv2(detector, img: np.ndarray) -> str:
    """Fallback OpenCV QRCodeDetector."""
    try:
        content, pts, _ = detector.detectAndDecode(img)
        if content and content.strip():
            return content.strip()
    except Exception:
        pass
    return ""


# ── Preprocessing ────────────────────────────────────────────

def _preprocess_variants(img: np.ndarray) -> list:
    """Generate 20+ preprocessed versions for maximum decode chance."""
    variants = []
    h, w = img.shape[:2]
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # 1. original color
    variants.append(img)
    # 2. grayscale
    variants.append(gray)

    # 3. CLAHE contrast boost
    clahe = cv2.createCLAHE(clipLimit=3.0, tileGridSize=(8, 8))
    variants.append(clahe.apply(gray))

    # 4. Otsu threshold
    _, otsu = cv2.threshold(gray, 0, 255,
                            cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    variants.append(otsu)

    # 5. adaptive mean threshold
    variants.append(cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_MEAN_C,
        cv2.THRESH_BINARY, 51, 10))

    # 6. adaptive gaussian threshold
    variants.append(cv2.adaptiveThreshold(
        gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY, 51, 10))

    # 7. sharpen
    kernel = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
    variants.append(cv2.filter2D(gray, -1, kernel))

    # 8. blur → Otsu (noise reduction first)
    blurred = cv2.GaussianBlur(gray, (5, 5), 0)
    _, blur_otsu = cv2.threshold(blurred, 0, 255,
                                 cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    variants.append(blur_otsu)

    # 9. morphological close → Otsu (fills small gaps in QR)
    k3 = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
    closed = cv2.morphologyEx(gray, cv2.MORPH_CLOSE, k3)
    _, closed_otsu = cv2.threshold(closed, 0, 255,
                                   cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    variants.append(closed_otsu)

    # 10. inverted (white-on-black QR)
    variants.append(cv2.bitwise_not(gray))

    # 11. PIL high contrast + sharpen
    try:
        pil = Image.fromarray(cv2.cvtColor(img, cv2.COLOR_BGR2RGB))
        pil = ImageEnhance.Contrast(pil).enhance(2.0)
        pil = ImageEnhance.Sharpness(pil).enhance(2.0)
        hi = cv2.cvtColor(np.array(pil), cv2.COLOR_RGB2BGR)
        variants.append(hi)
        variants.append(cv2.cvtColor(hi, cv2.COLOR_BGR2GRAY))
    except Exception:
        pass

    # 12-14. 2× upscale variants (small/distant QR codes)
    big = cv2.resize(img, (w * 2, h * 2),
                     interpolation=cv2.INTER_CUBIC)
    variants.append(big)
    big_gray = cv2.cvtColor(big, cv2.COLOR_BGR2GRAY)
    variants.append(clahe.apply(big_gray))
    _, big_otsu = cv2.threshold(big_gray, 0, 255,
                                cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    variants.append(big_otsu)

    # 15-20. multiple fixed thresholds (handles varying lighting)
    for t in [80, 100, 120, 140, 160, 180]:
        _, fixed = cv2.threshold(gray, t, 255, cv2.THRESH_BINARY)
        variants.append(fixed)

    return variants


# ── Perspective correction ───────────────────────────────────

def _try_perspective_correction(img: np.ndarray):
    """Find largest square-ish contour and warp to flat square."""
    try:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        blurred = cv2.GaussianBlur(gray, (5, 5), 0)
        edges = cv2.Canny(blurred, 50, 150)
        k5 = cv2.getStructuringElement(cv2.MORPH_RECT, (5, 5))
        dilated = cv2.dilate(edges, k5, iterations=2)

        contours, _ = cv2.findContours(
            dilated, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        if not contours:
            return None

        h, w = img.shape[:2]
        img_area = h * w
        best, best_area = None, 0

        for cnt in contours:
            area = cv2.contourArea(cnt)
            if area < img_area * 0.05 or area > img_area * 0.95:
                continue
            peri = cv2.arcLength(cnt, True)
            approx = cv2.approxPolyDP(cnt, 0.05 * peri, True)
            if len(approx) == 4 and area > best_area:
                rect = cv2.minAreaRect(cnt)
                rw, rh = rect[1]
                if rw > 0 and rh > 0:
                    if max(rw, rh) / min(rw, rh) < 2.0:
                        best, best_area = approx, area

        if best is None:
            return None

        pts = best.reshape(4, 2).astype(np.float32)
        s = pts.sum(axis=1)
        d = np.diff(pts, axis=1)
        ordered = np.zeros((4, 2), dtype=np.float32)
        ordered[0] = pts[np.argmin(s)]
        ordered[2] = pts[np.argmax(s)]
        ordered[1] = pts[np.argmin(d)]
        ordered[3] = pts[np.argmax(d)]

        side = int(max(
            np.linalg.norm(ordered[1] - ordered[0]),
            np.linalg.norm(ordered[2] - ordered[1]),
            np.linalg.norm(ordered[3] - ordered[2]),
            np.linalg.norm(ordered[0] - ordered[3]),
        ))
        if side < 100:
            side = 400

        dst = np.array(
            [[0, 0], [side, 0], [side, side], [0, side]],
            dtype=np.float32)
        M = cv2.getPerspectiveTransform(ordered, dst)
        return cv2.warpPerspective(img, M, (side, side))
    except Exception:
        return None


# ── Main decoder ─────────────────────────────────────────────

def decode_qr_image(image_bytes: bytes) -> dict:
    try:
        # Load image
        img_array = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)

        if img is None:
            try:
                pil_img = Image.open(io.BytesIO(image_bytes))
                img = cv2.cvtColor(
                    np.array(pil_img.convert("RGB")),
                    cv2.COLOR_RGB2BGR)
            except Exception:
                return {"success": False,
                        "error": "Could not read image file"}

        if img is None:
            return {"success": False,
                    "error": "Could not read image file"}

        content = None
        variants = _preprocess_variants(img)

        # ── Pass 1: WeChatQRCode on all variants (BEST decoder) ──
        if HAS_WECHAT:
            for v in variants:
                content = _try_wechat(v)
                if content:
                    break

        # ── Pass 2: OpenCV QRCodeDetector fallback ──
        if not content:
            detector = cv2.QRCodeDetector()
            for v in variants:
                content = _try_cv2(detector, v)
                if content:
                    break

        # ── Pass 3: perspective correction → try again ──
        if not content:
            corrected = _try_perspective_correction(img)
            if corrected is not None:
                if HAS_WECHAT:
                    content = _try_wechat(corrected)
                if not content:
                    detector = cv2.QRCodeDetector()
                    content = _try_cv2(detector, corrected)
                if not content:
                    cg = cv2.cvtColor(corrected, cv2.COLOR_BGR2GRAY)
                    _, co = cv2.threshold(
                        cg, 0, 255,
                        cv2.THRESH_BINARY + cv2.THRESH_OTSU)
                    if HAS_WECHAT:
                        content = _try_wechat(co)
                    if not content:
                        content = _try_cv2(
                            cv2.QRCodeDetector(), co)

        if not content:
            return {"success": False,
                    "error": "Could not read QR/Barcode from image"}

        return _parse_qr_content(content)

    except Exception as e:
        return {"success": False, "error": str(e)}


# ── Parse QR content ─────────────────────────────────────────

def _parse_qr_content(content: str) -> dict:
    content_lower = content.lower().strip()

    # UPI deep link
    if content_lower.startswith("upi://"):
        try:
            parsed = urlparse(content)
            params = parse_qs(parsed.query)

            upi_id = unquote(
                params.get("pa", [""])[0]).strip().lower()
            payee_name = unquote(
                params.get("pn", [""])[0]).strip()
            amount_raw = params.get("am", [None])[0]
            note = unquote(
                params.get("tn", [""])[0]).strip()
            merchant_code = params.get("mc", [None])[0]

            amount = None
            if amount_raw:
                try:
                    amount = float(amount_raw)
                except ValueError:
                    pass

            return {
                "success": True,
                "content": content,
                "content_type": "upi",
                "upi_id": upi_id or None,
                "payee_name": payee_name or None,
                "amount": amount,
                "note": note or None,
                "is_merchant": merchant_code is not None,
                "qr_type": "QRCODE"
            }
        except Exception:
            pass

    # URL
    if (content_lower.startswith("http://")
            or content_lower.startswith("https://")):
        try:
            parsed = urlparse(content)
            domain = parsed.netloc.lower().replace("www.", "")
            is_shortened = any(
                s in domain for s in SUSPICIOUS_SHORTENERS)
            return {
                "success": True,
                "content": content,
                "content_type": "url",
                "url_domain": domain,
                "url_shortened": is_shortened,
                "qr_type": "QRCODE"
            }
        except Exception:
            pass

    # Phone
    if content_lower.startswith("tel:"):
        return {
            "success": True,
            "content": content,
            "content_type": "phone",
            "qr_type": "QRCODE"
        }

    # Plain UPI ID
    if "@" in content and len(content.split("@")) == 2:
        handle = content.split("@")[1].lower().strip()
        if handle in VALID_BANK_HANDLES:
            return {
                "success": True,
                "content": content,
                "content_type": "upi",
                "upi_id": content.lower(),
                "payee_name": None,
                "amount": None,
                "is_merchant": False,
                "qr_type": "QRCODE"
            }
        else:
            return {
                "success": True,
                "content": content,
                "content_type": "text",
                "qr_type": "QRCODE"
            }

    # Generic text
    return {
        "success": True,
        "content": content,
        "content_type": "text",
        "qr_type": "QRCODE"
    }

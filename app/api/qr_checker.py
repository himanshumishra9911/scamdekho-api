import io
import re
import cv2
import numpy as np
from PIL import Image
from urllib.parse import unquote, parse_qs, urlparse
from app.api.upi_checker import VALID_BANK_HANDLES

SUSPICIOUS_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "rb.gy", "cutt.ly", "is.gd", "v.gd", "shorturl.at",
    "tiny.cc", "t2m.io", "shorte.st", "bc.vc", "adf.ly",
}


def decode_qr_image(image_bytes: bytes) -> dict:
    try:
        img_array = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)

        if img is None:
            # PIL se try karo
            try:
                pil_img = Image.open(io.BytesIO(image_bytes))
                img_array2 = np.array(pil_img.convert("RGB"))
                img = cv2.cvtColor(img_array2, cv2.COLOR_RGB2BGR)
            except Exception:
                return {"success": False, "error": "Could not read image file"}

        content = None
        qr_detector = cv2.QRCodeDetector()

        # Method 1: color
        content, _, _ = qr_detector.detectAndDecode(img)

        # Method 2: grayscale
        if not content:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            content, _, _ = qr_detector.detectAndDecode(gray)

        # Method 3: CLAHE contrast enhance
        if not content:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            enhanced = clahe.apply(gray)
            content, _, _ = qr_detector.detectAndDecode(enhanced)

        # Method 4: 2x upscale
        if not content:
            h, w = img.shape[:2]
            big = cv2.resize(img, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
            content, _, _ = qr_detector.detectAndDecode(big)

        # Method 5: sharpen
        if not content:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            kernel = np.array([[0, -1, 0], [-1, 5, -1], [0, -1, 0]])
            sharpened = cv2.filter2D(gray, -1, kernel)
            content, _, _ = qr_detector.detectAndDecode(sharpened)

        if not content:
            return {"success": False, "error": "No QR code found. Try a clearer photo."}

        content = content.strip()
        return _parse_qr_content(content)

    except Exception as e:
        return {"success": False, "error": str(e)}


def _parse_qr_content(content: str) -> dict:
    content_lower = content.lower().strip()

    # UPI deep link
    if content_lower.startswith("upi://"):
        try:
            parsed = urlparse(content)
            params = parse_qs(parsed.query)

            upi_id = unquote(params.get("pa", [""])[0]).strip().lower()
            payee_name = unquote(params.get("pn", [""])[0]).strip()
            amount_raw = params.get("am", [None])[0]
            note = unquote(params.get("tn", [""])[0]).strip()
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
    if content_lower.startswith("http://") or content_lower.startswith("https://"):
        try:
            parsed = urlparse(content)
            domain = parsed.netloc.lower().replace("www.", "")
            is_shortened = any(s in domain for s in SUSPICIOUS_SHORTENERS)
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

    # FIX: Plain UPI ID — handle validate karo pehle (email routing bug fix)
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
            # Email ya unknown handle — text treat karo
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

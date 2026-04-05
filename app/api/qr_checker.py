import io
import re
import cv2
import numpy as np
from PIL import Image
from urllib.parse import unquote, parse_qs, urlparse

# Known bank handles — UPI routing ke liye
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
            # PIL se try karo agar OpenCV read nahi kar paya
            try:
                pil_img = Image.open(io.BytesIO(image_bytes))
                img_array2 = np.array(pil_img.convert("RGB"))
                img = cv2.cvtColor(img_array2, cv2.COLOR_RGB2BGR)
            except Exception:
                return {"success": False, "error": "Could not read image file"}

        content = None

        # Method 1: OpenCV — color
        qr_detector = cv2.QRCodeDetector()
        content, _, _ = qr_detector.detectAndDecode(img)

        # Method 2: OpenCV — grayscale
        if not content:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            content, _, _ = qr_detector.detectAndDecode(gray)

        # Method 3: OpenCV — contrast enhanced
        if not content:
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
            enhanced = clahe.apply(gray)
            content, _, _ = qr_detector.detectAndDecode(enhanced)

        # Method 4: pyzbar fallback — sabse accurate
        if not content:
            try:
                from pyzbar.pyzbar import decode as pyzbar_decode
                pil_img = Image.open(io.BytesIO(image_bytes))
                decoded_list = pyzbar_decode(pil_img)
                if decoded_list:
                    content = decoded_list[0].data.decode("utf-8", errors="replace")
            except ImportError:
                pass  # pyzbar install nahi — OpenCV pe hi depend karo
            except Exception:
                pass

        # Method 5: pyzbar — upscaled image (blurry/small QR ke liye)
        if not content:
            try:
                from pyzbar.pyzbar import decode as pyzbar_decode
                pil_img = Image.open(io.BytesIO(image_bytes))
                # 2x upscale karo — door se li gayi photos ke liye
                w, h = pil_img.size
                pil_big = pil_img.resize((w * 2, h * 2), Image.LANCZOS)
                decoded_list = pyzbar_decode(pil_big)
                if decoded_list:
                    content = decoded_list[0].data.decode("utf-8", errors="replace")
            except Exception:
                pass

        if not content:
            return {"success": False, "error": "No QR code found in image. Try a clearer photo."}

        content = content.strip()
        return _parse_qr_content(content)

    except Exception as e:
        return {"success": False, "error": str(e)}


def _parse_qr_content(content: str) -> dict:
    """
    QR content parse karo aur sab fields extract karo.
    FIX: Email routing bug solve kiya — sirf valid UPI handles route karo.
    FIX: UPI deep link se pn/am/tn/mc bhi extract karo.
    """
    content_lower = content.lower().strip()

    # ── UPI deep link: upi://pay?pa=...&pn=...&am=... ──
    if content_lower.startswith("upi://"):
        try:
            parsed = urlparse(content)
            params = parse_qs(parsed.query)

            upi_id = unquote(params.get("pa", [""])[0]).strip().lower()
            payee_name = unquote(params.get("pn", [""])[0]).strip()
            amount_raw = params.get("am", [None])[0]
            note = unquote(params.get("tn", [""])[0]).strip()
            merchant_code = params.get("mc", [None])[0]
            currency = params.get("cu", ["INR"])[0]

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
                "merchant_code": merchant_code,
                "currency": currency,
                "qr_type": "QRCODE"
            }
        except Exception:
            pass

    # ── URL ──
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

    # ── Phone ──
    if content_lower.startswith("tel:"):
        return {
            "success": True,
            "content": content,
            "content_type": "phone",
            "qr_type": "QRCODE"
        }

    # ── Plain UPI ID — FIX: handle validate karo pehle ──
    # Email aur UPI dono mein "@" hota hai — is bug ko fix kiya
    if "@" in content and len(content.split("@")) == 2:
        handle = content.split("@")[1].lower().strip()
        if handle in VALID_BANK_HANDLES:
            # Valid bank handle confirm hua — ye UPI ID hai
            return {
                "success": True,
                "content": content,
                "content_type": "upi",
                "upi_id": content.lower(),
                "payee_name": None,
                "amount": None,
                "note": None,
                "is_merchant": False,
                "qr_type": "QRCODE"
            }
        else:
            # Unknown handle ya email — text ke roop mein treat karo
            return {
                "success": True,
                "content": content,
                "content_type": "text",
                "qr_type": "QRCODE"
            }

    # ── Generic text ──
    return {
        "success": True,
        "content": content,
        "content_type": "text",
        "qr_type": "QRCODE"
    }

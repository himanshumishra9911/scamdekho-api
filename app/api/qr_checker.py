import io
import re
import cv2
import numpy as np
from PIL import Image


def decode_qr_image(image_bytes: bytes) -> dict:
    try:
        # Bytes to numpy array
        img_array = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(img_array, cv2.IMREAD_COLOR)

        if img is None:
            return {"success": False, "error": "Could not read image"}

        # QR Code detector
        qr_detector = cv2.QRCodeDetector()
        content, points, _ = qr_detector.detectAndDecode(img)

        if not content:
            # Try grayscale
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            content, points, _ = qr_detector.detectAndDecode(gray)

        if not content:
            return {"success": False, "error": "No QR/Barcode found in image"}

        content = content.strip()

        # Content type detect karo
        if content.startswith("upi://"):
            match = re.search(r"pa=([^&]+)", content)
            upi_id = match.group(1) if match else None
            return {
                "success": True,
                "content": content,
                "content_type": "upi",
                "upi_id": upi_id,
                "qr_type": "QRCODE"
            }
        elif content.startswith("http://") or content.startswith("https://"):
            return {
                "success": True,
                "content": content,
                "content_type": "url",
                "qr_type": "QRCODE"
            }
        elif content.startswith("tel:"):
            return {
                "success": True,
                "content": content,
                "content_type": "phone",
                "qr_type": "QRCODE"
            }
        elif "@" in content and len(content.split("@")) == 2:
            return {
                "success": True,
                "content": content,
                "content_type": "upi",
                "upi_id": content,
                "qr_type": "QRCODE"
            }
        else:
            return {
                "success": True,
                "content": content,
                "content_type": "text",
                "qr_type": "QRCODE"
            }

    except Exception as e:
        return {"success": False, "error": str(e)}

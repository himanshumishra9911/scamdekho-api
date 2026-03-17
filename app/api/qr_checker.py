import io
import re
from PIL import Image
from pyzbar.pyzbar import decode as qr_decode


def decode_qr_image(image_bytes: bytes) -> dict:
    try:
        img = Image.open(io.BytesIO(image_bytes))
        decoded = qr_decode(img)

        if not decoded:
            return {"success": False, "error": "No QR/Barcode found in image"}

        content = decoded[0].data.decode("utf-8").strip()
        qr_type = decoded[0].type  # QRCODE, EAN13, CODE128 etc.

        # Content type detect karo
        if content.startswith("upi://"):
            # Extract UPI ID from UPI deep link
            match = re.search(r"pa=([^&]+)", content)
            upi_id = match.group(1) if match else None
            return {
                "success": True,
                "content": content,
                "content_type": "upi",
                "upi_id": upi_id,
                "qr_type": qr_type
            }
        elif content.startswith("http://") or content.startswith("https://"):
            return {
                "success": True,
                "content": content,
                "content_type": "url",
                "qr_type": qr_type
            }
        elif content.startswith("tel:"):
            return {
                "success": True,
                "content": content,
                "content_type": "phone",
                "qr_type": qr_type
            }
        elif "@" in content and "." not in content.split("@")[0]:
            # Looks like UPI ID directly
            return {
                "success": True,
                "content": content,
                "content_type": "upi",
                "upi_id": content,
                "qr_type": qr_type
            }
        else:
            return {
                "success": True,
                "content": content,
                "content_type": "text",
                "qr_type": qr_type
            }

    except Exception as e:
        return {"success": False, "error": str(e)}

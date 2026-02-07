import pytesseract
from PIL import Image
import io

def extract_text_from_image(image_bytes: bytes) -> str:
    """
    Extract text from image bytes using Tesseract OCR
    """

    try:
        image = Image.open(io.BytesIO(image_bytes))
        text = pytesseract.image_to_string(image)
        return text.strip()
    except Exception:
        return ""
from fastapi import UploadFile, File
from app.services.ocr_engine import extract_text_from_image
from app.services.ai_engine import call_ai_analysis



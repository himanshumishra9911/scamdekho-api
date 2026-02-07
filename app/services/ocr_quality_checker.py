def is_ocr_text_reliable(text: str):

    if not text:
        return False

    text = text.strip()

    # Too small text → unreliable
    if len(text) < 20:
        return False

    # Too many symbols → unreliable
    weird_chars = sum(1 for c in text if c in "@#$%^&*")
    ratio = weird_chars / max(len(text), 1)

    if ratio > 0.25:
        return False

    return True

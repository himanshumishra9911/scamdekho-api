import re

def clean_text(text: str) -> str:
    """
    Normalize text for scam analysis
    """
    text = text.lower()
    text = re.sub(r"http\S+", "", text)   # remove URLs
    text = re.sub(r"[^a-z0-9\s]", "", text)  # remove special chars
    text = re.sub(r"\s+", " ", text)  # extra spaces
    return text.strip()
def detect_language(text: str) -> str:
    # Hindi unicode range
    if any('\u0900' <= ch <= '\u097F' for ch in text):
        return "hi"
    return "en"
import re

def is_all_caps_ratio(text: str, threshold: float = 0.6) -> bool:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return False
    caps = [c for c in letters if c.isupper()]
    return (len(caps) / len(letters)) >= threshold

def has_excessive_symbols(text: str) -> bool:
    return bool(re.search(r"[!$]{3,}", text))

def has_suspicious_numbers(text: str) -> bool:
    # OTP (4–6 digits) or phone-like patterns
    return bool(re.search(r"\b\d{4,6}\b", text))

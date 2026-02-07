def ocr_quality_adjustment(text: str):

    if not text:
        return 5

    length = len(text)

    if length < 25:
        return -5

    return 0

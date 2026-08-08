from app.api.payment_screenshot import get_real_mime_type


def test_heic_detection_does_not_depend_on_one_box_size():
    assert get_real_mime_type(b"\x00\x00\x00\x20ftypheic" + b"\x00" * 8) == "image/heic"


def test_heif_and_avif_major_brands_are_supported():
    assert get_real_mime_type(b"\x00\x00\x00\x18ftypmif1" + b"\x00" * 8) == "image/heif"
    assert get_real_mime_type(b"\x00\x00\x00\x1cftypavif" + b"\x00" * 8) == "image/avif"


def test_non_webp_riff_is_not_accepted_as_an_image():
    assert get_real_mime_type(b"RIFF\x00\x00\x00\x00WAVE") is None

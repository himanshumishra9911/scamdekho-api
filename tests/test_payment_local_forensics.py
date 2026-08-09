import asyncio
import io
from pathlib import Path

import numpy as np
from PIL import Image

import app.services.payment_local_forensics as local_forensics
import app.services.payment_screenshot_engine as engine
from app.services.payment_local_forensics import (
    _explicit_overlay_term,
    _large_attention_overlay,
    _magenta_text_overlay,
    analyze_local_forensics,
    hamming_distance,
)


DATASET_ROOT = Path(__file__).parent / "payment_screenshot_dataset" / "calibration"
KNOWN_FAKE = (
    DATASET_ROOT
    / "fake"
    / "phonepe"
    / "phonepe-20260809-reviewcraft-generated.png"
)


def test_hamming_distance_counts_different_bits():
    assert hamming_distance("0000000000000000", "000000000000000f") == 4


def test_explicit_fabrication_and_warning_overlay_words_are_read():
    assert _explicit_overlay_term("PHONEPE SCREENSHOT GENERATOR") == "generator"
    assert _explicit_overlay_term("FAKE!") == "fake"
    assert _explicit_overlay_term("PhonePe scam se savdhan rahe") == "scam"
    assert _explicit_overlay_term("TEST   PAYMENT") == "test payment"
    assert _explicit_overlay_term("Payment successful") is None


def test_large_magenta_annotation_is_an_attention_candidate():
    rgb = np.full((700, 400, 3), 255, dtype=np.uint8)
    rgb[500:550, 70:340] = (230, 20, 150)

    candidate, area_ratio = _large_attention_overlay(rgb)

    assert candidate is True
    assert area_ratio >= 0.008


def test_many_small_magenta_glyphs_are_a_text_overlay_candidate():
    rgb = np.full((700, 400, 3), 255, dtype=np.uint8)
    for row in range(3):
        for column in range(10):
            x = 50 + column * 30
            y = 420 + row * 35
            rgb[y : y + 20, x : x + 10] = (230, 20, 150)

    candidate, area_ratio = _magenta_text_overlay(rgb)

    assert candidate is True
    assert area_ratio >= 0.012


def test_solid_magenta_promotion_is_not_a_text_overlay_candidate():
    rgb = np.full((700, 400, 3), 255, dtype=np.uint8)
    rgb[420:540, 50:350] = (230, 20, 150)

    candidate, _ = _magenta_text_overlay(rgb)

    assert candidate is False


def test_warning_annotation_is_queued_for_suspicious_floor_not_known_fake(
    monkeypatch,
):
    image = Image.new("RGB", (400, 700), "white")
    output = io.BytesIO()
    image.save(output, format="PNG")
    monkeypatch.setattr(local_forensics, "load_known_fake_signatures", lambda: ())
    monkeypatch.setattr(local_forensics, "_large_red_overlay", lambda rgb: (False, 0.0))
    monkeypatch.setattr(
        local_forensics, "_large_attention_overlay", lambda rgb: (True, 0.02)
    )
    monkeypatch.setattr(
        local_forensics, "_ocr_attention_overlay", lambda rgb: "scam"
    )

    result = analyze_local_forensics(output.getvalue())

    assert result.known_fake is None
    assert result.annotation_overlay_term == "scam"
    assert result.needs_overlay_floor is True
    assert result.force_review is False


def test_confirmed_fake_exact_hash_is_detected_locally():
    result = analyze_local_forensics(KNOWN_FAKE.read_bytes())

    assert result.known_fake is not None
    assert result.known_fake.signature_id == "reviewcraft-phonepe-clone-v1"
    assert result.known_fake.method == "exact_sha256"


def test_confirmed_fake_resize_and_reencode_uses_joint_perceptual_match():
    with Image.open(KNOWN_FAKE) as image:
        transformed = image.convert("RGB").resize((635, 995))
        output = io.BytesIO()
        transformed.save(output, format="JPEG", quality=88)

    result = analyze_local_forensics(output.getvalue())

    assert result.known_fake is not None
    assert result.known_fake.signature_id == "reviewcraft-phonepe-clone-v1"
    assert result.known_fake.method == "joint_perceptual_hash"


def test_all_genuine_calibration_images_clear_known_fake_and_overlay_checks():
    genuine_paths = sorted((DATASET_ROOT / "genuine").rglob("*.png"))
    assert len(genuine_paths) >= 16

    for path in genuine_paths:
        result = analyze_local_forensics(path.read_bytes())
        assert result.known_fake is None, path.name
        assert result.red_overlay_candidate is False, path.name
        assert result.magenta_text_overlay_candidate is False, path.name


def test_known_fake_short_circuits_all_paid_model_calls(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("OpenAI must not run for a known-fake signature")

    monkeypatch.setattr(engine, "_run_model", fail_if_called)
    monkeypatch.setattr(engine, "_run_replica_triage", fail_if_called)

    result = asyncio.run(engine.analyze_payment_screenshot(KNOWN_FAKE.read_bytes()))

    assert result["verdict"] == "SCAM"
    assert result["risk_percentage"] == 99
    assert result["safety_percentage"] == 1
    assert result["score_breakdown"]["safety_indicator"] == 1
    assert result["score_breakdown"]["is_calibrated_probability"] is False
    assert result["ensemble"]["attempted_passes"] == 0
    assert result["model_usage"]["request_estimated_cost_usd"] == 0

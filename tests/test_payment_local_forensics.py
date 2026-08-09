import asyncio
import io
from pathlib import Path

from PIL import Image

import app.services.payment_screenshot_engine as engine
from app.services.payment_local_forensics import (
    _explicit_overlay_term,
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


def test_only_explicit_fake_overlay_words_are_promoted():
    assert _explicit_overlay_term("PHONEPE SCREENSHOT GENERATOR") == "generator"
    assert _explicit_overlay_term("FAKE!") == "fake"
    assert _explicit_overlay_term("Payment successful") is None


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


def test_known_fake_short_circuits_all_paid_model_calls(monkeypatch):
    def fail_if_called(*args, **kwargs):
        raise AssertionError("OpenAI must not run for a known-fake signature")

    monkeypatch.setattr(engine, "_run_model", fail_if_called)
    monkeypatch.setattr(engine, "_run_replica_triage", fail_if_called)

    result = asyncio.run(engine.analyze_payment_screenshot(KNOWN_FAKE.read_bytes()))

    assert result["verdict"] == "SCAM"
    assert result["risk_percentage"] == 99
    assert result["safety_percentage"] == 1
    assert result["ensemble"]["attempted_passes"] == 0
    assert result["model_usage"]["request_estimated_cost_usd"] == 0

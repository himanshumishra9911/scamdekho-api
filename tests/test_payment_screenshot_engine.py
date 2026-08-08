import asyncio
import io

import pytest
from PIL import Image

from app.services.payment_screenshot_engine import (
    PaymentObservation,
    SYSTEM_PROMPT,
    _needs_review,
    _prepare_image,
    calibrate_observations,
)
import app.services.payment_screenshot_engine as engine


def observation(**overrides) -> PaymentObservation:
    data = {
        "app_name": "Google Pay",
        "app_key": "google_pay",
        "app_confidence": 95,
        "screenshot_kind": "payment_success",
        "readability": "clear",
        "payment_state": "success",
        "fields": {
            "amount": "500",
            "transaction_id": "123456789012",
            "upi_id": "merchant@paytm",
            "recipient_name": "Example Store",
            "sender_name": None,
            "bank_name": None,
            "timestamp": "10:30 AM, 08 Aug 2026",
            "status_text": "Paid successfully",
        },
        "tampering_evidence": [],
        "impossible_inconsistencies": [],
        "benign_limitations": [],
        "content_risk_signals": [],
        "authenticity_assessment": "no_evidence_of_manipulation",
        "fake_probability": 12,
        "confidence": "high",
        "reasons": ["No visible editing artifacts"],
    }
    data.update(overrides)
    return PaymentObservation(**data)


def test_missing_fields_and_scam_words_do_not_make_genuine_pixels_fake():
    item = observation(
        app_name="Unknown",
        app_key="unknown",
        app_confidence=15,
        fields={
            "amount": "750",
            "transaction_id": None,
            "upi_id": "refund.support@bank",
            "recipient_name": "Refund Support",
            "sender_name": None,
            "bank_name": None,
            "timestamp": None,
            "status_text": "Success",
        },
        benign_limitations=["The screenshot is cropped"],
        content_risk_signals=["The recipient name contains support/refund wording"],
        fake_probability=18,
    )

    result = calibrate_observations([item])

    assert result["verdict"] == "SAFE"
    assert result["content_risk_signals"]
    assert result["risk_percentage"] <= 30


def test_prompt_protects_common_genuine_receipt_variants_from_false_positives():
    prompt = SYSTEM_PROMPT.lower()

    for benign_variant in (
        "masked identifiers",
        "minimal share receipts",
        "viewer margins",
        "ads",
        "rewards panels",
        "alphanumeric reference",
        "cross-app upi handles or branding",
    ):
        assert benign_variant in prompt


def test_one_weak_visual_anomaly_is_not_enough_for_suspicious():
    item = observation(
        tampering_evidence=[
            {
                "category": "typography",
                "strength": "weak",
                "description": "One label may use a slightly different weight",
                "location": "lower half",
                "observed_text": "Paid",
            }
        ],
        fake_probability=20,
    )

    assert calibrate_observations([item])["verdict"] == "SAFE"


def test_multiple_moderate_anomalies_are_inconclusive_not_scam():
    item = observation(
        tampering_evidence=[
            {
                "category": "alignment",
                "strength": "moderate",
                "description": "Amount baseline differs from adjacent text",
                "location": "amount row",
                "observed_text": "₹500",
            },
            {
                "category": "pixel_artifact",
                "strength": "moderate",
                "description": "Possible rectangular compression boundary",
                "location": "recipient row",
                "observed_text": "Example Store",
            },
        ],
        authenticity_assessment="uncertain",
        fake_probability=58,
    )

    assert calibrate_observations([item])["verdict"] == "SUSPICIOUS"


def test_clear_localized_manipulation_is_scam():
    item = observation(
        tampering_evidence=[
            {
                "category": "overlay",
                "strength": "strong",
                "description": "Hard rectangular paste boundary surrounds the amount",
                "location": "amount row",
                "observed_text": "₹5,000",
            }
        ],
        authenticity_assessment="clear_manipulation",
        fake_probability=91,
    )

    result = calibrate_observations([item])

    assert result["verdict"] == "SCAM"
    assert result["risk_percentage"] >= 70
    assert result["pattern_match"]["found"] is True


def test_disagreeing_review_never_marks_screenshot_safe_or_scam():
    primary = observation(
        tampering_evidence=[
            {
                "category": "overlay",
                "strength": "strong",
                "description": "Possible pasted amount",
                "location": "amount row",
                "observed_text": "₹5,000",
            }
        ],
        authenticity_assessment="clear_manipulation",
        fake_probability=88,
    )
    reviewer = observation(fake_probability=14)

    assert calibrate_observations([primary, reviewer])["verdict"] == "SUSPICIOUS"


def test_two_confirmed_fake_votes_are_required_after_review():
    primary = observation(
        tampering_evidence=[
            {
                "category": "overlay",
                "strength": "strong",
                "description": "Pasted amount has a hard boundary",
                "location": "amount row",
                "observed_text": "₹5,000",
            }
        ],
        authenticity_assessment="clear_manipulation",
        fake_probability=90,
    )
    reviewer = observation(
        tampering_evidence=[
            {
                "category": "pixel_artifact",
                "strength": "strong",
                "description": "Different anti-aliasing is localized to the amount",
                "location": "amount row",
                "observed_text": "₹5,000",
            }
        ],
        authenticity_assessment="clear_manipulation",
        fake_probability=86,
    )

    assert calibrate_observations([primary, reviewer])["verdict"] == "SCAM"


def test_unknown_or_unclear_apps_receive_a_review_in_default_mode():
    assert _needs_review(observation(app_name="Unknown", app_key="unknown", app_confidence=10))


def test_valid_png_is_preserved_for_original_detail_analysis():
    output = io.BytesIO()
    Image.new("RGB", (300, 600), "white").save(output, format="PNG")

    prepared, media_type, dimensions = _prepare_image(output.getvalue())

    assert prepared == output.getvalue()
    assert media_type == "image/png"
    assert dimensions == (300, 600)


def test_tiny_images_are_rejected_before_paid_model_call():
    output = io.BytesIO()
    Image.new("RGB", (100, 100), "white").save(output, format="PNG")

    with pytest.raises(ValueError, match="dimensions are too small"):
        _prepare_image(output.getvalue())


def test_failed_required_review_cannot_leave_a_scam_verdict(monkeypatch):
    output = io.BytesIO()
    Image.new("RGB", (300, 600), "white").save(output, format="PNG")
    primary = observation(
        tampering_evidence=[
            {
                "category": "overlay",
                "strength": "strong",
                "description": "Pasted amount has a hard boundary",
                "location": "amount row",
                "observed_text": "₹5,000",
            }
        ],
        authenticity_assessment="clear_manipulation",
        fake_probability=90,
    )
    calls = 0

    def fake_run_model(*_args):
        nonlocal calls
        calls += 1
        if calls == 1:
            return primary
        raise RuntimeError("review unavailable")

    monkeypatch.setattr(engine, "_run_model", fake_run_model)
    monkeypatch.setattr(engine, "REVIEW_MODE", "suspicious")

    result = asyncio.run(engine.analyze_payment_screenshot(output.getvalue()))

    assert result["verdict"] == "SUSPICIOUS"
    assert result["review_status"] == "failed"
    assert result["confidence"] == "low"

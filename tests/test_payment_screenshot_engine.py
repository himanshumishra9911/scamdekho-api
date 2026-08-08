import asyncio
import io
from types import SimpleNamespace

import pytest
from PIL import Image

from app.services.payment_screenshot_engine import (
    PaymentObservation,
    ReplicaTriage,
    SYSTEM_PROMPT,
    _estimate_cost_usd,
    _make_analysis_views,
    _needs_review,
    _prepare_image,
    _replica_triage_to_observation,
    _reasoning_config,
    _request_policy,
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


def replica_triage(**overrides) -> ReplicaTriage:
    data = {
        "app_name": "PhonePe",
        "app_key": "phonepe",
        "app_confidence": 96,
        "headline_text": "Transaction Successful",
        "transaction_label": "PhonePe Transaction ID",
        "transaction_id": "T2608082154187816861687",
        "readability": "clear",
        "wording_errors": [],
        "app_identity_conflicts": [],
        "transaction_format_anomalies": [],
        "component_style_conflicts": [],
        "benign_explanations": [],
        "assessment": "likely_genuine",
        "replica_probability": 8,
        "confidence": "high",
        "reasons": ["No combined replica-app pattern"],
    }
    data.update(overrides)
    return ReplicaTriage(**data)


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


def test_prompt_covers_replica_apps_without_overfitting_to_a_typo():
    prompt = SYSTEM_PROMPT.lower()

    assert "fake or clone payment app" in prompt
    assert "at least two independent, visible inconsistencies" in prompt
    assert "a single typo" in prompt
    assert "forwarded inside whatsapp" in prompt


def test_replica_triage_requires_two_independent_signal_families_for_confirmation():
    triage = replica_triage(
        headline_text="Transaction Successfull",
        transaction_label="Transaction ID",
        transaction_id="TXNEHNAVCV3",
        wording_errors=["Successfull is misspelled in the system heading"],
        app_identity_conflicts=["Generic Banking name row conflicts with the claimed app UI"],
        transaction_format_anomalies=["Generic short provider transaction ID"],
        assessment="likely_replica",
        replica_probability=91,
        confidence="high",
    )

    converted = _replica_triage_to_observation(triage)

    assert converted.authenticity_assessment == "clear_manipulation"
    assert converted.fake_probability == 91
    assert sum(item.strength == "strong" for item in converted.tampering_evidence) == 1
    assert _needs_review(converted)


def test_one_identifier_format_anomaly_cannot_confirm_a_fake_screen():
    converted = _replica_triage_to_observation(
        replica_triage(
            transaction_id="ABC123",
            transaction_format_anomalies=["Identifier format is unfamiliar"],
            assessment="uncertain",
            replica_probability=42,
            confidence="medium",
        )
    )

    assert converted.authenticity_assessment == "uncertain"
    assert not any(item.strength == "strong" for item in converted.tampering_evidence)
    assert calibrate_observations([converted])["verdict"] == "SUSPICIOUS"


def test_default_fast_path_uses_low_detail_and_bounded_output():
    assert _request_policy(engine.ANALYST_PROMPT) == ("low", 1100)
    assert _request_policy(engine.REPLICA_REVIEW_PROMPT) == ("auto", 1500)


def test_gpt5_nano_omits_unsupported_reasoning_parameters():
    assert _reasoning_config("gpt-5-nano", "none", "standard") is None
    assert _reasoning_config("gpt-5-nano", "high", "standard") is None
    assert _reasoning_config("gpt-5.4-mini", "low", "standard") == {"effort": "low"}
    assert _reasoning_config("gpt-5.6-luna", "medium", "pro") == {
        "effort": "medium",
        "mode": "pro",
    }


def test_nano_primary_meets_per_check_budget_on_observed_production_usage():
    cost = _estimate_cost_usd("gpt-5-nano", 2354, 1262, 1089, 901)

    assert cost == pytest.approx(0.000435)
    assert cost < engine.BUDGET_TARGET_USD_PER_CHECK


def test_replica_app_signal_is_supported_but_remains_inconclusive_without_strong_proof():
    item = observation(
        tampering_evidence=[
            {
                "category": "replica_app",
                "strength": "moderate",
                "description": "The system heading and component styles contain two independent inconsistencies",
                "location": "payment confirmation panel",
                "observed_text": "Payments Successful",
            }
        ],
        authenticity_assessment="uncertain",
        fake_probability=56,
    )

    assert calibrate_observations([item])["verdict"] == "SUSPICIOUS"


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


def test_two_of_three_confirmed_fake_votes_form_a_scam_consensus():
    confirmed = observation(
        tampering_evidence=[
            {
                "category": "overlay",
                "strength": "strong",
                "description": "A hard paste boundary surrounds the amount",
                "location": "amount row",
                "observed_text": "₹5,000",
            }
        ],
        authenticity_assessment="clear_manipulation",
        fake_probability=92,
    )

    result = calibrate_observations([confirmed, confirmed, observation(fake_probability=9)])

    assert result["verdict"] == "SCAM"
    assert result["evidence_summary"]["confirmed_fake_votes"] == 2
    assert result["evidence_summary"]["required_consensus_votes"] == 2


def test_one_false_strong_vote_cannot_overrule_two_clean_reviews():
    dissent = observation(
        tampering_evidence=[
            {
                "category": "pixel_artifact",
                "strength": "strong",
                "description": "Possible hard edge near amount",
                "location": "amount row",
                "observed_text": "₹500",
            }
        ],
        authenticity_assessment="clear_manipulation",
        fake_probability=86,
    )

    result = calibrate_observations(
        [dissent, observation(fake_probability=8), observation(fake_probability=11)]
    )

    assert result["verdict"] == "SUSPICIOUS"
    assert result["evidence_summary"]["confirmed_fake_votes"] == 1


def test_weak_dissent_does_not_create_a_false_positive_against_clean_consensus():
    weak = observation(
        tampering_evidence=[
            {
                "category": "typography",
                "strength": "weak",
                "description": "One label may have a different weight",
                "location": "lower half",
                "observed_text": "Paid",
            }
        ],
        fake_probability=19,
    )

    assert calibrate_observations(
        [weak, observation(fake_probability=7), observation(fake_probability=9)]
    )["verdict"] == "SAFE"


def test_replica_app_dissent_is_never_silently_marked_safe():
    replica = observation(
        tampering_evidence=[
            {
                "category": "replica_app",
                "strength": "moderate",
                "description": "Two independent component families conflict",
                "location": "payment panel",
                "observed_text": "Payments Successful",
            }
        ],
        authenticity_assessment="uncertain",
        fake_probability=54,
    )

    assert calibrate_observations(
        [replica, observation(fake_probability=8), observation(fake_probability=10)]
    )["verdict"] == "SUSPICIOUS"


def test_unknown_or_unclear_apps_receive_a_review_in_default_mode():
    assert _needs_review(observation(app_name="Unknown", app_key="unknown", app_confidence=10))


def test_valid_png_is_preserved_for_original_detail_analysis():
    output = io.BytesIO()
    Image.new("RGB", (300, 600), "white").save(output, format="PNG")

    prepared, media_type, dimensions = _prepare_image(output.getvalue())

    assert prepared == output.getvalue()
    assert media_type == "image/png"
    assert dimensions == (300, 600)


def test_tall_screenshot_gets_overlapping_native_resolution_focus_views():
    output = io.BytesIO()
    Image.new("RGB", (400, 1000), "white").save(output, format="PNG")

    views = _make_analysis_views(output.getvalue(), "image/png", max_views=3)

    assert [view[0] for view in views] == [
        "Full screenshot",
        "Upper payment area",
        "Lower details area",
    ]
    assert all(view[2].startswith("image/") for view in views)


def test_model_request_uses_configured_detail_structured_output_and_optional_pro_mode(monkeypatch):
    captured = {}

    class FakeResponses:
        def parse(self, **kwargs):
            captured.update(kwargs)
            return SimpleNamespace(
                output_parsed=observation(),
                usage=SimpleNamespace(
                    input_tokens=4000,
                    input_tokens_details=SimpleNamespace(
                        cached_tokens=1000,
                        cache_write_tokens=0,
                    ),
                    output_tokens=900,
                    output_tokens_details=SimpleNamespace(reasoning_tokens=600),
                    total_tokens=4900,
                ),
            )

    fake_client = SimpleNamespace(responses=FakeResponses())
    monkeypatch.setattr(engine, "get_client", lambda: fake_client)
    monkeypatch.setattr(engine, "ADJUDICATOR_IMAGE_DETAIL", "original")

    model_pass = engine._run_model(
        [("Full screenshot", b"image-bytes", "image/png")],
        engine.ADJUDICATOR_PROMPT,
        "gpt-5.6-sol",
        "xhigh",
        "pro",
    )

    assert captured["model"] == "gpt-5.6-sol"
    assert captured["reasoning"] == {"effort": "xhigh", "mode": "pro"}
    assert captured["text_format"] is PaymentObservation
    image_item = captured["input"][0]["content"][2]
    assert image_item["type"] == "input_image"
    assert image_item["detail"] == "original"
    assert captured["store"] is False
    assert captured["text"] == {"verbosity": "low"}
    assert "verbosity" not in captured
    assert captured["max_output_tokens"] == 1800
    assert captured["prompt_cache_key"].startswith("payment-vision-v7:gpt-5.6-sol:")
    assert model_pass.input_tokens == 4000
    assert model_pass.cached_input_tokens == 1000
    assert model_pass.reasoning_tokens == 600
    assert model_pass.estimated_cost_usd == pytest.approx(0.0425)


def test_cost_estimate_applies_cached_discount_and_cache_write_premium():
    assert _estimate_cost_usd("gpt-5.6-sol", 1000, 200, 100, 100) == pytest.approx(
        0.007225
    )


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
    monkeypatch.setattr(
        engine, "_run_replica_triage", lambda *_args: observation(fake_probability=8)
    )
    monkeypatch.setattr(engine, "REVIEW_MODE", "suspicious")

    result = asyncio.run(engine.analyze_payment_screenshot(output.getvalue()))

    assert result["verdict"] == "SUSPICIOUS"
    assert result["review_status"] == "failed"
    assert result["confidence"] == "low"


def test_clean_parallel_consensus_skips_costly_adjudicator(monkeypatch):
    output = io.BytesIO()
    Image.new("RGB", (300, 600), "white").save(output, format="PNG")
    calls = 0

    def fake_run_model(*_args):
        nonlocal calls
        calls += 1
        return observation(fake_probability=8)

    monkeypatch.setattr(engine, "_run_model", fake_run_model)
    monkeypatch.setattr(
        engine, "_run_replica_triage", lambda *_args: observation(fake_probability=8)
    )
    monkeypatch.setattr(engine, "REVIEW_MODE", "always")
    monkeypatch.setattr(engine, "ADJUDICATOR_MODE", "adaptive")

    result = asyncio.run(engine.analyze_payment_screenshot(output.getvalue()))

    assert result["verdict"] == "SAFE"
    assert calls == 2
    assert result["ensemble"]["attempted_passes"] == 3
    assert result["ensemble"]["successful_passes"] == 3
    assert result["ensemble"]["failed_passes"] == 0
    assert result["ensemble"]["adjudicator_performed"] is False
    assert result["ensemble"]["analysis_views"] == 2
    assert result["ensemble"]["view_counts"] == {
        "primary": 1,
        "replica_triage": 1,
        "review": 2,
    }
    assert result["ensemble"]["cascade_path"] == [
        "primary",
        "replica_triage",
        "review",
    ]


def test_clean_default_cascade_uses_parallel_nano_checks_without_review(monkeypatch):
    output = io.BytesIO()
    Image.new("RGB", (300, 600), "white").save(output, format="PNG")
    calls = []

    def fake_run_model(image_views, _prompt, model, effort, _mode):
        calls.append((len(image_views), model, effort))
        return observation(fake_probability=8)

    monkeypatch.setattr(engine, "_run_model", fake_run_model)
    monkeypatch.setattr(
        engine, "_run_replica_triage", lambda *_args: observation(fake_probability=7)
    )
    monkeypatch.setattr(engine, "PRIMARY_MODEL", "gpt-5-nano")
    monkeypatch.setattr(engine, "PRIMARY_REASONING_EFFORT", "none")
    monkeypatch.setattr(engine, "REVIEW_MODE", "suspicious")
    monkeypatch.setattr(engine, "ADJUDICATOR_MODE", "adaptive")

    result = asyncio.run(engine.analyze_payment_screenshot(output.getvalue()))

    assert result["verdict"] == "SAFE"
    assert calls == [(1, "gpt-5-nano", "none")]
    assert result["review_status"] == "not_required"
    assert result["ensemble"]["cascade_path"] == ["primary", "replica_triage"]
    assert result["ensemble"]["view_counts"] == {
        "primary": 1,
        "replica_triage": 1,
    }


def test_fake_candidate_escalates_to_mini_with_focus_views_and_requires_consensus(monkeypatch):
    output = io.BytesIO()
    Image.new("RGB", (300, 600), "white").save(output, format="PNG")
    calls = []
    confirmed = observation(
        tampering_evidence=[
            {
                "category": "overlay",
                "strength": "strong",
                "description": "A hard paste boundary surrounds the amount",
                "location": "amount row",
                "observed_text": "₹5,000",
            }
        ],
        authenticity_assessment="clear_manipulation",
        fake_probability=92,
    )

    def fake_run_model(image_views, _prompt, model, effort, _mode):
        calls.append((len(image_views), model, effort))
        return confirmed

    monkeypatch.setattr(engine, "_run_model", fake_run_model)
    monkeypatch.setattr(engine, "_run_replica_triage", lambda *_args: confirmed)
    monkeypatch.setattr(engine, "PRIMARY_MODEL", "gpt-5-nano")
    monkeypatch.setattr(engine, "PRIMARY_REASONING_EFFORT", "none")
    monkeypatch.setattr(engine, "REVIEW_MODEL", "gpt-5.4-mini")
    monkeypatch.setattr(engine, "REVIEW_REASONING_EFFORT", "low")
    monkeypatch.setattr(engine, "REVIEW_MODE", "suspicious")
    monkeypatch.setattr(engine, "ADJUDICATOR_MODE", "adaptive")

    result = asyncio.run(engine.analyze_payment_screenshot(output.getvalue()))

    assert result["verdict"] == "SCAM"
    assert calls == [
        (1, "gpt-5-nano", "none"),
        (2, "gpt-5.4-mini", "low"),
    ]
    assert result["evidence_summary"]["confirmed_fake_votes"] == 3
    assert result["ensemble"]["adjudicator_performed"] is False


def test_uncertain_parallel_result_triggers_independent_adjudicator(monkeypatch):
    output = io.BytesIO()
    Image.new("RGB", (300, 600), "white").save(output, format="PNG")
    responses = [
        observation(fake_probability=9),
        observation(
            authenticity_assessment="uncertain",
            fake_probability=52,
            tampering_evidence=[
                {
                    "category": "replica_app",
                    "strength": "moderate",
                    "description": "Conflicting component families",
                    "location": "payment panel",
                    "observed_text": "Payments Successful",
                }
            ],
        ),
        observation(fake_probability=12),
    ]
    calls = 0

    def fake_run_model(*_args):
        nonlocal calls
        item = responses[calls]
        calls += 1
        return item

    monkeypatch.setattr(engine, "_run_model", fake_run_model)
    monkeypatch.setattr(
        engine, "_run_replica_triage", lambda *_args: observation(fake_probability=7)
    )
    monkeypatch.setattr(engine, "REVIEW_MODE", "always")
    monkeypatch.setattr(engine, "ADJUDICATOR_MODE", "adaptive")

    result = asyncio.run(engine.analyze_payment_screenshot(output.getvalue()))

    assert calls == 3
    assert result["verdict"] == "SUSPICIOUS"
    assert result["ensemble"]["adjudicator_performed"] is True

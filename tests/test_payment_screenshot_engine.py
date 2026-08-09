import asyncio
import io
from types import SimpleNamespace

import pytest
from PIL import Image

from app.services.payment_local_forensics import LocalForensicsResult
from app.services.payment_screenshot_engine import (
    PaymentObservation,
    ReplicaTriage,
    SYSTEM_PROMPT,
    _estimate_cost_usd,
    _apply_provider_identifier_consensus,
    _apply_success_heading_consensus,
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
        "amount": "₹1",
        "upi_id": "9956809088@ptyes",
        "recipient_name": "Shikhar Tripathi",
        "sender_name": "Himanshu Mishra",
        "bank_name": "State Bank of India",
        "timestamp": "8 August 2026 at 9:54 PM",
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
    assert "explicit visible label such as fake" in prompt
    assert "third-party warning annotation" in prompt


def test_warning_annotation_prevents_safe_and_exposes_honest_score_metadata():
    result = calibrate_observations([observation()])
    local = LocalForensicsResult(
        known_fake=None,
        red_overlay_candidate=False,
        red_overlay_area_ratio=0.0017,
        attention_overlay_candidate=True,
        attention_overlay_area_ratio=0.0182,
        explicit_overlay_term="scam",
        annotation_overlay_term="scam",
        latency_ms=520,
    )

    engine._apply_local_overlay_floor(result, local)
    engine._sync_score_metadata(result, local)

    assert result["verdict"] == "SUSPICIOUS"
    assert result["risk_percentage"] == 68
    assert result["safety_percentage"] == 32
    assert result["score_breakdown"]["risk_indicator"] == 68
    assert result["score_breakdown"]["signals"]["annotation_term"] == "scam"
    assert result["score_breakdown"]["is_calibrated_probability"] is False


def test_model_confirmed_warning_overlay_floors_safe_when_ocr_misses():
    result = calibrate_observations(
        [
            observation(
                tampering_evidence=[
                    {
                        "category": "replica_app",
                        "strength": "weak",
                        "description": (
                            'Prominent overlaid red handwritten text: "PhonePe scam '
                            'se savdhan rhe" covering the receipt UI.'
                        ),
                        "location": "payment interface",
                        "observed_text": "PhonePe scam se savdhan rhe",
                    }
                ],
                fake_probability=25,
            )
        ]
    )
    local = LocalForensicsResult(
        known_fake=None,
        red_overlay_candidate=False,
        red_overlay_area_ratio=0.0017,
        attention_overlay_candidate=True,
        attention_overlay_area_ratio=0.0182,
        explicit_overlay_term=None,
        annotation_overlay_term=None,
        latency_ms=27,
    )

    engine._apply_local_overlay_floor(result, local)
    engine._sync_score_metadata(result, local)

    assert result["verdict"] == "SUSPICIOUS"
    assert result["risk_percentage"] == 68
    assert result["safety_percentage"] == 32
    assert result["score_breakdown"]["signals"]["annotation_overlay"] is True
    assert result["score_breakdown"]["signals"]["annotation_term"] == "scam"


def test_model_localized_annotation_floors_safe_without_transcribed_warning():
    result = calibrate_observations(
        [
            observation(
                tampering_evidence=[
                    {
                        "category": "replica_app",
                        "strength": "weak",
                        "description": (
                            "Overlaid red/magenta annotation text over central "
                            "payment area (candidate tampering/annotation)."
                        ),
                        "location": "payment interface",
                        "observed_text": None,
                    }
                ],
                fake_probability=25,
            )
        ]
    )
    local = LocalForensicsResult(
        known_fake=None,
        red_overlay_candidate=False,
        red_overlay_area_ratio=0.0017,
        attention_overlay_candidate=True,
        attention_overlay_area_ratio=0.0182,
        explicit_overlay_term=None,
        annotation_overlay_term=None,
        latency_ms=27,
    )

    engine._apply_local_overlay_floor(result, local)
    engine._sync_score_metadata(result, local)

    assert result["verdict"] == "SUSPICIOUS"
    assert result["risk_percentage"] == 68
    assert result["score_breakdown"]["signals"]["annotation_overlay"] is True
    assert (
        result["score_breakdown"]["signals"]["annotation_term"]
        == "model-confirmed annotation"
    )


def test_model_annotation_in_limitations_still_corroborates_pixel_candidate():
    result = calibrate_observations([observation(fake_probability=25)])
    result["benign_limitations"] = [
        "Overlaid magenta warning text likely added later"
    ]
    local = LocalForensicsResult(
        known_fake=None,
        red_overlay_candidate=False,
        red_overlay_area_ratio=0.0017,
        attention_overlay_candidate=True,
        attention_overlay_area_ratio=0.0182,
        explicit_overlay_term=None,
        annotation_overlay_term=None,
        latency_ms=27,
    )

    engine._apply_local_overlay_floor(result, local)

    assert result["verdict"] == "SUSPICIOUS"
    assert result["risk_percentage"] == 68


def test_text_like_magenta_overlay_is_suspicious_even_when_gpt_misses_it():
    observed = observation(
        authenticity_assessment="no_evidence_of_manipulation",
        fake_probability=55,
    )
    result = calibrate_observations([observed])
    local = LocalForensicsResult(
        known_fake=None,
        red_overlay_candidate=False,
        red_overlay_area_ratio=0.0017,
        attention_overlay_candidate=True,
        attention_overlay_area_ratio=0.0182,
        explicit_overlay_term=None,
        annotation_overlay_term=None,
        latency_ms=27,
        magenta_text_overlay_candidate=True,
        magenta_text_overlay_area_ratio=0.0183,
    )
    model_pass = engine.ModelPassResult(
        observation=observed,
        model="gpt-5-mini",
        view_count=1,
        raw_model_score=55,
    )

    engine._apply_local_overlay_floor(result, local)
    engine._apply_weighted_ensemble(result, [model_pass], local)
    engine._sync_score_metadata(result, local)

    assert result["verdict"] == "SUSPICIOUS"
    assert 35 <= result["risk_percentage"] <= 69
    assert result["score_breakdown"]["components"]["gpt_vision"]["score"] == 34
    assert result["score_breakdown"]["components"]["forensic_logic"]["score"] >= 80
    assert result["score_breakdown"]["signals"]["annotation_overlay"] is True


def test_promotion_limitation_does_not_become_annotation_evidence():
    result = calibrate_observations([observation(fake_probability=20)])
    result["benign_limitations"] = [
        "Overlaid promotional reward banner is normal in-app UI"
    ]
    local = LocalForensicsResult(
        known_fake=None,
        red_overlay_candidate=False,
        red_overlay_area_ratio=0.0,
        attention_overlay_candidate=True,
        attention_overlay_area_ratio=0.02,
        explicit_overlay_term=None,
        annotation_overlay_term=None,
        latency_ms=20,
    )

    engine._apply_local_overlay_floor(result, local)

    assert result["verdict"] == "SAFE"


def test_attention_color_without_model_warning_does_not_floor_genuine_ui():
    result = calibrate_observations(
        [
            observation(
                tampering_evidence=[
                    {
                        "category": "other",
                        "strength": "weak",
                        "description": "A normal red promotional card appears below the receipt",
                        "location": "advertisement panel",
                        "observed_text": "Rewards",
                    }
                ]
            )
        ]
    )
    local = LocalForensicsResult(
        known_fake=None,
        red_overlay_candidate=False,
        red_overlay_area_ratio=0.0,
        attention_overlay_candidate=True,
        attention_overlay_area_ratio=0.02,
        explicit_overlay_term=None,
        annotation_overlay_term=None,
        latency_ms=20,
    )

    engine._apply_local_overlay_floor(result, local)

    assert result["verdict"] == "SAFE"
    assert result["risk_percentage"] <= 30


def test_weighted_ensemble_uses_exact_75_25_continuous_components():
    observed = observation(fake_probability=17)
    result = calibrate_observations([observed])
    local = LocalForensicsResult(
        known_fake=None,
        red_overlay_candidate=False,
        red_overlay_area_ratio=0.0,
        attention_overlay_candidate=False,
        attention_overlay_area_ratio=0.0,
        explicit_overlay_term=None,
        annotation_overlay_term=None,
        latency_ms=12,
    )
    model_pass = engine.ModelPassResult(
        observation=observed,
        model="gpt-5-mini",
        view_count=1,
        raw_model_score=17,
    )
    forensic_score = engine._forensic_logic_score(result, local)

    engine._apply_weighted_ensemble(result, [model_pass], local)
    engine._sync_score_metadata(result, local)

    expected = round(17 * 0.75 + forensic_score * 0.25)
    assert result["risk_percentage"] == expected
    assert result["safety_percentage"] == 100 - expected
    assert result["weighted_ensemble"]["model_weight"] == 0.75
    assert result["weighted_ensemble"]["forensic_weight"] == 0.25
    assert result["score_breakdown"]["method"] == "gpt_75_forensics_25_v1"
    assert result["score_breakdown"]["components"]["gpt_vision"]["score"] == 17


def test_weighted_scores_vary_with_direct_model_score_instead_of_fixed_bucket():
    local = LocalForensicsResult(
        known_fake=None,
        red_overlay_candidate=False,
        red_overlay_area_ratio=0.0,
        attention_overlay_candidate=False,
        attention_overlay_area_ratio=0.0,
        explicit_overlay_term=None,
        annotation_overlay_term=None,
        latency_ms=10,
    )
    risks = []
    for model_score in (8, 19, 31):
        observed = observation(fake_probability=model_score)
        result = calibrate_observations([observed])
        model_pass = engine.ModelPassResult(
            observation=observed,
            model="gpt-5-mini",
            view_count=1,
            raw_model_score=model_score,
        )
        engine._apply_weighted_ensemble(result, [model_pass], local)
        risks.append(result["risk_percentage"])

    assert risks[0] < risks[1] < risks[2]
    assert len(set(risks)) == 3


def test_model_number_is_bounded_by_its_own_genuine_category():
    observed = observation(
        authenticity_assessment="no_evidence_of_manipulation",
        fake_probability=25,
    )

    assert engine._category_consistent_model_score(55, observed) == 34
    assert engine._category_consistent_model_score(22, observed) == 22


def test_model_number_is_bounded_by_uncertain_and_fake_categories():
    uncertain = observation(
        authenticity_assessment="uncertain",
        fake_probability=52,
    )
    fake = observation(
        authenticity_assessment="clear_manipulation",
        fake_probability=88,
    )

    assert engine._category_consistent_model_score(18, uncertain) == 35
    assert engine._category_consistent_model_score(92, uncertain) == 69
    assert engine._category_consistent_model_score(41, fake) == 70


def test_replica_triage_requires_two_independent_signal_families_for_confirmation():
    triage = replica_triage(
        headline_text="Transaction Successfull",
        transaction_label="Transaction ID",
        transaction_id="TXNEHNAVCV3",
        wording_errors=["Successfull is misspelled in the system heading"],
        app_identity_conflicts=["Two different app names both claim to be the paying application"],
        transaction_format_anomalies=["Generic short provider transaction ID"],
        component_style_conflicts=["The success icon has a localized hard rectangular edge"],
        assessment="likely_replica",
        replica_probability=91,
        confidence="high",
    )

    converted = _replica_triage_to_observation(triage)

    assert converted.authenticity_assessment == "clear_manipulation"
    assert converted.fake_probability == 91
    assert sum(item.strength == "strong" for item in converted.tampering_evidence) == 1
    assert _needs_review(converted)


def test_high_probability_semantic_claims_cannot_become_strong_evidence():
    converted = _replica_triage_to_observation(
        replica_triage(
            wording_errors=["Odd system wording"],
            transaction_format_anomalies=["Provider ID does not cohere with its label"],
            component_style_conflicts=[
                "The success icon has a localized hard rectangular edge"
            ],
            assessment="uncertain",
            replica_probability=85,
            confidence="medium",
        )
    )

    assert converted.authenticity_assessment == "uncertain"
    assert converted.fake_probability == 85
    assert not any(item.strength == "strong" for item in converted.tampering_evidence)
    assert sum(item.strength == "moderate" for item in converted.tampering_evidence) == 1


def test_negated_absence_statements_never_become_visual_evidence():
    converted = _replica_triage_to_observation(
        replica_triage(
            wording_errors=[
                "No clear grammar/spelling error in the main success heading."
            ],
            component_style_conflicts=[
                "No obvious pixel artifact or duplicated component is visible."
            ],
            assessment="uncertain",
            replica_probability=64,
        )
    )

    assert converted.authenticity_assessment == "no_evidence_of_manipulation"
    assert converted.fake_probability == 25
    assert converted.tampering_evidence == []
    assert len(converted.benign_limitations) == 2
    assert _needs_review(converted) is False


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

    assert converted.authenticity_assessment == "no_evidence_of_manipulation"
    assert converted.fake_probability == 25
    assert not any(item.strength == "strong" for item in converted.tampering_evidence)
    assert calibrate_observations([converted])["verdict"] == "SAFE"


def test_cross_app_upi_interoperability_claims_are_filtered_as_benign():
    converted = _replica_triage_to_observation(
        replica_triage(
            app_identity_conflicts=[
                "PhonePe-branded success screen shows Sent to: paytm in the recipient line"
            ],
            component_style_conflicts=[
                "PhonePe branding is paired with a Paytm UPI handle"
            ],
            transaction_format_anomalies=["The identifier format is unfamiliar"],
            assessment="likely_replica",
            replica_probability=88,
            confidence="high",
        )
    )

    assert converted.authenticity_assessment == "no_evidence_of_manipulation"
    assert converted.fake_probability == 25
    assert all(item.strength == "weak" for item in converted.tampering_evidence)
    assert len(converted.benign_limitations) == 2
    assert calibrate_observations([converted])["verdict"] == "SAFE"


def test_share_receipt_heading_and_recipient_brand_are_not_tampering():
    converted = _replica_triage_to_observation(
        replica_triage(
            wording_errors=[
                "The powered by UPI receipt-style page has a generic heading"
            ],
            app_identity_conflicts=[
                "Recipient row shows paytm on a PhonePe-branded receipt"
            ],
            component_style_conflicts=[
                "PhonePe purple UI coexists with a Paytm-labeled recipient row"
            ],
            assessment="uncertain",
            replica_probability=55,
        )
    )

    assert converted.authenticity_assessment == "no_evidence_of_manipulation"
    assert converted.fake_probability == 25
    assert not converted.tampering_evidence
    assert len(converted.benign_limitations) == 3
    assert _needs_review(converted) is False


def test_repeated_invalid_phonepe_transaction_id_confirms_two_votes():
    first = _replica_triage_to_observation(
        replica_triage(
            app_name="Unknown",
            app_key=".",
            app_confidence=35,
            transaction_label="Transaction ID",
            transaction_id="TXNEHNAVCV3",
            assessment="uncertain",
            replica_probability=40,
            confidence="low",
        )
    )
    second = _replica_triage_to_observation(
        replica_triage(
            transaction_label="Transaction ID",
            transaction_id="TXNEHNAVCV3",
            assessment="likely_genuine",
            replica_probability=12,
        )
    )

    assert _apply_provider_identifier_consensus([first, second]) is True
    result = calibrate_observations([first, second])

    assert result["verdict"] == "SCAM"
    assert result["evidence_summary"]["confirmed_fake_votes"] == 2
    assert result["evidence_summary"]["strong"] == 2


def test_repeated_invalid_success_heading_confirms_two_votes():
    observations = [
        _replica_triage_to_observation(
            replica_triage(
                headline_text="Payments Successful",
                assessment="likely_genuine",
                replica_probability=12,
            )
        ),
        _replica_triage_to_observation(
            replica_triage(
                headline_text="Payments Successful",
                assessment="likely_genuine",
                replica_probability=10,
            )
        ),
    ]

    assert _needs_review(observations[0]) is True
    assert _apply_success_heading_consensus(observations) is True
    result = calibrate_observations(observations)

    assert result["verdict"] == "SCAM"
    assert result["evidence_summary"]["confirmed_fake_votes"] == 2
    assert result["evidence_summary"]["strong"] == 2


def test_one_invalid_success_heading_cannot_confirm_fake_screen():
    item = _replica_triage_to_observation(
        replica_triage(
            headline_text="Payments Successful",
            assessment="likely_genuine",
            replica_probability=12,
        )
    )

    assert _needs_review(item) is True
    assert _apply_success_heading_consensus([item]) is False
    assert calibrate_observations([item])["verdict"] == "SAFE"


@pytest.mark.parametrize(
    "heading",
    [
        "Payment Successful",
        "Transaction Successful",
        "Sent Successfully",
        "Paid successfully",
        "Payment received",
    ],
)
def test_legitimate_success_headings_do_not_trigger_review(heading):
    item = _replica_triage_to_observation(
        replica_triage(headline_text=heading)
    )

    assert _needs_review(item) is False
    assert _apply_success_heading_consensus([item, item.model_copy(deep=True)]) is False


def test_valid_phonepe_transaction_id_is_not_promoted():
    observations = [
        _replica_triage_to_observation(replica_triage()),
        _replica_triage_to_observation(replica_triage()),
    ]

    assert _apply_provider_identifier_consensus(observations) is False
    assert not any(item.tampering_evidence for item in observations)


def test_repeated_utr_is_not_treated_as_phonepe_transaction_id():
    observations = [
        _replica_triage_to_observation(
            replica_triage(transaction_label="UTR", transaction_id="264786711602")
        ),
        _replica_triage_to_observation(
            replica_triage(transaction_label="UTR", transaction_id="264786711602")
        ),
    ]

    assert _apply_provider_identifier_consensus(observations) is False
    assert not any(item.tampering_evidence for item in observations)


def test_one_invalid_provider_id_read_only_triggers_review():
    item = _replica_triage_to_observation(
        replica_triage(
            transaction_label="Transaction ID",
            transaction_id="TXNEHNAVCV3",
            assessment="likely_genuine",
            replica_probability=12,
        )
    )

    assert _apply_provider_identifier_consensus([item]) is False
    assert _needs_review(item) is True
    assert not item.tampering_evidence


def test_low_app_identity_confidence_alone_does_not_trigger_review():
    item = observation(
        app_name="Unknown",
        app_key="unknown",
        app_confidence=5,
        confidence="low",
        fake_probability=10,
    )

    assert _needs_review(item) is False


def test_short_mixed_explicit_transaction_id_triggers_independent_review():
    item = _replica_triage_to_observation(
        replica_triage(
            app_name="Unknown",
            app_key="unknown",
            app_confidence=10,
            transaction_label="Transaction ID",
            transaction_id="TXNEHNAVCV3",
            transaction_format_anomalies=[],
            assessment="likely_genuine",
            replica_probability=10,
            confidence="low",
        )
    )

    assert item.authenticity_assessment == "no_evidence_of_manipulation"
    assert _needs_review(item) is True


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


def test_compact_54_nano_fast_path_meets_per_check_budget_envelope():
    cost = _estimate_cost_usd("gpt-5.4-nano", 2000, 0, 0, 500)

    assert cost == pytest.approx(0.001025)
    assert cost < engine.BUDGET_TARGET_USD_PER_CHECK


def test_direct_gpt5_mini_typical_scan_fits_five_day_credit_target():
    cost = _estimate_cost_usd("gpt-5-mini", 2100, 0, 0, 331)

    assert cost == pytest.approx(0.001187)
    assert cost < engine.BUDGET_TARGET_USD_PER_CHECK
    assert cost * 700 * 5 < 5.0


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


def test_normal_in_app_promo_and_matching_clock_are_not_fraud_evidence():
    paytm = observation(
        authenticity_assessment="uncertain",
        fake_probability=45,
        tampering_evidence=[
            {
                "category": "replica_app",
                "strength": "moderate",
                "description": (
                    "Mixed content layers: payment-success receipt UI is partially "
                    "covered by a full-width ad banner/landing page-style content."
                ),
                "location": "payment interface",
                "observed_text": "Discover the Perfect Tablet",
            },
            {
                "category": "replica_app",
                "strength": "moderate",
                "description": (
                    "The status bar shows 9:53 while the transaction time shows "
                    "9:53, which may be an inconsistency."
                ),
                "location": "status bar and receipt",
                "observed_text": "9:53 / 9:53",
            },
        ],
    )

    normalized = engine._normalize_pass_result(
        paytm, "primary", "gpt-5.4-nano", 1
    ).observation

    assert normalized.authenticity_assessment == "no_evidence_of_manipulation"
    assert normalized.fake_probability == 25
    assert normalized.tampering_evidence == []
    assert len(normalized.benign_limitations) == 2


def test_promotion_with_localized_pixel_artifact_remains_material_evidence():
    edited_ad = observation(
        authenticity_assessment="uncertain",
        fake_probability=55,
        tampering_evidence=[
            {
                "category": "overlay",
                "strength": "moderate",
                "description": "A paste boundary is visible around the promotional banner.",
                "location": "promotion panel",
                "observed_text": "Claim reward",
            }
        ],
    )

    normalized = engine._normalize_pass_result(
        edited_ad, "primary", "gpt-5.4-nano", 1
    ).observation

    assert normalized.authenticity_assessment == "uncertain"
    assert normalized.fake_probability == 55
    assert len(normalized.tampering_evidence) == 1


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
    assert captured["prompt_cache_key"].startswith(
        f"{engine.ANALYSIS_VERSION}:gpt-5.6-sol:"
    )
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
    triage_calls = 0

    def fake_run_triage(*_args):
        nonlocal triage_calls
        triage_calls += 1
        if triage_calls == 1:
            return primary
        raise RuntimeError("review unavailable")

    monkeypatch.setattr(engine, "_run_replica_triage", fake_run_triage)
    monkeypatch.setattr(
        engine, "_run_model", lambda *_args: (_ for _ in ()).throw(RuntimeError("adjudicator unavailable"))
    )
    monkeypatch.setattr(engine, "REVIEW_MODE", "suspicious")

    result = asyncio.run(engine.analyze_payment_screenshot(output.getvalue()))

    assert result["verdict"] == "SUSPICIOUS"
    assert result["review_status"] == "failed"
    assert result["confidence"] == "low"


def test_clean_parallel_consensus_skips_costly_adjudicator(monkeypatch):
    output = io.BytesIO()
    Image.new("RGB", (300, 600), "white").save(output, format="PNG")
    calls = []

    def fake_run_triage(image_views, _prompt, model, effort, detail, _tokens):
        calls.append((len(image_views), model, effort, detail))
        return observation(fake_probability=8)

    monkeypatch.setattr(engine, "_run_replica_triage", fake_run_triage)
    monkeypatch.setattr(engine, "REVIEW_MODE", "always")
    monkeypatch.setattr(engine, "ADJUDICATOR_MODE", "adaptive")

    result = asyncio.run(engine.analyze_payment_screenshot(output.getvalue()))

    assert result["verdict"] == "SAFE"
    assert calls == [
        (1, "gpt-5-mini", "none", "low"),
        (2, "gpt-5.4-nano", "none", "auto"),
    ]
    assert result["ensemble"]["attempted_passes"] == 2
    assert result["ensemble"]["successful_passes"] == 2
    assert result["ensemble"]["failed_passes"] == 0
    assert result["ensemble"]["adjudicator_performed"] is False
    assert result["ensemble"]["analysis_views"] == 2
    assert result["ensemble"]["view_counts"] == {
        "primary": 1,
        "review": 2,
    }
    assert result["ensemble"]["cascade_path"] == ["primary", "review"]


def test_clean_default_cascade_uses_one_nano_triage_without_review(monkeypatch):
    output = io.BytesIO()
    Image.new("RGB", (300, 600), "white").save(output, format="PNG")
    calls = []

    def fake_run_triage(image_views, _prompt, model, effort, detail, tokens):
        calls.append((len(image_views), model, effort, detail, tokens))
        return observation(fake_probability=8)

    monkeypatch.setattr(engine, "_run_replica_triage", fake_run_triage)
    monkeypatch.setattr(engine, "PRIMARY_MODEL", "gpt-5.4-nano")
    monkeypatch.setattr(engine, "PRIMARY_REASONING_EFFORT", "none")
    monkeypatch.setattr(engine, "REVIEW_MODE", "suspicious")
    monkeypatch.setattr(engine, "ADJUDICATOR_MODE", "adaptive")

    result = asyncio.run(engine.analyze_payment_screenshot(output.getvalue()))

    assert result["verdict"] == "SAFE"
    assert calls == [(1, "gpt-5.4-nano", "none", "low", 800)]
    assert result["review_status"] == "not_required"
    assert result["ensemble"]["cascade_path"] == ["primary"]
    assert result["ensemble"]["view_counts"] == {"primary": 1}


def test_clean_partial_readability_skips_review(monkeypatch):
    output = io.BytesIO()
    Image.new("RGB", (300, 600), "white").save(output, format="PNG")
    responses = [observation(readability="partial")]
    calls = []

    def fake_run_triage(image_views, _prompt, model, effort, detail, tokens):
        calls.append((len(image_views), model, effort, detail, tokens))
        return responses[len(calls) - 1]

    monkeypatch.setattr(engine, "_run_replica_triage", fake_run_triage)
    monkeypatch.setattr(engine, "PRIMARY_MODEL", "gpt-5.4-nano")
    monkeypatch.setattr(engine, "CHEAP_REVIEW_MODEL", "gpt-5.4-nano")
    monkeypatch.setattr(engine, "CHEAP_REVIEW_REASONING_EFFORT", "none")
    monkeypatch.setattr(engine, "REVIEW_MODEL", "gpt-5.4-mini")
    monkeypatch.setattr(engine, "REVIEW_MODE", "suspicious")
    monkeypatch.setattr(engine, "ADJUDICATOR_MODE", "adaptive")

    result = asyncio.run(engine.analyze_payment_screenshot(output.getvalue()))

    assert result["verdict"] == "SAFE"
    assert calls == [(1, "gpt-5.4-nano", "none", "low", 800)]
    assert result["review_status"] == "not_required"
    assert result["ensemble"]["cascade_path"] == ["primary"]
    assert result["ensemble"]["adjudicator_performed"] is False


def test_unreadable_primary_still_uses_nano_review(monkeypatch):
    output = io.BytesIO()
    Image.new("RGB", (300, 600), "white").save(output, format="PNG")
    responses = [observation(readability="unreadable"), observation(fake_probability=10)]
    calls = []

    def fake_run_triage(image_views, _prompt, model, effort, detail, tokens):
        calls.append((len(image_views), model, effort, detail, tokens))
        return responses[len(calls) - 1]

    monkeypatch.setattr(engine, "_run_replica_triage", fake_run_triage)
    monkeypatch.setattr(engine, "PRIMARY_MODEL", "gpt-5.4-nano")
    monkeypatch.setattr(engine, "CHEAP_REVIEW_MODEL", "gpt-5.4-nano")
    monkeypatch.setattr(engine, "CHEAP_REVIEW_REASONING_EFFORT", "none")
    monkeypatch.setattr(engine, "REVIEW_MODEL", "gpt-5.4-mini")
    monkeypatch.setattr(engine, "REVIEW_MODE", "suspicious")
    monkeypatch.setattr(engine, "ADJUDICATOR_MODE", "off")

    result = asyncio.run(engine.analyze_payment_screenshot(output.getvalue()))

    assert result["verdict"] == "SUSPICIOUS"
    assert calls == [
        (1, "gpt-5.4-nano", "none", "low", 800),
        (2, "gpt-5.4-nano", "none", "auto", 1100),
    ]
    assert result["ensemble"]["adjudicator_performed"] is False


def test_heading_only_consensus_uses_two_nano_passes(monkeypatch):
    output = io.BytesIO()
    Image.new("RGB", (300, 600), "white").save(output, format="PNG")
    heading_fields = {
        "amount": "1200",
        "transaction_id": None,
        "upi_id": "merchant@oksbi",
        "recipient_name": "Example Merchant",
        "sender_name": None,
        "bank_name": None,
        "timestamp": "03:33 PM, 24 Jun 2026",
        "status_text": "Payments Successful",
    }
    responses = [
        observation(fields=heading_fields, fake_probability=20),
        observation(fields=heading_fields, fake_probability=18),
    ]
    calls = []

    def fake_run_triage(image_views, _prompt, model, effort, detail, tokens):
        calls.append((len(image_views), model, effort, detail, tokens))
        return responses[len(calls) - 1]

    monkeypatch.setattr(engine, "_run_replica_triage", fake_run_triage)
    monkeypatch.setattr(engine, "PRIMARY_MODEL", "gpt-5.4-nano")
    monkeypatch.setattr(engine, "CHEAP_REVIEW_MODEL", "gpt-5.4-nano")
    monkeypatch.setattr(engine, "CHEAP_REVIEW_REASONING_EFFORT", "none")
    monkeypatch.setattr(engine, "REVIEW_MODEL", "gpt-5.4-mini")
    monkeypatch.setattr(engine, "REVIEW_MODE", "suspicious")
    monkeypatch.setattr(engine, "ADJUDICATOR_MODE", "adaptive")

    result = asyncio.run(engine.analyze_payment_screenshot(output.getvalue()))

    assert result["verdict"] == "SCAM"
    assert calls == [
        (1, "gpt-5.4-nano", "none", "low", 800),
        (2, "gpt-5.4-nano", "none", "auto", 1100),
    ]
    assert result["evidence_summary"]["confirmed_fake_votes"] == 2
    assert result["ensemble"]["adjudicator_performed"] is False


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

    def fake_run_triage(image_views, _prompt, model, effort, detail, _tokens):
        calls.append((len(image_views), model, effort, detail))
        return confirmed

    monkeypatch.setattr(engine, "_run_replica_triage", fake_run_triage)
    monkeypatch.setattr(engine, "PRIMARY_MODEL", "gpt-5.4-nano")
    monkeypatch.setattr(engine, "PRIMARY_REASONING_EFFORT", "none")
    monkeypatch.setattr(engine, "REVIEW_MODEL", "gpt-5.4-mini")
    monkeypatch.setattr(engine, "REVIEW_REASONING_EFFORT", "low")
    monkeypatch.setattr(engine, "REVIEW_MODE", "suspicious")
    monkeypatch.setattr(engine, "ADJUDICATOR_MODE", "adaptive")

    result = asyncio.run(engine.analyze_payment_screenshot(output.getvalue()))

    assert result["verdict"] == "SCAM"
    assert calls == [
        (1, "gpt-5.4-nano", "none", "low"),
        (2, "gpt-5.4-mini", "low", "auto"),
    ]
    assert result["evidence_summary"]["confirmed_fake_votes"] == 2
    assert result["ensemble"]["adjudicator_performed"] is False


def test_uncertain_parallel_result_triggers_independent_adjudicator(monkeypatch):
    output = io.BytesIO()
    Image.new("RGB", (300, 600), "white").save(output, format="PNG")
    triage_responses = [
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
    ]
    triage_calls = 0
    adjudicator_calls = 0

    def fake_run_triage(*_args):
        nonlocal triage_calls
        item = triage_responses[triage_calls]
        triage_calls += 1
        return item

    def fake_run_model(*_args):
        nonlocal adjudicator_calls
        adjudicator_calls += 1
        return observation(fake_probability=12)

    monkeypatch.setattr(engine, "_run_model", fake_run_model)
    monkeypatch.setattr(engine, "_run_replica_triage", fake_run_triage)
    monkeypatch.setattr(engine, "REVIEW_MODE", "always")
    monkeypatch.setattr(engine, "ADJUDICATOR_MODE", "adaptive")

    result = asyncio.run(engine.analyze_payment_screenshot(output.getvalue()))

    assert triage_calls == 2
    assert adjudicator_calls == 1
    assert result["verdict"] == "SUSPICIOUS"
    assert result["ensemble"]["adjudicator_performed"] is True

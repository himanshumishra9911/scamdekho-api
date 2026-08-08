from argparse import Namespace

from scripts.evaluate_payment_screenshots import (
    find_group_label_conflicts,
    find_split_leakage,
    summarize,
)


def args(**overrides) -> Namespace:
    values = {
        "split": "holdout",
        "target_accuracy": 0.95,
        "max_genuine_fpr": 0.03,
        "max_fake_fnr": 0.05,
        "min_samples": 4,
        "min_per_class": 2,
        "min_groups": 4,
        "min_groups_per_class": 2,
    }
    values.update(overrides)
    return Namespace(**values)


def test_suspicious_is_strictly_wrong_but_does_not_mark_a_fake_genuine():
    predictions = [
        {"label": "GENUINE", "predicted_verdict": "SAFE", "app": "gpay"},
        {"label": "GENUINE", "predicted_verdict": "SUSPICIOUS", "app": "gpay"},
        {"label": "FAKE", "predicted_verdict": "SCAM", "app": "phonepe"},
        {"label": "FAKE", "predicted_verdict": "SUSPICIOUS", "app": "phonepe"},
    ]

    report = summarize(predictions, args(), [])

    assert report["strict_accuracy"] == 0.5
    assert report["genuine_false_positive_rate"] == 0.5
    assert report["fake_false_negative_rate_conservative"] == 0.0
    assert report["fake_not_confirmed_rate_strict"] == 0.5
    assert report["gate"]["passed"] is False


def test_group_reuse_across_calibration_and_holdout_is_detected():
    rows = [
        {"group_id": "same-source", "split": "calibration"},
        {"group_id": "same-source", "split": "holdout"},
        {"group_id": "holdout-only", "split": "holdout"},
    ]

    assert find_split_leakage(rows) == ["same-source"]


def test_conflicting_labels_for_the_same_source_are_detected():
    rows = [
        {"group_id": "same-source", "label": "GENUINE"},
        {"group_id": "same-source", "label": "FAKE"},
    ]

    assert find_group_label_conflicts(rows) == ["same-source"]


def test_quality_gate_passes_only_when_all_thresholds_and_sample_sizes_pass():
    predictions = [
        {"label": "GENUINE", "predicted_verdict": "SAFE", "app": "gpay"},
        {"label": "GENUINE", "predicted_verdict": "SAFE", "app": "phonepe"},
        {"label": "FAKE", "predicted_verdict": "SCAM", "app": "gpay"},
        {"label": "FAKE", "predicted_verdict": "SCAM", "app": "phonepe"},
    ]

    assert summarize(predictions, args(), [])["gate"]["passed"] is True
    assert summarize(predictions, args(), ["leaked-source"])["gate"]["passed"] is False


def test_duplicate_variants_cannot_satisfy_independent_group_gate():
    predictions = [
        {"label": "GENUINE", "predicted_verdict": "SAFE", "app": "gpay", "group_id": "one"},
        {"label": "GENUINE", "predicted_verdict": "SAFE", "app": "gpay", "group_id": "one"},
        {"label": "FAKE", "predicted_verdict": "SCAM", "app": "gpay", "group_id": "two"},
        {"label": "FAKE", "predicted_verdict": "SCAM", "app": "gpay", "group_id": "two"},
    ]

    report = summarize(predictions, args(), [])

    assert report["strict_accuracy"] == 1.0
    assert report["independent_groups"] == 2
    assert report["gate"]["passed"] is False

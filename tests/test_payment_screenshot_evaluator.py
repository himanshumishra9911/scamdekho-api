from argparse import Namespace

from scripts.evaluate_payment_screenshots import (
    find_content_hash_leakage,
    find_group_label_conflicts,
    find_split_leakage,
    summarize,
    wilson_interval,
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


def test_exact_image_reuse_across_splits_is_detected_even_with_different_groups(tmp_path):
    (tmp_path / "a.png").write_bytes(b"same-image-bytes")
    (tmp_path / "b.png").write_bytes(b"same-image-bytes")
    rows = [
        {"file": "a.png", "split": "calibration", "group_id": "one"},
        {"file": "b.png", "split": "holdout", "group_id": "two"},
    ]

    assert len(find_content_hash_leakage(rows, tmp_path)) == 1


def test_quality_gate_passes_only_when_all_thresholds_and_sample_sizes_pass():
    predictions = [
        {"label": "GENUINE", "predicted_verdict": "SAFE", "app": "gpay"},
        {"label": "GENUINE", "predicted_verdict": "SAFE", "app": "phonepe"},
        {"label": "FAKE", "predicted_verdict": "SCAM", "app": "gpay"},
        {"label": "FAKE", "predicted_verdict": "SCAM", "app": "phonepe"},
    ]

    relaxed = args(target_accuracy=0.5)
    assert summarize(predictions, relaxed, [])["gate"]["passed"] is True
    assert summarize(predictions, relaxed, ["leaked-source"])["gate"]["passed"] is False


def test_reported_95_percent_does_not_pass_when_confidence_bound_is_lower():
    predictions = [
        {"label": "GENUINE", "predicted_verdict": "SAFE", "app": "gpay"}
        for _ in range(50)
    ] + [
        {"label": "FAKE", "predicted_verdict": "SCAM", "app": "phonepe"}
        for _ in range(45)
    ] + [
        {"label": "FAKE", "predicted_verdict": "SUSPICIOUS", "app": "phonepe"}
        for _ in range(5)
    ]

    report = summarize(predictions, args(), [])

    assert report["strict_accuracy"] == 0.95
    assert report["strict_accuracy_wilson_95"]["lower"] < 0.95
    assert report["gate"]["passed"] is False


def test_wilson_interval_is_defined_for_perfect_small_sample_without_claiming_perfection():
    interval = wilson_interval(4, 4)

    assert interval["lower"] < 1.0
    assert interval["upper"] == 1.0


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

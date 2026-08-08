"""Run a leakage-aware payment screenshot holdout evaluation.

Examples:
    python scripts/evaluate_payment_screenshots.py \
        --manifest tests/payment_screenshot_dataset/manifest.jsonl \
        --split holdout --output payment-screenshot-eval.json
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import sys
from collections import Counter, defaultdict
from math import sqrt
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.services.payment_screenshot_engine import (  # noqa: E402
    ANALYSIS_VERSION,
    analyze_payment_screenshot,
)

VALID_LABELS = {"GENUINE", "FAKE"}
VALID_VERDICTS = {"SAFE", "SUSPICIOUS", "SCAM"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--split", default="holdout")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--target-accuracy", type=float, default=0.95)
    parser.add_argument("--max-genuine-fpr", type=float, default=0.03)
    parser.add_argument("--max-fake-fnr", type=float, default=0.05)
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument("--min-per-class", type=int, default=40)
    parser.add_argument("--min-groups", type=int, default=80)
    parser.add_argument("--min-groups-per-class", type=int, default=30)
    return parser.parse_args()


def load_manifest(path: Path) -> list[dict]:
    rows: list[dict] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON on manifest line {line_number}: {exc}") from exc
        missing = {"id", "file", "label", "app", "split", "group_id"} - row.keys()
        if missing:
            raise ValueError(f"Manifest line {line_number} is missing: {sorted(missing)}")
        row["label"] = str(row["label"]).upper()
        if row["label"] not in VALID_LABELS:
            raise ValueError(f"Manifest line {line_number} has invalid label {row['label']!r}")
        rows.append(row)
    return rows


def find_split_leakage(rows: list[dict]) -> list[str]:
    group_splits: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        group_splits[str(row["group_id"])].add(str(row["split"]))
    return sorted(group for group, splits in group_splits.items() if len(splits) > 1)


def find_group_label_conflicts(rows: list[dict]) -> list[str]:
    group_labels: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        group_labels[str(row["group_id"])].add(str(row["label"]))
    return sorted(group for group, labels in group_labels.items() if len(labels) > 1)


def find_content_hash_leakage(rows: list[dict], manifest_dir: Path) -> list[str]:
    """Catch exact image reuse across splits even when group IDs were entered incorrectly."""
    hash_splits: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        image_path = (manifest_dir / str(row["file"])).resolve()
        if not image_path.is_file():
            continue
        digest = hashlib.sha256(image_path.read_bytes()).hexdigest()
        hash_splits[digest].add(str(row["split"]))
    return sorted(digest[:16] for digest, splits in hash_splits.items() if len(splits) > 1)


def safe_ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> dict | None:
    """95% Wilson score interval; more honest than a point estimate on small sets."""
    if total <= 0:
        return None
    proportion = successes / total
    denominator = 1 + (z * z / total)
    centre = (proportion + z * z / (2 * total)) / denominator
    margin = (
        z
        * sqrt((proportion * (1 - proportion) / total) + (z * z / (4 * total * total)))
        / denominator
    )
    return {"lower": round(max(0.0, centre - margin), 4), "upper": round(min(1.0, centre + margin), 4)}


async def evaluate(rows: list[dict], manifest_dir: Path) -> list[dict]:
    predictions: list[dict] = []
    for index, row in enumerate(rows, 1):
        image_path = (manifest_dir / row["file"]).resolve()
        print(f"[{index}/{len(rows)}] {row['id']} ({row['app']}, {row['label']})", flush=True)
        prediction = {**row, "resolved_file": str(image_path)}
        try:
            result = await analyze_payment_screenshot(image_path.read_bytes())
            verdict = str(result.get("verdict", "")).upper()
            if verdict not in VALID_VERDICTS:
                raise ValueError(f"Engine returned invalid verdict {verdict!r}")
            prediction.update(
                {
                    "predicted_verdict": verdict,
                    "risk_percentage": result.get("risk_percentage"),
                    "detected_app": result.get("detected_app"),
                    "review_performed": result.get("review_performed"),
                    "evidence_summary": result.get("evidence_summary"),
                    "error": None,
                }
            )
        except Exception as exc:
            prediction.update(
                {
                    "predicted_verdict": "ERROR",
                    "risk_percentage": None,
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
        predictions.append(prediction)
    return predictions


def summarize(
    predictions: list[dict],
    args: argparse.Namespace,
    leakage: list[str],
    label_conflicts: list[str] | None = None,
    content_leakage: list[str] | None = None,
) -> dict:
    label_conflicts = label_conflicts or []
    content_leakage = content_leakage or []
    label_counts = Counter(item["label"] for item in predictions)
    verdict_counts = Counter(item["predicted_verdict"] for item in predictions)
    confusion = Counter((item["label"], item["predicted_verdict"]) for item in predictions)
    total = len(predictions)
    genuine = label_counts["GENUINE"]
    fake = label_counts["FAKE"]

    strict_correct = sum(
        (item["label"] == "GENUINE" and item["predicted_verdict"] == "SAFE")
        or (item["label"] == "FAKE" and item["predicted_verdict"] == "SCAM")
        for item in predictions
    )
    genuine_false_positives = sum(
        item["label"] == "GENUINE" and item["predicted_verdict"] != "SAFE"
        for item in predictions
    )
    fake_false_negatives = sum(
        item["label"] == "FAKE" and item["predicted_verdict"] == "SAFE"
        for item in predictions
    )
    fake_not_confirmed = sum(
        item["label"] == "FAKE" and item["predicted_verdict"] != "SCAM"
        for item in predictions
    )

    accuracy = safe_ratio(strict_correct, total)
    accuracy_interval = wilson_interval(strict_correct, total)
    genuine_fpr = safe_ratio(genuine_false_positives, genuine)
    fake_fnr = safe_ratio(fake_false_negatives, fake)
    strict_fake_fnr = safe_ratio(fake_not_confirmed, fake)
    grouped: dict[str, list[dict]] = defaultdict(list)
    for index, item in enumerate(predictions):
        # Synthetic callers/tests predating group-aware evaluation get unique
        # groups rather than accidentally collapsing into one.
        grouped[str(item.get("group_id", f"ungrouped-{index}"))].append(item)
    group_scores = [
        sum(
            (item["label"] == "GENUINE" and item["predicted_verdict"] == "SAFE")
            or (item["label"] == "FAKE" and item["predicted_verdict"] == "SCAM")
            for item in items
        )
        / len(items)
        for items in grouped.values()
    ]
    group_weighted_accuracy = round(sum(group_scores) / len(group_scores), 4) if group_scores else None
    group_label_counts = Counter(items[0]["label"] for items in grouped.values())
    enough_data = (
        total >= args.min_samples
        and genuine >= args.min_per_class
        and fake >= args.min_per_class
        and len(grouped) >= args.min_groups
        and group_label_counts["GENUINE"] >= args.min_groups_per_class
        and group_label_counts["FAKE"] >= args.min_groups_per_class
        and not leakage
        and not label_conflicts
        and not content_leakage
    )
    passed = bool(
        enough_data
        and accuracy is not None
        and accuracy >= args.target_accuracy
        and accuracy_interval is not None
        and accuracy_interval["lower"] >= args.target_accuracy
        and group_weighted_accuracy is not None
        and group_weighted_accuracy >= args.target_accuracy
        and genuine_fpr is not None
        and genuine_fpr <= args.max_genuine_fpr
        and fake_fnr is not None
        and fake_fnr <= args.max_fake_fnr
    )

    by_app = {}
    for app in sorted({str(item["app"]) for item in predictions}):
        app_items = [item for item in predictions if str(item["app"]) == app]
        app_correct = sum(
            (item["label"] == "GENUINE" and item["predicted_verdict"] == "SAFE")
            or (item["label"] == "FAKE" and item["predicted_verdict"] == "SCAM")
            for item in app_items
        )
        by_app[app] = {"samples": len(app_items), "strict_accuracy": safe_ratio(app_correct, len(app_items))}

    return {
        "analysis_version": ANALYSIS_VERSION,
        "split": args.split,
        "samples": total,
        "label_counts": dict(label_counts),
        "verdict_counts": dict(verdict_counts),
        "strict_accuracy": accuracy,
        "strict_accuracy_wilson_95": accuracy_interval,
        "group_weighted_strict_accuracy": group_weighted_accuracy,
        "independent_groups": len(grouped),
        "group_label_counts": dict(group_label_counts),
        "genuine_false_positive_rate": genuine_fpr,
        "fake_false_negative_rate_conservative": fake_fnr,
        "fake_not_confirmed_rate_strict": strict_fake_fnr,
        "errors": verdict_counts["ERROR"],
        "confusion": {
            f"{label}->{verdict}": count
            for (label, verdict), count in sorted(confusion.items())
        },
        "by_app": by_app,
        "leaked_group_ids": leakage,
        "leaked_content_hashes": content_leakage,
        "conflicting_group_label_ids": label_conflicts,
        "gate": {
            "passed": passed,
            "enough_data": enough_data,
            "target_accuracy": args.target_accuracy,
            "requires_wilson_lower_bound": True,
            "max_genuine_fpr": args.max_genuine_fpr,
            "max_fake_fnr": args.max_fake_fnr,
            "min_samples": args.min_samples,
            "min_per_class": args.min_per_class,
            "min_groups": args.min_groups,
            "min_groups_per_class": args.min_groups_per_class,
        },
    }


async def async_main() -> int:
    args = parse_args()
    manifest_path = args.manifest.resolve()
    all_rows = load_manifest(manifest_path)
    leakage = find_split_leakage(all_rows)
    label_conflicts = find_group_label_conflicts(all_rows)
    content_leakage = find_content_hash_leakage(all_rows, manifest_path.parent)
    rows = [row for row in all_rows if str(row["split"]) == args.split]
    if args.limit:
        rows = rows[: args.limit]
    if not rows:
        raise ValueError(f"No rows found for split {args.split!r}")

    predictions = await evaluate(rows, manifest_path.parent)
    summary = summarize(predictions, args, leakage, label_conflicts, content_leakage)
    report = {"summary": summary, "predictions": predictions}
    rendered = json.dumps(report, indent=2, ensure_ascii=False)
    print(rendered)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if summary["gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(async_main()))

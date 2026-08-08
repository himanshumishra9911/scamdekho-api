# Payment screenshot evaluation dataset

Keep screenshots local: image extensions in this folder are ignored by Git. The
manifest may be committed only after personal details have been reviewed.

Each `manifest.jsonl` line must contain:

```json
{"id":"gpay-genuine-001","file":"genuine/google_pay/gpay-001.png","label":"GENUINE","app":"google_pay","split":"calibration","group_id":"gpay-source-001","variant":"original"}
```

- `label`: `GENUINE` or `FAKE` describes screenshot pixel authenticity, not
  whether the underlying payment settled.
- `split`: use `calibration` while tuning and `holdout` for the final untouched
  measurement.
- `group_id`: original and compressed/cropped variants of the same source must
  share a group. The evaluator fails the quality gate if a group crosses splits.
- The evaluator also hashes image bytes and fails the gate when an exact image is
  reused across splits under different group IDs.
- `variant`: optional description such as `original`, `whatsapp_compressed`,
  `cropped`, `dark_mode`, or `hindi`.

Recommended minimum for a credible 95% claim: 100 untouched holdout screenshots,
at least 40 genuine and 40 fake, at least 80 independent transaction/image-source
groups (30 per class), multiple apps/devices, and no source overlap with calibration
examples. Both screenshot-level and group-weighted accuracy must reach the target.
The quality gate also requires the 95% Wilson confidence-interval lower bound to
reach the target, so a small or merely lucky holdout cannot produce a “95%” claim.

Current calibration intake contains 16 user-confirmed genuine images across
PhonePe, Paytm, CRED, Airtel Thanks, YONO SBI Pay, Navi, and Google Pay, plus one
medium-confidence public fake report. Several genuine images are alternate views
of the same payment, so the dataset currently represents 9 independent source
groups (8 genuine and 1 fake). Do not move these groups into the holdout split.

`public_candidates.jsonl` records public scam reports separately. Only the
medium-confidence, source-described fake is present in the calibration manifest.
Community guesses and ambiguous non-receipt claims remain provisional and must
not enter measured accuracy. Public images stay local because they may contain
personal identifiers and must not be redistributed without permission.

`external_sources.jsonl` records researched forgery datasets and why they were
not silently ingested. Access-controlled, academic-only, incompatible-license,
or non-UPI receipt datasets are research leads, not production training data.

`official_sources.jsonl` records official pages for additional app coverage.
Those pages are reference-only: promotional app-store artwork must never be
silently treated as a genuine raw receipt or included in measured accuracy.

Run:

```bash
python scripts/evaluate_payment_screenshots.py \
  --manifest tests/payment_screenshot_dataset/manifest.jsonl \
  --split holdout \
  --output payment-screenshot-eval.json
```

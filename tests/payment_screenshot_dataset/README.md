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
- `variant`: optional description such as `original`, `whatsapp_compressed`,
  `cropped`, `dark_mode`, or `hindi`.

Recommended minimum for a credible 95% claim: 100 untouched holdout screenshots,
at least 40 genuine and 40 fake, at least 80 independent transaction/image-source
groups (30 per class), multiple apps/devices, and no source overlap with calibration
examples. Both screenshot-level and group-weighted accuracy must reach the target.

Current calibration intake contains 16 user-confirmed genuine images across
PhonePe, Paytm, CRED, Airtel Thanks, YONO SBI Pay, Navi, and Google Pay. Several
images are alternate views of the same payment, so they represent 8 independent
transaction groups. Do not move these groups into the holdout split.

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

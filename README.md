# ScamDekho AI Scam Detection API

**Live website:** [ScamDekho – Free AI Scam Checker](https://scamdekho.in/)

ScamDekho is an India-focused online safety toolkit for checking suspicious websites, messages, UPI IDs, QR codes, payment screenshots, and job offers before users click, pay, or share.

## ScamDekho AI Engine

This project uses an AI-only (ChatGPT-style) scam detection engine.

How it works:
- User pastes a message / content
- AI directly evaluates whether it is REAL or FAKE
- AI explains why, what to do, and how to avoid
- No keyword scoring or rule overrides are applied

Important notes:
- This is a risk-awareness tool
- Responses are AI-generated
- Users should always verify via official sources

## Bot protection

Set these Render environment variables before deploying:

- `ADMIN_TOKEN`: protects `/dashboard` and `/analytics/stats`. Open dashboard as `/dashboard?token=YOUR_TOKEN`.
- `PUBLIC_API_KEY`: optional trusted API key for server/API testing. Send it as `x-api-key`.
- `ALLOWED_PUBLIC_ORIGINS`: optional comma-separated origins allowed to call public checks. Defaults include `https://scamdekho.in`, `https://www.scamdekho.in`, and the Render API origin.
- `ALLOW_DIRECT_API`: keep unset/false in production. Set `true` only if you want to allow direct API calls without browser origin checks.

The URL checker also has a stricter per-IP rate limit because it performs external checks, screenshots, AI work, and writes dashboard history.

## Payment screenshot accuracy controls

The payment screenshot endpoint uses an adaptive GPT-5.6 Sol ensemble plus a
deterministic consensus threshold. Two independent passes inspect localized edits
and fake/clone-app signals in parallel. Ambiguous evidence triggers a third blind
adjudicator. Tall receipts are supplied as the original image plus overlapping
native-resolution focus views. Missing fields, unfamiliar apps, compression,
cropping, and suspicious UPI words are not treated as proof of fabrication.

Optional Render environment variables:

- `PAYMENT_SCREENSHOT_MODEL` (default `gpt-5.6-sol`): primary forensic model.
- `PAYMENT_SCREENSHOT_REVIEW_MODEL` (default `gpt-5.6-sol`): independent clone-app specialist.
- `PAYMENT_SCREENSHOT_ADJUDICATOR_MODEL` (default `gpt-5.6-sol`): blind third-pass adjudicator.
- `PAYMENT_SCREENSHOT_REVIEW_MODE`: `always` (default), `suspicious`, or `off`.
- `PAYMENT_SCREENSHOT_ADJUDICATOR_MODE`: `adaptive` (default), `always`, or `off`.
- `PAYMENT_SCREENSHOT_REASONING_EFFORT` (default `high`) supplies the primary/reviewer baseline.
- `PAYMENT_SCREENSHOT_PRIMARY_REASONING_EFFORT` and `PAYMENT_SCREENSHOT_REVIEW_REASONING_EFFORT` optionally override that baseline.
- `PAYMENT_SCREENSHOT_ADJUDICATOR_REASONING_EFFORT` (default `xhigh`).
- `PAYMENT_SCREENSHOT_ADJUDICATOR_REASONING_MODE`: `standard` (default) or `pro`. Enable `pro` only after a representative holdout demonstrates a worthwhile gain.
- `PAYMENT_SCREENSHOT_IMAGE_DETAIL` (default `original`).
- `PAYMENT_SCREENSHOT_MAX_VIEWS` (default `3`, range `1`-`3`).
- `PAYMENT_SCREENSHOT_ANALYSIS_TIMEOUT` (default `180` seconds).

See `tests/payment_screenshot_dataset/README.md` for the leakage-safe labeled
evaluation format and the 95% quality gate.

## Domain CSV seeder

Run the isolated seeder whenever you want to create the next batch of public pages from a CSV:

```bash
python scripts/seed_domains.py --csv /path/to/domains.csv
```

Useful options:

- `--limit 50`: number of new domains to scan this run. Default is `50`.
- `--domain-column domain`: CSV header to read. If omitted, common headers like `domain`, `url`, `website`, `site`, and `host` are auto-detected.
- `--seed-id my-domains`: optional stable ID if you move/rename the CSV and want to keep the same progress.
- `--delay 1`: optional delay between scans.

The seeder stores progress in MongoDB, skips duplicate CSV domains, skips domains that already have public pages, resumes from the last saved row, and prints a final processed/skipped/failed/remaining summary.

Idempotency notes:

- Progress advances only after a row is completed, intentionally skipped, or recorded as a terminal domain failure.
- Scan responses are saved to the seeder item before page publishing, so an interrupted run can resume publishing without rescanning.
- Seeder-created dashboard scan records use deterministic IDs, so retries update the same row instead of inserting duplicates.
- If page publishing cannot be verified, progress is not advanced; rerun the seeder to retry the same domain safely.

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

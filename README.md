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

# ScamDekho Partner URL Check API (v1)

## Base URL

Production base URL:

```text
https://scamdekho.in
```

Endpoint:

```text
POST /api/v1/url-check
```

## Authentication

Pass the partner API key in the `Authorization` header:

```text
Authorization: Bearer YOUR_API_KEY
```

Required headers:

```text
Authorization: Bearer YOUR_API_KEY
Content-Type: application/json
```

Each partner has its own API key record in the `partner_api_keys` collection with:

- `api_key`
- `partner_name`
- `created_at`
- `monthly_limit`
- `is_active`

For the initial Askeal rollout, the backend can seed the key from:

```text
ASKEAL_PARTNER_API_KEY
ASKEAL_PARTNER_MONTHLY_LIMIT
```

## Request Schema

```json
{
  "url": "https://example.com"
}
```

## Success Response

Status: `200 OK`

```json
{
  "trust_score": 90,
  "verdict": "very_likely_safe",
  "confidence": "high",
  "summary": "This website looks safe based on multiple independent checks.",
  "sources_checked": 14,
  "full_report_url": "https://scamdekho.in/check/example.com"
}
```

### Verdict Values

- `very_likely_safe`
- `likely_safe`
- `suspicious`
- `risky`
- `very_likely_scam`

These verdicts are mapped from the existing ScamDekho URL scoring thresholds. The scoring engine is reused; this API is only a filtered summary layer.

## What This API Does Not Return

The partner API intentionally does **not** expose:

- source-by-source security results
- SSL certificate details
- IP / hosting details
- domain age details
- "why this looks safe" reasoning lists
- prevention tips / recommended actions
- Hindi / translated text

Those details stay on ScamDekho and are available through `full_report_url`.

## Error Responses

### `400 Bad Request`

Returned when the URL is missing or invalid.

Example:

```json
{
  "detail": {
    "message": "Invalid or missing URL"
  }
}
```

### `401 Unauthorized`

Returned when the `Authorization` header is missing or the API key is invalid.

Example:

```json
{
  "detail": {
    "message": "Invalid API key"
  }
}
```

### `429 Too Many Requests`

Returned when the monthly partner limit is exhausted.

Example:

```json
{
  "detail": {
    "message": "Monthly rate limit exceeded",
    "retry_after": "2026-08-01T00:00:00Z"
  }
}
```

### `500 Internal Server Error`

Returned when the internal scan fails unexpectedly.

Example:

```json
{
  "detail": {
    "message": "Internal scan failure"
  }
}
```

## Rate Limit Behavior

Each partner key has a configurable monthly limit stored in the database. For the current Askeal rollout, the target limit is:

```text
350 requests per calendar month
```

Usage is tracked in the `partner_api_usage` collection with:

- `api_key`
- `month`
- `request_count`

The monthly counter resets automatically at the start of each calendar month (UTC).

### Rate Limit Headers

Successful requests, `400` responses after authentication, `429` responses, and internal scan failures include:

```text
X-RateLimit-Limit: 350
X-RateLimit-Remaining: 214
X-RateLimit-Reset: 2026-08-01T00:00:00Z
```

## Sample cURL

```bash
curl -X POST https://scamdekho.in/api/v1/url-check \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## Implementation Notes

- This endpoint reuses the existing ScamDekho URL scoring engine.
- It returns only summary data and a link back to the full ScamDekho report page.
- `full_report_url` deep-links to the specific report route on ScamDekho when a valid domain can be normalized.

## v1 Scope

This is a v1 partner launch focused on URL checks only.

Future versions may add:

- phone number checks
- UPI ID checks
- per-end-user limits (for example if a partner starts passing `user_id`)

# ScamDekho Content Automation

This isolated command collects topic opportunities, creates at most three source-grounded articles, runs quality checks, and saves accepted articles as WordPress drafts. It does not generate images, import into `app.main`, change any API route, publish posts, or submit URLs to Google.

## Daily flow

1. Collect Google Search Console queries, configured RSS feeds, Google News RSS, and Google Trends RSS.
2. Keep only ScamDekho-relevant topics and merge near-duplicates.
3. Score recency, source type, GSC traffic drops, impressions, clicks, CTR opportunity, position, and growth.
4. Claim each topic once in MongoDB so retries cannot create duplicate drafts.
5. Research two to four allowlisted sources.
6. Generate one source-grounded draft per accepted topic.
7. Reject thin, robotic, unfinished, poorly structured, or weakly sourced drafts.
8. Create a WordPress post with `status=draft` only and no featured image.
9. Log opportunities, drafts, and GSC performance in Google Sheets.

The daily maximum is hard-capped at three even if a larger value is supplied.
The default daily mix is exactly two GSC recovery topics plus one current news topic. GSC
recovery topics are ordered by lost clicks, then lost impressions, then opportunity score. If a
candidate fails source or quality checks, the next eligible candidate in the same bucket is
tried. Unselected topics can be reconsidered later, and source-only skips can retry safely
without repeatedly paying for same-day AI quality failures.

GSC topics receive a small official-source research pack (for example RBI/NPCI for payment
queries and Google Safe Browsing/Cloudflare for website queries). The existing requirement
for at least two independent trusted sources is not lowered.

Internal links prioritize the matching ScamDekho product page before related blog posts,
including the Fake Payment Screenshot Checker, URL Checker, Scam Message Checker, UPI/QR
Checker, and Fake Offer Letter Checker.

## Article writer

OpenAI writes the article draft. The model is selected with `CONTENT_AI_MODEL`; the supplied environment example uses `gpt-4.5-preview` as requested. GPT-4.5 Preview is deprecated, so confirm that your OpenAI account can still call it before enabling the live cron job. If it is unavailable, change only `CONTENT_AI_MODEL`; no code change is required.

The AI-generated result always passes through the source, structure, length, internal-link, FAQ, and quality checks before a WordPress draft can be created. It is never published automatically.

## Credentials

Copy the variable names from `.env.content-automation.example` into Render. Do not commit real values.

### WordPress

Create a dedicated WordPress user with Author or Editor access, then create an Application Password under that user's profile.

- `WORDPRESS_URL=https://scamdekho.in`
- `WORDPRESS_USERNAME=<dedicated user>`
- `WORDPRESS_APPLICATION_PASSWORD=<application password>`

The normal WordPress password is not used.

### Google Search Console and Sheets

1. Create a Google Cloud service account and enable the Google Search Console API and Google Sheets API.
2. Download its JSON key and base64-encode the whole file into `GOOGLE_SERVICE_ACCOUNT_JSON_BASE64`.
3. Add the service account's `client_email` as a user on the `sc-domain:scamdekho.in` Search Console property.
4. Create a blank Google Sheet and share it with the same `client_email` as Editor.
5. Set the spreadsheet ID from its URL as `GOOGLE_SHEET_ID`.
6. Initialize the four tabs:

```bash
python scripts/run_content_automation.py --bootstrap-sheet
```

The bootstrap command now fails clearly when the service-account JSON is missing or invalid. A successful message means the configured spreadsheet was actually reached and initialized.

The tabs are:

- `Topic Opportunities`: topic, score, reason, keywords, sources, and selection status.
- `Drafts`: WordPress draft ID/link, quality score, keywords, source count, and review status.
- `Performance`: daily 28-day GSC query/page metrics.
- `Settings`: a place for editorial settings maintained by the owner.

## RSS sources

Set `CONTENT_RSS_FEEDS` to a comma-separated list of official or reputable cybersecurity/consumer-safety feeds. A discovered article is accepted for research only when its final hostname is in `CONTENT_TRUSTED_DOMAINS`. This is intentionally strict to prevent low-quality aggregation and unsupported claims.

## Test safely

Dry run only collects, filters, and scores topics. It does not call OpenAI, MongoDB, Google Sheets, or WordPress.

```bash
python scripts/run_content_automation.py --dry-run --limit 3
```

Enable real draft creation only after the dry run and Sheet bootstrap succeed:

```bash
CONTENT_AUTOMATION_ENABLED=true python scripts/run_content_automation.py --limit 3
```

## Render Cron Job

Create a separate Render Cron Job from the same repository. Use:

```text
python scripts/run_content_automation.py --limit 3
```

For a 9:00 AM India run, use `30 3 * * *` when the scheduler expects UTC. Keep this separate from the FastAPI web service. MongoDB stores a daily run lock and unique topic IDs, so a retry or overlapping trigger cannot create a duplicate WordPress post. The WordPress slug is also checked before creating a draft.

## Human review checklist

Before publishing each draft:

- Open every cited source and confirm the article represents it accurately.
- Check the headline, meta description, names, dates, figures, and legal/financial wording.
- Remove any generic wording and add ScamDekho's own practical perspective.
- Create and add your preferred featured image, then check every internal/external link.
- Publish manually, then submit the final URL through Search Console when appropriate.

The pipeline intentionally does not auto-publish. This keeps the human review step that protects quality, voice, and search compliance.


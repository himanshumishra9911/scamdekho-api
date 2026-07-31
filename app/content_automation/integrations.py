from __future__ import annotations

import asyncio
import base64
import html
import json
import logging
import re
from datetime import date, timedelta
from html.parser import HTMLParser
from io import BytesIO
from urllib.parse import quote, urlparse

import httpx

from app.content_automation.config import ContentAutomationConfig
from app.content_automation.models import ArticleDraft, SourceReference, TopicCandidate
from app.content_automation.payloads import build_wordpress_draft_payload

logger = logging.getLogger(__name__)

GOOGLE_SCOPES = [
    "https://www.googleapis.com/auth/webmasters.readonly",
    "https://www.googleapis.com/auth/spreadsheets",
]

OFFICIAL_REFERENCE_LIBRARY = {
    "payment": [
        SourceReference(
            title="Unified Payments Interface Safety Shield",
            url="https://www.npci.org.in/safety-feature",
            publisher="NPCI",
            excerpt="Official UPI safety guidance for consumers making digital payments.",
        ),
        SourceReference(
            title="Customer Protection - Limiting Liability in Unauthorised Electronic Banking Transactions",
            url="https://www.rbi.org.in/commonman/English/scripts/Notification.aspx?Id=2623",
            publisher="Reserve Bank of India",
            excerpt="Official RBI guidance on electronic payment safety and reporting unauthorised transactions.",
        ),
    ],
    "website": [
        SourceReference(
            title="Google Safe Browsing",
            url="https://safebrowsing.google.com/",
            publisher="Google",
            excerpt="Official guidance on phishing, malware, unwanted software, and unsafe websites.",
        ),
        SourceReference(
            title="What is a phishing attack?",
            url="https://www.cloudflare.com/learning/security/phishing-attack/",
            publisher="Cloudflare",
            excerpt="Security guidance about phishing, fake websites, spoofed domains, and suspicious links.",
        ),
    ],
    "message": [
        SourceReference(
            title="What is smishing?",
            url="https://www.cloudflare.com/learning/security/smishing/",
            publisher="Cloudflare",
            excerpt="Security guidance about scam text messages, suspicious links, and social engineering.",
        ),
        SourceReference(
            title="National Cyber Crime Reporting Portal",
            url="https://www.cybercrime.gov.in/",
            publisher="Government of India",
            excerpt="Official Indian cybercrime reporting and citizen-safety information.",
        ),
    ],
    "general": [
        SourceReference(
            title="National Cyber Crime Reporting Portal",
            url="https://www.cybercrime.gov.in/",
            publisher="Government of India",
            excerpt="Official Indian cybercrime reporting and citizen-safety information.",
        ),
        SourceReference(
            title="Common cyber attacks: detection and prevention",
            url="https://www.cloudflare.com/learning/security/threats/common-cyber-attacks/",
            publisher="Cloudflare",
            excerpt="Security guidance covering phishing and common online attack methods.",
        ),
    ],
}


def official_references_for_query(query: str) -> list[SourceReference]:
    value = (query or "").lower()
    if any(term in value for term in ("upi", "payment", "gpay", "google pay", "phonepe", "paytm", "utr", "bank")):
        category = "payment"
    elif any(term in value for term in ("url", "website", "domain", "link", "phish", "browser")):
        category = "website"
    elif any(term in value for term in ("sms", "message", "whatsapp", "otp", "kyc", "email")):
        category = "message"
    else:
        category = "general"
    return [SourceReference(**vars(item)) for item in OFFICIAL_REFERENCE_LIBRARY[category]]


def product_links_for_query(query: str, site_url: str = "https://scamdekho.in") -> list[dict[str, str]]:
    value = (query or "").lower()
    groups = [
        (("upi", "payment", "gpay", "google pay", "phonepe", "paytm", "utr", "screenshot"),
         "Fake Payment Screenshot Checker", "/fake-payment-screenshot-checker"),
        (("url", "website", "domain", "link", "phish", "browser"),
         "URL Checker", "/url-checker"),
        (("sms", "message", "whatsapp", "otp", "kyc", "email"),
         "Scam Message Checker", "/scam-message-checker"),
        (("qr", "vpa", "upi id"), "UPI and QR Checker", "/upi-qr-checker"),
        (("job", "offer", "recruit", "employment"),
         "Fake Offer Letter Checker", "/fake-offer-letter-checker"),
    ]
    matched = [
        {"title": title, "url": site_url.rstrip("/") + path}
        for terms, title, path in groups
        if any(term in value for term in terms)
    ]
    if not matched:
        matched = [
            {"title": "URL Checker", "url": site_url.rstrip("/") + "/url-checker"},
            {"title": "Scam Message Checker", "url": site_url.rstrip("/") + "/scam-message-checker"},
        ]
    return matched


class GoogleTokenProvider:
    def __init__(self, service_account_info: dict | None):
        self.service_account_info = service_account_info
        self._credentials = None
        self._refresh_lock = asyncio.Lock()

    @property
    def configured(self) -> bool:
        return bool(self.service_account_info)

    def service_account_email(self) -> str:
        return (self.service_account_info or {}).get("client_email", "")

    def _refresh_sync(self) -> str:
        try:
            from google.auth.transport.requests import Request
            from google.oauth2 import service_account
        except ImportError as exc:
            raise RuntimeError("google-auth is required for GSC and Sheets") from exc

        if not self.service_account_info:
            raise RuntimeError("Google service account credentials are not configured")
        if self._credentials is None:
            self._credentials = service_account.Credentials.from_service_account_info(
                self.service_account_info,
                scopes=GOOGLE_SCOPES,
            )
        if not self._credentials.valid or not self._credentials.token:
            self._credentials.refresh(Request())
        return self._credentials.token

    async def access_token(self, *, force_refresh: bool = False) -> str:
        async with self._refresh_lock:
            if force_refresh:
                self._credentials = None
            return await asyncio.to_thread(self._refresh_sync)


class GoogleSearchConsoleClient:
    def __init__(self, config: ContentAutomationConfig, tokens: GoogleTokenProvider):
        self.config = config
        self.tokens = tokens

    async def _query(
        self,
        start_date: date,
        end_date: date,
        dimensions: list[str],
        row_limit: int = 500,
    ) -> list[dict]:
        if not self.tokens.configured or not self.config.gsc_property:
            return []
        site = quote(self.config.gsc_property, safe="")
        url = f"https://www.googleapis.com/webmasters/v3/sites/{site}/searchAnalytics/query"
        payload = {
            "startDate": start_date.isoformat(),
            "endDate": end_date.isoformat(),
            "dimensions": dimensions,
            "rowLimit": row_limit,
            "dataState": "final",
        }
        async with httpx.AsyncClient(timeout=self.config.request_timeout_seconds) as client:
            response = None
            for attempt in range(2):
                token = await self.tokens.access_token(force_refresh=attempt == 1)
                response = await client.post(
                    url,
                    headers={"Authorization": f"Bearer {token}"},
                    json=payload,
                )
                if response.status_code != 401 or attempt == 1:
                    break
            response.raise_for_status()
            return response.json().get("rows", [])

    async def collect_candidates(self) -> list[TopicCandidate]:
        today = date.today()
        current_end = today - timedelta(days=3)
        current_start = current_end - timedelta(days=6)
        previous_end = current_start - timedelta(days=1)
        previous_start = previous_end - timedelta(days=6)
        try:
            current, previous = await asyncio.gather(
                self._query(current_start, current_end, ["query"]),
                self._query(previous_start, previous_end, ["query"]),
            )
        except Exception as exc:
            logger.warning("GSC topic collection failed: %s", exc)
            return []

        previous_by_query = {
            (row.get("keys") or [""])[0].lower(): {
                "impressions": float(row.get("impressions", 0)),
                "clicks": float(row.get("clicks", 0)),
            }
            for row in previous
        }
        candidates = []
        for row in current[: self.config.max_candidates_per_source]:
            query_value = (row.get("keys") or [""])[0].strip()
            if not query_value:
                continue
            current_impressions = float(row.get("impressions", 0))
            previous_metrics = previous_by_query.get(query_value.lower(), {})
            old_impressions = float(previous_metrics.get("impressions", 0))
            current_clicks = float(row.get("clicks", 0))
            old_clicks = float(previous_metrics.get("clicks", 0))
            growth = 0.0
            if old_impressions:
                growth = max(-1.0, min(3.0, (current_impressions - old_impressions) / old_impressions))
            elif current_impressions:
                growth = 1.0
            candidates.append(
                TopicCandidate(
                    title=query_value,
                    source_type="gsc",
                    source_name="Google Search Console",
                    url=self.config.site_url,
                    primary_keyword=query_value,
                    impressions=current_impressions,
                    clicks=current_clicks,
                    previous_impressions=old_impressions,
                    previous_clicks=old_clicks,
                    impression_change=current_impressions - old_impressions,
                    click_change=current_clicks - old_clicks,
                    ctr=float(row.get("ctr", 0)),
                    position=float(row.get("position", 0)),
                    growth=growth,
                    source_references=official_references_for_query(query_value),
                )
            )
        return candidates

    async def performance_rows(self) -> list[list]:
        today = date.today()
        end = today - timedelta(days=3)
        start = end - timedelta(days=27)
        try:
            rows = await self._query(start, end, ["page", "query"], row_limit=1000)
        except Exception as exc:
            logger.warning("GSC performance collection failed: %s", exc)
            return []
        collected_on = today.isoformat()
        period = f"{start.isoformat()} to {end.isoformat()}"
        return [
            [
                collected_on,
                (row.get("keys") or ["", ""])[0],
                (row.get("keys") or ["", ""])[1],
                round(float(row.get("clicks", 0)), 2),
                round(float(row.get("impressions", 0)), 2),
                round(float(row.get("ctr", 0)) * 100, 2),
                round(float(row.get("position", 0)), 2),
                period,
            ]
            for row in rows
        ]


class GoogleSheetsClient:
    TAB_HEADERS = {
        "Topic Opportunities": [
            "Date", "Topic Key", "Topic", "Why Chosen", "Opportunity Score",
            "Primary Keyword", "Secondary Keywords", "Sources", "Status", "Notes",
        ],
        "Drafts": [
            "Date", "WordPress Draft ID", "Draft URL", "Title", "Slug",
            "Quality Score", "Primary Keyword", "Secondary Keywords",
            "Source Count", "Internal Link Count", "Review Status",
        ],
        "Performance": [
            "Collected On", "Page URL", "Query", "Clicks", "Impressions",
            "CTR Percent", "Average Position", "Period",
        ],
        "Settings": ["Key", "Value", "Description"],
    }

    def __init__(self, config: ContentAutomationConfig, tokens: GoogleTokenProvider):
        self.config = config
        self.tokens = tokens

    @property
    def configured(self) -> bool:
        return bool(self.config.google_sheet_id and self.tokens.configured)

    async def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}))
        async with httpx.AsyncClient(timeout=self.config.request_timeout_seconds) as client:
            response = None
            for attempt in range(2):
                token = await self.tokens.access_token(force_refresh=attempt == 1)
                headers["Authorization"] = f"Bearer {token}"
                response = await client.request(method, url, headers=headers, **kwargs)
                if response.status_code != 401 or attempt == 1:
                    break
            response.raise_for_status()
            return response

    async def create_spreadsheet(self, title: str = "ScamDekho Content Automation") -> str:
        sheets = [{"properties": {"title": name}} for name in self.TAB_HEADERS]
        response = await self._request(
            "POST",
            "https://sheets.googleapis.com/v4/spreadsheets",
            json={"properties": {"title": title}, "sheets": sheets},
        )
        spreadsheet_id = response.json()["spreadsheetId"]
        self.config.google_sheet_id = spreadsheet_id
        await self.bootstrap()
        return spreadsheet_id

    async def bootstrap(self) -> None:
        if not self.config.google_sheet_id or not self.tokens.configured:
            return
        metadata = await self._request(
            "GET",
            f"https://sheets.googleapis.com/v4/spreadsheets/{self.config.google_sheet_id}",
            params={"fields": "sheets.properties"},
        )
        existing = {
            sheet["properties"]["title"]: sheet["properties"]["sheetId"]
            for sheet in metadata.json().get("sheets", [])
        }
        add_requests = [
            {"addSheet": {"properties": {"title": name}}}
            for name in self.TAB_HEADERS
            if name not in existing
        ]
        if add_requests:
            await self._request(
                "POST",
                f"https://sheets.googleapis.com/v4/spreadsheets/{self.config.google_sheet_id}:batchUpdate",
                json={"requests": add_requests},
            )
            metadata = await self._request(
                "GET",
                f"https://sheets.googleapis.com/v4/spreadsheets/{self.config.google_sheet_id}",
                params={"fields": "sheets.properties"},
            )
            existing = {
                sheet["properties"]["title"]: sheet["properties"]["sheetId"]
                for sheet in metadata.json().get("sheets", [])
            }

        data = []
        for tab, headers in self.TAB_HEADERS.items():
            data.append({"range": f"'{tab}'!A1", "values": [headers]})
        await self._request(
            "POST",
            f"https://sheets.googleapis.com/v4/spreadsheets/{self.config.google_sheet_id}/values:batchUpdate",
            json={"valueInputOption": "RAW", "data": data},
        )

        requests = []
        for tab, sheet_id in existing.items():
            if tab not in self.TAB_HEADERS:
                continue
            requests.extend(
                [
                    {
                        "repeatCell": {
                            "range": {"sheetId": sheet_id, "startRowIndex": 0, "endRowIndex": 1},
                            "cell": {
                                "userEnteredFormat": {
                                    "backgroundColor": {"red": 0.05, "green": 0.16, "blue": 0.30},
                                    "textFormat": {"foregroundColor": {"red": 1, "green": 1, "blue": 1}, "bold": True},
                                }
                            },
                            "fields": "userEnteredFormat(backgroundColor,textFormat)",
                        }
                    },
                    {
                        "updateSheetProperties": {
                            "properties": {"sheetId": sheet_id, "gridProperties": {"frozenRowCount": 1}},
                            "fields": "gridProperties.frozenRowCount",
                        }
                    },
                    {
                        "autoResizeDimensions": {
                            "dimensions": {
                                "sheetId": sheet_id,
                                "dimension": "COLUMNS",
                                "startIndex": 0,
                                "endIndex": len(self.TAB_HEADERS[tab]),
                            }
                        }
                    },
                ]
            )
        if requests:
            await self._request(
                "POST",
                f"https://sheets.googleapis.com/v4/spreadsheets/{self.config.google_sheet_id}:batchUpdate",
                json={"requests": requests},
            )

    async def append_rows(self, tab: str, rows: list[list]) -> None:
        if not self.configured or not rows:
            return
        encoded_range = quote(f"'{tab}'!A:Z", safe="")
        await self._request(
            "POST",
            f"https://sheets.googleapis.com/v4/spreadsheets/{self.config.google_sheet_id}/values/{encoded_range}:append",
            params={"valueInputOption": "RAW", "insertDataOption": "INSERT_ROWS"},
            json={"values": rows},
        )


class _ReadableHTML(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self.ignored_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "nav", "footer", "form", "noscript"}:
            self.ignored_depth += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style", "nav", "footer", "form", "noscript"} and self.ignored_depth:
            self.ignored_depth -= 1

    def handle_data(self, data):
        if not self.ignored_depth:
            value = " ".join(data.split())
            if value:
                self.parts.append(value)

    def text(self) -> str:
        return " ".join(self.parts)


def _trusted_url(url: str, trusted_domains: list[str]) -> bool:
    host = (urlparse(url).hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    if host in {"news.google.com", "trends.google.com"}:
        return False
    return any(host == domain or host.endswith("." + domain) for domain in trusted_domains)


def research_references_for_candidate(
    candidate: TopicCandidate,
    related: list[TopicCandidate],
) -> list[SourceReference]:
    references = list(candidate.source_references)
    for item in related:
        references.extend(item.source_references)
    references.extend(
        official_references_for_query(f"{candidate.title} {candidate.excerpt}")
    )
    unique = []
    seen = set()
    for reference in references:
        if reference.url and reference.url not in seen:
            unique.append(reference)
            seen.add(reference.url)
    return unique


class ResearchClient:
    def __init__(self, config: ContentAutomationConfig):
        self.config = config

    async def build_source_pack(
        self,
        candidate: TopicCandidate,
        related: list[TopicCandidate],
    ) -> list[SourceReference]:
        unique = research_references_for_candidate(candidate, related)

        headers = {"User-Agent": "ScamDekhoContentResearch/1.0 (+https://scamdekho.in)"}
        timeout = httpx.Timeout(self.config.request_timeout_seconds)
        researched = []
        researched_hosts = set()
        async with httpx.AsyncClient(headers=headers, timeout=timeout, follow_redirects=True) as client:
            for reference in unique[:12]:
                try:
                    response = await client.get(reference.url)
                    response.raise_for_status()
                    final_url = str(response.url)
                    if not _trusted_url(final_url, self.config.trusted_domains):
                        continue
                    final_host = (urlparse(final_url).hostname or "").lower()
                    if final_host in researched_hosts:
                        continue
                    parser = _ReadableHTML()
                    parser.feed(response.text[:1_000_000])
                    extracted = parser.text()[:8000]
                    researched.append(
                        SourceReference(
                            title=reference.title,
                            url=final_url,
                            publisher=reference.publisher,
                            excerpt=extracted or reference.excerpt,
                            published_at=reference.published_at,
                        )
                    )
                    researched_hosts.add(final_host)
                except Exception as exc:
                    original_host = (urlparse(reference.url).hostname or "").lower()
                    if (
                        _trusted_url(reference.url, self.config.trusted_domains)
                        and reference.excerpt
                        and original_host not in researched_hosts
                    ):
                        researched.append(reference)
                        researched_hosts.add(original_host)
                    else:
                        logger.debug("Research source skipped url=%s error=%s", reference.url, exc)
                if len(researched) >= self.config.maximum_sources:
                    break
        return researched


class WordPressClient:
    def __init__(self, config: ContentAutomationConfig):
        self.config = config
        raw = f"{config.wordpress_username}:{config.wordpress_application_password}"
        self.authorization = "Basic " + base64.b64encode(raw.encode("utf-8")).decode("ascii")

    def _headers(self) -> dict[str, str]:
        return {"Authorization": self.authorization, "Accept": "application/json"}

    async def internal_links(self, query: str, limit: int = 6) -> list[dict[str, str]]:
        url = f"{self.config.wordpress_url}/wp-json/wp/v2/search"
        links = product_links_for_query(query, self.config.site_url)
        try:
            async with httpx.AsyncClient(timeout=self.config.request_timeout_seconds) as client:
                response = await client.get(
                    url,
                    headers=self._headers(),
                    params={"search": query, "subtype": "post", "per_page": limit},
                )
                response.raise_for_status()
                links.extend([
                    {"title": html.unescape(item.get("title", "")), "url": item.get("url", "")}
                    for item in response.json()
                    if item.get("url")
                ])
        except Exception as exc:
            logger.warning("WordPress internal link lookup failed: %s", exc)
        unique = []
        seen = set()
        for item in links:
            if item["url"] not in seen:
                unique.append(item)
                seen.add(item["url"])
        return unique[:limit]

    async def find_post_by_slug(self, slug: str) -> dict | None:
        url = f"{self.config.wordpress_url}/wp-json/wp/v2/posts"
        async with httpx.AsyncClient(timeout=self.config.request_timeout_seconds) as client:
            response = await client.get(
                url,
                headers=self._headers(),
                params={"slug": slug, "status": "any", "context": "edit"},
            )
            response.raise_for_status()
            items = response.json()
            return items[0] if items else None

    async def create_draft(self, article: ArticleDraft) -> dict:
        existing = await self.find_post_by_slug(article.slug)
        if existing:
            return existing
        payload = build_wordpress_draft_payload(
            article,
            self.config.wordpress_category_ids,
        )
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(
                f"{self.config.wordpress_url}/wp-json/wp/v2/posts",
                headers=self._headers(),
                json=payload,
            )
            response.raise_for_status()
            return response.json()

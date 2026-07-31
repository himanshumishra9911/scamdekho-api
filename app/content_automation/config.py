from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from zoneinfo import ZoneInfo


DEFAULT_RELEVANCE_TERMS = (
    "scam,fraud,phishing,cybercrime,online safety,upi,otp,kyc,banking fraud,"
    "investment scam,job scam,shopping scam,loan scam,identity theft,deepfake,"
    "whatsapp scam,sms scam,email scam,fake website,digital arrest"
)

DEFAULT_NEWS_QUERIES = (
    "online scam India,cyber fraud India,UPI fraud,phishing India,"
    "fake website scam,WhatsApp scam India,digital arrest scam"
)

DEFAULT_RSS_FEEDS = (
    "https://www.bleepingcomputer.com/feed/,"
    "https://feeds.feedburner.com/TheHackersNews,"
    "https://krebsonsecurity.com/feed/"
)

DEFAULT_TRUSTED_DOMAINS = (
    "cert-in.org.in,cybercrime.gov.in,rbi.org.in,sebi.gov.in,pib.gov.in,"
    "mha.gov.in,consumerhelpline.gov.in,google.com,microsoft.com,cloudflare.com,"
    "krebsonsecurity.com,bleepingcomputer.com,thehackernews.com,indiatoday.in,"
    "indianexpress.com,thehindu.com,livemint.com,business-standard.com,"
    "economictimes.indiatimes.com"
)


def _csv(name: str, default: str = "") -> list[str]:
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default


def _bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class ContentAutomationConfig:
    enabled: bool = False
    max_drafts_per_day: int = 3
    quality_threshold: int = 75
    timezone_name: str = "Asia/Kolkata"
    site_url: str = "https://scamdekho.in"
    openai_api_key: str = ""
    content_model: str = "gpt-4.5-preview"
    wordpress_url: str = "https://scamdekho.in"
    wordpress_username: str = ""
    wordpress_application_password: str = ""
    wordpress_category_ids: list[int] = field(default_factory=list)
    gsc_property: str = "sc-domain:scamdekho.in"
    google_sheet_id: str = ""
    google_service_account_info: dict | None = None
    rss_feeds: list[str] = field(default_factory=list)
    news_queries: list[str] = field(default_factory=list)
    relevance_terms: list[str] = field(default_factory=list)
    trusted_domains: list[str] = field(default_factory=list)
    request_timeout_seconds: int = 20
    minimum_sources: int = 2
    maximum_sources: int = 4
    minimum_opportunity_score: int = 55
    max_candidates_per_source: int = 25
    voice_notes: str = ""

    @property
    def timezone(self) -> ZoneInfo:
        return ZoneInfo(self.timezone_name)

    @classmethod
    def from_env(cls) -> "ContentAutomationConfig":
        category_ids = []
        for value in _csv("WORDPRESS_CATEGORY_IDS"):
            try:
                category_ids.append(int(value))
            except ValueError:
                continue

        service_account_info = None
        raw_json = (os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON") or "").strip()
        raw_b64 = (os.getenv("GOOGLE_SERVICE_ACCOUNT_JSON_BASE64") or "").strip()
        try:
            if raw_json:
                service_account_info = json.loads(raw_json)
            elif raw_b64:
                decoded = base64.b64decode(raw_b64).decode("utf-8")
                service_account_info = json.loads(decoded)
        except (ValueError, json.JSONDecodeError):
            service_account_info = None

        return cls(
            enabled=_bool("CONTENT_AUTOMATION_ENABLED"),
            max_drafts_per_day=max(1, min(3, _int("CONTENT_MAX_DRAFTS_PER_DAY", 3))),
            quality_threshold=max(50, min(100, _int("CONTENT_QUALITY_THRESHOLD", 75))),
            timezone_name=os.getenv("CONTENT_TIMEZONE", "Asia/Kolkata"),
            site_url=os.getenv("PUBLIC_SITE_URL", "https://scamdekho.in").rstrip("/"),
            openai_api_key=os.getenv("OPENAI_API_KEY", ""),
            content_model=os.getenv("CONTENT_AI_MODEL", os.getenv("OPENAI_MODEL", "gpt-4.5-preview")),
            wordpress_url=os.getenv("WORDPRESS_URL", "https://scamdekho.in").rstrip("/"),
            wordpress_username=os.getenv("WORDPRESS_USERNAME", ""),
            wordpress_application_password=os.getenv("WORDPRESS_APPLICATION_PASSWORD", ""),
            wordpress_category_ids=category_ids,
            gsc_property=os.getenv("GSC_PROPERTY", "sc-domain:scamdekho.in"),
            google_sheet_id=os.getenv("GOOGLE_SHEET_ID", ""),
            google_service_account_info=service_account_info,
            rss_feeds=_csv("CONTENT_RSS_FEEDS", DEFAULT_RSS_FEEDS),
            news_queries=_csv("CONTENT_NEWS_QUERIES", DEFAULT_NEWS_QUERIES),
            relevance_terms=[item.lower() for item in _csv("CONTENT_RELEVANCE_TERMS", DEFAULT_RELEVANCE_TERMS)],
            trusted_domains=[item.lower() for item in _csv("CONTENT_TRUSTED_DOMAINS", DEFAULT_TRUSTED_DOMAINS)],
            request_timeout_seconds=max(5, _int("CONTENT_REQUEST_TIMEOUT_SECONDS", 20)),
            minimum_sources=max(2, min(4, _int("CONTENT_MINIMUM_SOURCES", 2))),
            maximum_sources=max(2, min(4, _int("CONTENT_MAXIMUM_SOURCES", 4))),
            minimum_opportunity_score=max(0, min(100, _int("CONTENT_MIN_OPPORTUNITY_SCORE", 55))),
            max_candidates_per_source=max(5, _int("CONTENT_MAX_CANDIDATES_PER_SOURCE", 25)),
            voice_notes=os.getenv("CONTENT_VOICE_NOTES", "").strip(),
        )

    def validate_for_run(self, dry_run: bool = False) -> list[str]:
        errors = []
        if not dry_run and not self.enabled:
            errors.append("CONTENT_AUTOMATION_ENABLED must be true")
        if not self.openai_api_key:
            errors.append("OPENAI_API_KEY is required")
        if not dry_run:
            if not self.wordpress_username:
                errors.append("WORDPRESS_USERNAME is required")
            if not self.wordpress_application_password:
                errors.append("WORDPRESS_APPLICATION_PASSWORD is required")
        return errors

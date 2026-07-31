from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def normalize_topic(value: str) -> str:
    words = re.findall(r"[a-z0-9]+", (value or "").lower())
    stop_words = {
        "a", "an", "and", "are", "for", "from", "how", "in", "is", "of",
        "on", "the", "to", "what", "when", "with", "your",
    }
    return " ".join(word for word in words if word not in stop_words)


def topic_key(value: str) -> str:
    normalized = normalize_topic(value)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


@dataclass
class SourceReference:
    title: str
    url: str
    publisher: str
    excerpt: str = ""
    published_at: datetime | None = None

    def as_prompt_text(self, index: int) -> str:
        published = self.published_at.isoformat() if self.published_at else "unknown"
        return (
            f"[S{index}] Publisher: {self.publisher}\n"
            f"Title: {self.title}\nPublished: {published}\n"
            f"URL: {self.url}\nNotes: {self.excerpt[:4000]}"
        )


@dataclass
class TopicCandidate:
    title: str
    source_type: str
    source_name: str
    url: str
    published_at: datetime | None = None
    excerpt: str = ""
    primary_keyword: str = ""
    secondary_keywords: list[str] = field(default_factory=list)
    impressions: float = 0.0
    clicks: float = 0.0
    ctr: float = 0.0
    position: float = 0.0
    growth: float = 0.0
    opportunity_score: float = 0.0
    why_chosen: str = ""
    source_references: list[SourceReference] = field(default_factory=list)

    @property
    def key(self) -> str:
        return topic_key(self.title)

    def ensure_reference(self) -> None:
        if not self.url:
            return
        if any(item.url == self.url for item in self.source_references):
            return
        self.source_references.append(
            SourceReference(
                title=self.title,
                url=self.url,
                publisher=self.source_name,
                excerpt=self.excerpt,
                published_at=self.published_at,
            )
        )


@dataclass
class ArticleDraft:
    title: str
    slug: str
    meta_description: str
    excerpt: str
    content_html: str
    primary_keyword: str
    secondary_keywords: list[str]
    faqs: list[dict[str, str]]
    schema: dict[str, Any]
    references: list[SourceReference]


@dataclass
class QualityReport:
    score: int
    passed: bool
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineSummary:
    run_key: str
    candidates_collected: int = 0
    candidates_after_dedup: int = 0
    selected: int = 0
    drafts_created: int = 0
    skipped: int = 0
    failed: int = 0
    draft_urls: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None


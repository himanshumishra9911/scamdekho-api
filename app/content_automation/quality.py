from __future__ import annotations

import re
from html import unescape
from urllib.parse import urlparse

from app.content_automation.models import ArticleDraft, QualityReport


ROBOTIC_PHRASES = (
    "in today's digital age",
    "in the ever-evolving landscape",
    "it is important to note",
    "delve into",
    "in conclusion",
    "this comprehensive guide",
    "game-changer",
)


def _plain_text(value: str) -> str:
    return " ".join(unescape(re.sub(r"<[^>]+>", " ", value or "")).split())


def _links(value: str) -> list[str]:
    return re.findall(r'href=["\']([^"\']+)["\']', value or "", flags=re.I)


class QualityGate:
    def __init__(self, site_url: str, threshold: int):
        self.site_host = (urlparse(site_url).hostname or "").lower()
        self.threshold = threshold

    def evaluate(self, article: ArticleDraft) -> QualityReport:
        score = 0
        issues = []
        warnings = []
        text = _plain_text(article.content_html)
        words = re.findall(r"\b[\w'-]+\b", text)
        word_count = len(words)
        h2_count = len(re.findall(r"<h2\b", article.content_html, flags=re.I))
        links = _links(article.content_html)
        internal_links = [url for url in links if (urlparse(url).hostname or "").lower() == self.site_host]
        source_links = list(dict.fromkeys(reference.url for reference in article.references if reference.url))
        lowered = text.lower()

        if 900 <= word_count <= 1800:
            score += 15
        elif 750 <= word_count <= 2100:
            score += 8
            warnings.append(f"Article length is {word_count} words")
        else:
            issues.append(f"Article length is {word_count} words; expected 900-1800")

        if 35 <= len(article.title) <= 70:
            score += 10
        else:
            issues.append(f"Title length is {len(article.title)} characters")

        if 120 <= len(article.meta_description) <= 160:
            score += 10
        else:
            issues.append(f"Meta description length is {len(article.meta_description)} characters")

        if h2_count >= 4:
            score += 10
        else:
            issues.append(f"Only {h2_count} H2 sections found")

        if 3 <= len(article.faqs) <= 5:
            score += 10
        else:
            issues.append(f"FAQ count is {len(article.faqs)}; expected 3-5")

        if len(article.references) >= 2 and len(source_links) >= 2:
            score += 20
        else:
            issues.append("Fewer than two independent source references")

        if len(internal_links) >= 2:
            score += 10
        elif internal_links:
            score += 5
            warnings.append("Only one internal link was found")
        else:
            warnings.append("No relevant internal links were available")

        if article.primary_keyword and article.primary_keyword.lower() in lowered:
            score += 5
        else:
            warnings.append("Primary keyword is not present naturally in the article")

        robotic = [phrase for phrase in ROBOTIC_PHRASES if phrase in lowered]
        placeholders = re.findall(r"\b(?:todo|tbd|lorem ipsum|insert link|placeholder)\b", lowered)
        if not robotic and not placeholders:
            score += 10
        else:
            if robotic:
                warnings.append("Robotic phrases found: " + ", ".join(robotic))
            if placeholders:
                issues.append("Draft contains unfinished placeholders")

        if not re.search(r"<\s*(?:iframe|object|embed)\b", article.content_html, flags=re.I):
            score += 5
        else:
            issues.append("Unsafe embedded content found")

        score = min(100, score)
        return QualityReport(
            score=score,
            passed=score >= self.threshold and not any("placeholder" in item.lower() for item in issues),
            issues=issues,
            warnings=warnings,
            metrics={
                "word_count": word_count,
                "h2_count": h2_count,
                "faq_count": len(article.faqs),
                "internal_link_count": len(internal_links),
                "source_count": len(source_links),
            },
        )

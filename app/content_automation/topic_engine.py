from __future__ import annotations

import math
import re
from collections import defaultdict
from datetime import datetime, timezone

from app.content_automation.config import ContentAutomationConfig
from app.content_automation.models import TopicCandidate, normalize_topic


def _tokens(value: str) -> set[str]:
    return set(normalize_topic(value).split())


def similarity(left: str, right: str) -> float:
    a = _tokens(left)
    b = _tokens(right)
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def is_relevant(candidate: TopicCandidate, terms: list[str]) -> bool:
    text = f"{candidate.title} {candidate.excerpt}".lower()
    return any(term in text for term in terms)


def _recency_points(published_at: datetime | None) -> int:
    if not published_at:
        return 2
    if published_at.tzinfo is None:
        published_at = published_at.replace(tzinfo=timezone.utc)
    age_days = max(0, (datetime.now(timezone.utc) - published_at).days)
    if age_days <= 1:
        return 15
    if age_days <= 3:
        return 11
    if age_days <= 7:
        return 7
    if age_days <= 30:
        return 3
    return 0


def score_candidate(candidate: TopicCandidate) -> float:
    score = 20 + _recency_points(candidate.published_at)
    score += {"gsc": 15, "trends": 15, "news": 10, "rss": 7}.get(candidate.source_type, 0)

    if candidate.impressions:
        score += min(20, math.log10(candidate.impressions + 1) * 6)
    if candidate.impressions >= 20 and candidate.ctr < 0.03:
        score += 12
    if 4 <= candidate.position <= 30:
        score += 10
    if candidate.growth > 0:
        score += min(12, candidate.growth * 12)
    score += min(8, max(0, len(candidate.source_references) - 1) * 4)
    return round(min(100, score), 1)


def _primary_keyword(title: str) -> str:
    cleaned = normalize_topic(title)
    return " ".join(cleaned.split()[:7])


def consolidate_candidates(
    candidates: list[TopicCandidate],
    config: ContentAutomationConfig,
) -> list[TopicCandidate]:
    relevant = [item for item in candidates if is_relevant(item, config.relevance_terms)]
    groups: list[list[TopicCandidate]] = []
    for candidate in relevant:
        candidate.ensure_reference()
        for group in groups:
            if similarity(candidate.title, group[0].title) >= 0.48:
                group.append(candidate)
                break
        else:
            groups.append([candidate])

    merged = []
    for group in groups:
        group.sort(key=lambda item: (item.impressions, item.published_at or datetime.min.replace(tzinfo=timezone.utc)), reverse=True)
        winner = group[0]
        references = []
        seen_urls = set()
        source_types = set()
        for item in group:
            source_types.add(item.source_type)
            for reference in item.source_references:
                if reference.url and reference.url not in seen_urls:
                    references.append(reference)
                    seen_urls.add(reference.url)
        winner.source_references = references[: config.maximum_sources]
        winner.primary_keyword = winner.primary_keyword or _primary_keyword(winner.title)
        winner.secondary_keywords = list(
            dict.fromkeys(
                keyword
                for item in group
                for keyword in ([item.primary_keyword] + item.secondary_keywords)
                if keyword and keyword != winner.primary_keyword
            )
        )[:8]
        winner.opportunity_score = score_candidate(winner)
        reasons = [f"{winner.source_type.upper()} signal"]
        if len(source_types) > 1:
            reasons.append(f"confirmed across {len(source_types)} source types")
        if winner.impressions:
            reasons.append(f"{int(winner.impressions)} GSC impressions")
        if winner.impressions >= 20 and winner.ctr < 0.03:
            reasons.append("high impressions with CTR improvement opportunity")
        if winner.growth > 0:
            reasons.append("search demand is rising")
        reasons.append(f"opportunity score {winner.opportunity_score}/100")
        winner.why_chosen = "; ".join(reasons)
        merged.append(winner)

    return sorted(merged, key=lambda item: item.opportunity_score, reverse=True)


def find_related_candidates(
    selected: TopicCandidate,
    all_candidates: list[TopicCandidate],
    limit: int = 8,
) -> list[TopicCandidate]:
    scored = []
    for candidate in all_candidates:
        if candidate.key == selected.key:
            continue
        value = similarity(selected.title, candidate.title)
        if value > 0.18:
            scored.append((value, candidate))
    scored.sort(key=lambda item: item[0], reverse=True)
    return [item[1] for item in scored[:limit]]

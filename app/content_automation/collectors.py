from __future__ import annotations

import asyncio
import html
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import quote_plus, urlparse

from app.content_automation.config import ContentAutomationConfig
from app.content_automation.models import SourceReference, TopicCandidate

logger = logging.getLogger(__name__)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _text(node: ET.Element | None) -> str:
    if node is None:
        return ""
    return " ".join("".join(node.itertext()).split())


def _clean_html(value: str) -> str:
    without_tags = re.sub(r"<[^>]+>", " ", value or "")
    return " ".join(html.unescape(without_tags).split())


def _parse_date(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        pass
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def parse_feed(xml_text: str, source_type: str, source_name: str) -> list[TopicCandidate]:
    root = ET.fromstring(xml_text)
    entries = [node for node in root.iter() if _local_name(node.tag) in {"item", "entry"}]
    candidates = []
    for entry in entries:
        children = {_local_name(child.tag): child for child in list(entry)}
        title = _text(children.get("title"))
        link_node = children.get("link")
        link = ""
        if link_node is not None:
            link = link_node.attrib.get("href") or _text(link_node)
        excerpt = _clean_html(
            _text(children.get("description"))
            or _text(children.get("summary"))
            or _text(children.get("content"))
        )
        published = _parse_date(
            _text(children.get("pubdate"))
            or _text(children.get("published"))
            or _text(children.get("updated"))
        )
        publisher = _text(children.get("source")) or source_name
        if not title or not link:
            continue
        candidate = TopicCandidate(
            title=title,
            source_type=source_type,
            source_name=publisher,
            url=link,
            published_at=published,
            excerpt=excerpt,
        )
        candidate.ensure_reference()
        candidates.append(candidate)
    return candidates


async def _fetch_feed(
    client: httpx.AsyncClient,
    url: str,
    source_type: str,
    source_name: str,
) -> list[TopicCandidate]:
    try:
        response = await client.get(url)
        response.raise_for_status()
        return parse_feed(response.text, source_type, source_name)
    except Exception as exc:
        logger.warning("Content feed failed url=%s error=%s", url, exc)
        return []


async def collect_rss(
    client: httpx.AsyncClient,
    config: ContentAutomationConfig,
) -> list[TopicCandidate]:
    tasks = []
    for feed_url in config.rss_feeds:
        host = urlparse(feed_url).hostname or "RSS"
        tasks.append(_fetch_feed(client, feed_url, "rss", host))
    if not tasks:
        return []
    groups = await asyncio.gather(*tasks)
    return [item for group in groups for item in group[: config.max_candidates_per_source]]


async def collect_news(
    client: httpx.AsyncClient,
    config: ContentAutomationConfig,
) -> list[TopicCandidate]:
    tasks = []
    for query in config.news_queries:
        url = (
            "https://news.google.com/rss/search?q="
            f"{quote_plus(query)}&hl=en-IN&gl=IN&ceid=IN:en"
        )
        tasks.append(_fetch_feed(client, url, "news", "Google News"))
    groups = await asyncio.gather(*tasks)
    return [item for group in groups for item in group[: config.max_candidates_per_source]]


async def collect_trends(
    client: httpx.AsyncClient,
    config: ContentAutomationConfig,
) -> list[TopicCandidate]:
    url = "https://trends.google.com/trending/rss?geo=IN"
    items = await _fetch_feed(client, url, "trends", "Google Trends")
    return items[: config.max_candidates_per_source]


def trusted_source(reference: SourceReference, trusted_domains: list[str]) -> bool:
    hostname = (urlparse(reference.url).hostname or "").lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return any(hostname == item or hostname.endswith("." + item) for item in trusted_domains)


async def collect_all_public_sources(
    config: ContentAutomationConfig,
) -> list[TopicCandidate]:
    import httpx

    headers = {
        "User-Agent": "ScamDekhoContentResearch/1.0 (+https://scamdekho.in)",
        "Accept": "application/rss+xml, application/xml, text/xml, */*",
    }
    timeout = httpx.Timeout(config.request_timeout_seconds)
    async with httpx.AsyncClient(headers=headers, timeout=timeout, follow_redirects=True) as client:
        rss, news, trends = await asyncio.gather(
            collect_rss(client, config),
            collect_news(client, config),
            collect_trends(client, config),
        )
    return rss + news + trends

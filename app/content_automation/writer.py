from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone

from openai import AsyncOpenAI

from app.content_automation.config import ContentAutomationConfig
from app.content_automation.models import ArticleDraft, SourceReference, TopicCandidate


def slugify(value: str) -> str:
    value = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return value[:75].strip("-") or "scam-safety-update"


def _sanitize_html(value: str) -> str:
    value = re.sub(r"<\s*(script|iframe|object|embed)[^>]*>.*?<\s*/\s*\1\s*>", "", value, flags=re.I | re.S)
    value = re.sub(r"\son\w+\s*=\s*(['\"]).*?\1", "", value, flags=re.I | re.S)
    return value.strip()


def _references_html(references: list[SourceReference]) -> str:
    items = []
    for reference in references:
        title = html.escape(reference.title or reference.publisher)
        publisher = html.escape(reference.publisher)
        url = html.escape(reference.url, quote=True)
        items.append(
            f'<li><a href="{url}" rel="nofollow noopener" target="_blank">{title}</a> '
            f"({publisher})</li>"
        )
    return "<h2>Sources reviewed</h2><ol>" + "".join(items) + "</ol>"


def _related_html(links: list[dict[str, str]]) -> str:
    items = []
    for link in links[:5]:
        title = html.escape(link.get("title") or "Related ScamDekho guide")
        url = html.escape(link.get("url") or "", quote=True)
        if url:
            items.append(f'<li><a href="{url}">{title}</a></li>')
    if not items:
        return ""
    return "<h2>Related ScamDekho guides</h2><ul>" + "".join(items) + "</ul>"


def _schema(article: dict, config: ContentAutomationConfig) -> dict:
    faqs = article.get("faqs") or []
    faq_entities = [
        {
            "@type": "Question",
            "name": item.get("question", ""),
            "acceptedAnswer": {"@type": "Answer", "text": item.get("answer", "")},
        }
        for item in faqs
        if item.get("question") and item.get("answer")
    ]
    return {
        "@context": "https://schema.org",
        "@graph": [
            {
                "@type": "Article",
                "headline": article.get("title", ""),
                "description": article.get("meta_description", ""),
                "author": {"@type": "Organization", "name": "ScamDekho"},
                "publisher": {"@type": "Organization", "name": "ScamDekho"},
                "dateCreated": datetime.now(timezone.utc).date().isoformat(),
            },
            {"@type": "FAQPage", "mainEntity": faq_entities},
        ],
    }


class ArticleWriter:
    def __init__(self, config: ContentAutomationConfig):
        self.config = config
        self.client = AsyncOpenAI(api_key=config.openai_api_key)

    async def write(
        self,
        candidate: TopicCandidate,
        references: list[SourceReference],
        internal_links: list[dict[str, str]],
    ) -> ArticleDraft:
        source_pack = "\n\n".join(
            reference.as_prompt_text(index)
            for index, reference in enumerate(references, start=1)
        )
        link_pack = "\n".join(
            f"- {item.get('title', '')}: {item.get('url', '')}"
            for item in internal_links[:8]
        ) or "No relevant existing internal links were found."
        voice = self.config.voice_notes or (
            "Clear, calm, practical Indian consumer-safety journalism. Use plain English, "
            "specific examples, short paragraphs, and a helpful but not alarmist tone."
        )
        prompt = f"""
Create a WordPress draft for ScamDekho.

TOPIC: {candidate.title}
WHY SELECTED: {candidate.why_chosen}
TARGET PRIMARY KEYWORD: {candidate.primary_keyword}
SUGGESTED SECONDARY KEYWORDS: {', '.join(candidate.secondary_keywords)}
VOICE: {voice}

SOURCE PACK:
{source_pack}

APPROVED INTERNAL LINKS:
{link_pack}

Rules:
1. Use only facts supported by the source pack. Never invent statistics, quotes, victims, dates, or official advice.
2. Attribute reports and claims to the named source. Distinguish allegation, warning, and confirmed fact.
3. Write 900-1600 useful words. Avoid filler, keyword stuffing, hype, and robotic phrases.
4. Include a direct introduction, at least four useful H2 sections, practical safety checks, and 3-5 FAQs.
5. Do not add an H1; WordPress supplies the title. Do not include scripts, schema, source links, or a references section in html.
6. Use only approved internal URLs. Add 2-4 natural internal links when relevant; otherwise omit rather than inventing links.
7. This is a draft for human review. Do not claim that ScamDekho independently verified facts unless the source pack says so.

Return only a JSON object with this shape:
{{
  "title": "35-70 character SEO title",
  "slug": "lowercase-hyphen-slug",
  "meta_description": "120-160 character factual description",
  "excerpt": "one short factual summary",
  "primary_keyword": "keyword",
  "secondary_keywords": ["keyword 1", "keyword 2"],
  "html": "article HTML using p, h2, h3, ul, ol, strong and a tags",
  "faqs": [{{"question": "...", "answer": "..."}}]
}}
""".strip()
        response = await self.client.chat.completions.create(
            model=self.config.content_model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are ScamDekho's careful cybersecurity editor. Produce source-grounded, "
                        "natural editorial drafts in valid JSON. Accuracy is more important than volume."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=3800,
            response_format={"type": "json_object"},
        )
        data = json.loads(response.choices[0].message.content)
        article_schema = _schema(data, self.config)
        body = _sanitize_html(data.get("html", ""))
        body += _related_html(internal_links)
        body += _references_html(references)
        schema_json = json.dumps(article_schema, ensure_ascii=True).replace("<", "\\u003c")
        body += (
            '<script type="application/ld+json">'
            + schema_json
            + "</script>"
        )
        title = " ".join(str(data.get("title") or candidate.title).split())
        return ArticleDraft(
            title=title,
            slug=slugify(data.get("slug") or title),
            meta_description=" ".join(str(data.get("meta_description") or "").split()),
            excerpt=" ".join(str(data.get("excerpt") or "").split()),
            content_html=body,
            primary_keyword=" ".join(str(data.get("primary_keyword") or candidate.primary_keyword).split()),
            secondary_keywords=[
                " ".join(str(item).split())
                for item in (data.get("secondary_keywords") or candidate.secondary_keywords)
                if str(item).strip()
            ][:8],
            faqs=[item for item in (data.get("faqs") or []) if isinstance(item, dict)],
            schema=article_schema,
            references=references,
        )

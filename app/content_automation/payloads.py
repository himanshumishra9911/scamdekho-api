from __future__ import annotations

from app.content_automation.models import ArticleDraft


def build_wordpress_draft_payload(
    article: ArticleDraft,
    category_ids: list[int],
) -> dict:
    payload = {
        "status": "draft",
        "title": article.title,
        "slug": article.slug,
        "excerpt": article.meta_description,
        "content": article.content_html,
    }
    if category_ids:
        payload["categories"] = category_ids
    return payload

import html as html_lib
import logging
from datetime import datetime

from fastapi import APIRouter
from fastapi.responses import Response

from app.services.public_pages_service import get_recent_pages, pages_collection

router = APIRouter()
logger = logging.getLogger(__name__)

SITE = "https://scamdekho.in"
SITEMAP_PAGE_SIZE = 50000
SITEMAP_HEADERS = {"Cache-Control": "no-store, max-age=0"}


def esc(value) -> str:
    return html_lib.escape(str(value or ""))


async def _find_sitemap_docs(skip: int, limit: int, sort_field: str | None) -> list:
    projection = {"domain": 1, "last_scanned": 1, "first_scanned": 1}
    cursor = pages_collection.find({}, projection)
    if sort_field:
        cursor = cursor.sort(sort_field, -1)
    cursor = cursor.skip(skip).limit(limit)
    return [doc async for doc in cursor]


async def _fetch_sitemap_docs(skip: int, limit: int) -> list:
    """Fetch sitemap docs with fallbacks so the XML is never empty while pages exist."""
    for sort_field in ("last_scanned", "first_scanned", None):
        try:
            docs = await _find_sitemap_docs(skip, limit, sort_field)
            if docs or skip > 0:
                return docs
        except Exception as exc:
            logger.warning("Sitemap query failed using %s sort: %s", sort_field, exc)

    # recent-checks is proven live in production; use it as a final page-0 fallback.
    if skip == 0:
        for fallback_limit in (min(limit, 50000), 1000, 100, 10):
            try:
                docs = await get_recent_pages(limit=fallback_limit)
                if docs:
                    return docs
            except Exception as exc:
                logger.warning("Recent sitemap fallback failed at limit %s: %s", fallback_limit, exc)

    return []


def _lastmod(doc: dict) -> str:
    scanned_at = doc.get("last_scanned") or doc.get("first_scanned")
    if isinstance(scanned_at, datetime):
        return f"<lastmod>{scanned_at.strftime('%Y-%m-%d')}</lastmod>"
    return ""


def _urlset_xml(items: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"{items}</urlset>"
    )


@router.get("/sitemap-index.xml", include_in_schema=False)
async def sitemap_index():
    try:
        total = await pages_collection.count_documents({})
    except Exception as exc:
        logger.warning("Sitemap count failed: %s", exc)
        total = 0

    if total <= 0:
        try:
            total = len(await get_recent_pages(limit=SITEMAP_PAGE_SIZE))
        except Exception as exc:
            logger.warning("Sitemap count fallback failed: %s", exc)
            total = 0

    page_count = max(1, (total + SITEMAP_PAGE_SIZE - 1) // SITEMAP_PAGE_SIZE)
    items = "".join(
        f"<sitemap><loc>{SITE}/sitemap-checks-{page}.xml</loc></sitemap>"
        for page in range(page_count)
    )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"{items}</sitemapindex>"
    )
    return Response(content=xml, media_type="application/xml", headers=SITEMAP_HEADERS)


@router.get("/sitemap-checks-{page}.xml", include_in_schema=False)
async def sitemap_checks_paginated(page: int):
    if page < 0:
        return Response(
            content=_urlset_xml(""),
            media_type="application/xml",
            status_code=404,
            headers=SITEMAP_HEADERS,
        )

    docs = await _fetch_sitemap_docs(page * SITEMAP_PAGE_SIZE, SITEMAP_PAGE_SIZE)
    items = ""
    for doc in docs:
        domain = doc.get("domain") or doc.get("_id")
        if not domain:
            continue
        items += (
            f"<url><loc>{SITE}/check/{esc(domain)}</loc>{_lastmod(doc)}"
            "<changefreq>weekly</changefreq><priority>0.6</priority></url>"
        )

    return Response(
        content=_urlset_xml(items),
        media_type="application/xml",
        headers=SITEMAP_HEADERS,
    )


@router.get("/sitemap-checks.xml", include_in_schema=False)
async def sitemap_checks_legacy():
    return await sitemap_checks_paginated(0)

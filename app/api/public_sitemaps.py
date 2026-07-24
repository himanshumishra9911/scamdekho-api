import html as html_lib
import logging
from datetime import datetime

from fastapi import APIRouter
from fastapi.responses import Response

from app.services.public_pages_service import get_recent_pages, pages_collection

router = APIRouter()
logger = logging.getLogger(__name__)

SITE = "https://scamdekho.in"
SITEMAP_PAGE_SIZE = 5000


def esc(value) -> str:
    return html_lib.escape(str(value or ""))


async def _fetch_sitemap_docs(skip: int, limit: int) -> list:
    """Fetch sitemap docs; fallback keeps XML populated if the primary query is empty."""
    projection = {"domain": 1, "last_scanned": 1, "first_scanned": 1}
    try:
        cursor = pages_collection.find({"indexable": True}, projection).sort(
            "last_scanned", -1
        ).skip(skip).limit(limit)
        docs = [doc async for doc in cursor]
        if docs or skip > 0:
            return docs
    except Exception as exc:
        logger.warning("Primary sitemap query failed: %s", exc)

    # The recent-checks path is already working in production, so reuse it as a safe fallback.
    if skip == 0:
        docs = await get_recent_pages(limit=limit)
        if docs:
            return docs

    try:
        cursor = pages_collection.find({"indexable": True}, projection).sort(
            "first_scanned", -1
        ).skip(skip).limit(limit)
        return [doc async for doc in cursor]
    except Exception as exc:
        logger.error("Fallback sitemap query failed: %s", exc)
        return []


def _urlset_xml(items: str) -> str:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        f"{items}</urlset>"
    )


@router.get("/sitemap-index.xml", include_in_schema=False)
async def sitemap_index():
    try:
        total = await pages_collection.count_documents({"indexable": True})
    except Exception as exc:
        logger.warning("Sitemap count failed: %s", exc)
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
    return Response(content=xml, media_type="application/xml")


@router.get("/sitemap-checks-{page}.xml", include_in_schema=False)
async def sitemap_checks_paginated(page: int):
    if page < 0:
        return Response(
            content=_urlset_xml(""), media_type="application/xml", status_code=404
        )

    docs = await _fetch_sitemap_docs(page * SITEMAP_PAGE_SIZE, SITEMAP_PAGE_SIZE)
    items = ""
    for doc in docs:
        domain = doc.get("domain") or doc.get("_id")
        if not domain:
            continue

        lastmod = ""
        last_scanned = doc.get("last_scanned") or doc.get("first_scanned")
        if isinstance(last_scanned, datetime):
            lastmod = f"<lastmod>{last_scanned.strftime('%Y-%m-%d')}</lastmod>"

        items += (
            f"<url><loc>{SITE}/check/{esc(domain)}</loc>{lastmod}"
            "<changefreq>weekly</changefreq><priority>0.6</priority></url>"
        )

    return Response(content=_urlset_xml(items), media_type="application/xml")


@router.get("/sitemap-checks.xml", include_in_schema=False)
async def sitemap_checks_legacy():
    return await sitemap_checks_paginated(0)

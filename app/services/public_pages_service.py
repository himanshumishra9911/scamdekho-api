"""
Public Pages Service — ScamDekho
=================================
Har URL scan ko ek public /check/{domain} page document me save karta hai.
Quality score decide karta hai ki page Google me INDEX hoga ya NOINDEX.

File location: app/services/public_pages_service.py
"""

import re
import logging
from datetime import datetime
from urllib.parse import urlparse
from app.core.database import db

logger = logging.getLogger(__name__)

pages_collection = db["public_pages"]

# ──────────────────────────────────────────────
# DOMAINS JINKE PAGES KABHI NAHI BANENGE
# ──────────────────────────────────────────────
BLOCKED_PATTERNS = re.compile(
    r"porn|xxx|sex|hentai|nude|escort|onlyfans|fap|milf|xvideo|xnxx|"
    r"redtube|brazzer|camgirl|chaturbate|stripchat|bongacams",
    re.IGNORECASE,
)
IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
LOCALHOST_PATTERN = re.compile(r"localhost|127\.0\.0\.1|0\.0\.0\.0|192\.168\.|10\.\d+\.")


def normalize_domain(url_or_domain: str) -> str | None:
    """URL/domain ko ek canonical domain me convert karo. Invalid → None."""
    d = (url_or_domain or "").strip().lower()
    if d.startswith("http://") or d.startswith("https://"):
        d = urlparse(d).netloc
    d = d.split("/")[0].split(":")[0].strip()
    if d.startswith("www."):
        d = d[4:]
    if not d or "." not in d or len(d) > 100:
        return None
    if IP_PATTERN.match(d) or LOCALHOST_PATTERN.search(d):
        return None
    if BLOCKED_PATTERNS.search(d):
        return None
    # Sirf valid domain chars
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", d):
        return None
    return d


def calculate_page_quality(result: dict) -> dict:
    """
    Decide karo page index-worthy hai ya nahi.
    Returns: {"indexable": bool, "reasons": [...], "quality_score": int}
    """
    reasons = []
    points = 0

    other = result.get("other_info") or {}
    summary = result.get("summary") or {}
    sources = result.get("sources") or []
    explanation = result.get("explanation") or []
    why = result.get("why") or []

    # 1. Domain resolve hua? (IP mila)
    if other.get("ip_address"):
        points += 2
    else:
        reasons.append("no_ip")

    # 2. Domain age data mila?
    created = other.get("domain_created")
    if created and created not in ("Unknown", "", None):
        points += 2
    else:
        reasons.append("no_domain_age")

    # 3. SSL data mila?
    ssl_issuer = other.get("ssl_issuer")
    if ssl_issuer and ssl_issuer not in ("Unknown", "", None):
        points += 1

    # 4. Kitne sources ne actual data diya (non-neutral)?
    decided = (summary.get("positive_signals", 0) or 0) + (summary.get("negative_signals", 0) or 0)
    if decided >= 6:
        points += 3
    elif decided >= 4:
        points += 1
        reasons.append("few_decided_sources")
    else:
        reasons.append("too_few_decided_sources")

    # 5. Explanation/AI text content kaafi hai?
    text_items = len(explanation) + len(why)
    if text_items >= 4:
        points += 2
    elif text_items >= 2:
        points += 1
    else:
        reasons.append("thin_text")

    # 6. Sources list render karne layak?
    if len(sources) >= 10:
        points += 1

    # INDEX RULE: 8+ points = indexable
    indexable = points >= 8
    return {"indexable": indexable, "quality_score": points, "reasons": reasons}


async def save_public_scan(url: str, result: dict) -> None:
    """
    Har successful URL scan ke baad call hota hai (cache_service se hook).
    Public page document upsert karta hai. Silently fails — kabhi scan break nahi karega.
    """
    try:
        domain = normalize_domain(result.get("domain") or url)
        if not domain:
            return

        quality = calculate_page_quality(result)

        # Result se heavy/private cheezein hatao
        clean_result = {
            k: v for k, v in result.items()
            if k not in ("screenshot_bytes", "technical_report", "from_cache")
        }

        now = datetime.utcnow()
        await pages_collection.update_one(
            {"_id": domain},
            {
                "$set": {
                    "domain": domain,
                    "result": clean_result,
                    "indexable": quality["indexable"],
                    "quality_score": quality["quality_score"],
                    "quality_reasons": quality["reasons"],
                    "last_scanned": now,
                },
                "$setOnInsert": {"first_scanned": now},
                "$inc": {"scan_count": 1},
            },
            upsert=True,
        )
    except Exception as e:
        logger.error(f"save_public_scan failed for {url}: {e}")


async def get_public_page(domain: str) -> dict | None:
    d = normalize_domain(domain)
    if not d:
        return None
    try:
        return await pages_collection.find_one({"_id": d})
    except Exception:
        return None


async def get_recent_pages(limit: int = 10) -> list:
    """Recently checked indexable domains — widget + related links ke liye."""
    try:
        cursor = pages_collection.find(
            {"indexable": True},
            {"domain": 1, "result.trust_score": 1, "result.verdict": 1, "last_scanned": 1},
        ).sort("last_scanned", -1).limit(limit)
        return [doc async for doc in cursor]
    except Exception:
        return []


async def get_indexable_domains_for_sitemap(limit: int = 5000) -> list:
    try:
        cursor = pages_collection.find(
            {"indexable": True},
            {"domain": 1, "last_scanned": 1},
        ).sort("last_scanned", -1).limit(limit)
        return [doc async for doc in cursor]
    except Exception:
        return []

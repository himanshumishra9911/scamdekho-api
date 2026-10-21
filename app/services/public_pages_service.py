"""
Public Pages Service — ScamDekho
=================================
Har URL scan ko ek public /check/{domain} page document me save karta hai.
Ek page tabhi INDEX hota hai jab (a) domain khud allowed ho — major brand,
shortener ya throwaway host na ho — aur (b) scan ne itna data nikala ho ki
page reader ko kuch bataye, ya us domain ki already proven search demand ho.

File location: app/services/public_pages_service.py
"""

import re
import logging
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse
from app.core.database import db

logger = logging.getLogger(__name__)

pages_collection = db["public_pages"]


class PublicPageStorageUnavailable(RuntimeError):
    """The report lookup failed; this is not evidence that a page is missing."""

# ──────────────────────────────────────────────
# ADULT DOMAIN TEXT CATEGORY LABELS
# ──────────────────────────────────────────────
ADULT_CONTENT_PATTERNS = re.compile(
    r"porn|xxx|sex|hentai|nude|escort|onlyfans|fap|milf|xvideo|xnxx|"
    r"redtube|brazzer|camgirl|chaturbate|stripchat|bongacams",
    re.IGNORECASE,
)
IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
LOCALHOST_PATTERN = re.compile(r"localhost|127\.0\.0\.1|0\.0\.0\.0|192\.168\.|10\.\d+\.")

# ──────────────────────────────────────────────
# PROVEN SEARCH DEMAND
# Domains whose /check/ page actually earned organic clicks. These skip the
# quality gate: real demand outranks our heuristic, and deindexing an earner
# to satisfy a rule costs more than the rule saves.
# ──────────────────────────────────────────────
SEARCH_DEMAND_FILE = Path(__file__).resolve().parents[1] / "data" / "search_demand_domains.txt"


@lru_cache(maxsize=1)
def load_search_demand_domains() -> frozenset[str]:
    """Domains with proven organic clicks. Missing file → empty set, never fatal."""
    try:
        lines = SEARCH_DEMAND_FILE.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("Search-demand list unreadable (%s); gate runs without it", exc)
        return frozenset()
    domains = set()
    for line in lines:
        entry = line.strip().lower()
        if entry and not entry.startswith("#"):
            domains.add(entry)
    return frozenset(domains)


def has_search_demand(domain: str) -> bool:
    """True → this page earns clicks, so it stays indexed regardless of data gaps."""
    d = (domain or "").strip().lower()
    return bool(d) and d in load_search_demand_domains()


# ──────────────────────────────────────────────
# INDEXABILITY REQUIREMENTS
# A /check/ page is indexable only when the scan actually learned enough to
# say something the on-page table does not already say. Every reason listed
# here blocks indexing on its own; `few_decided_sources` deliberately does
# not, so a partial-but-substantive scan still publishes.
# ──────────────────────────────────────────────
MIN_DECIDED_SOURCES = 6
MIN_TEXT_ITEMS = 4
INDEX_BLOCKING_REASONS = frozenset(
    {"no_ip", "no_domain_age", "too_few_decided_sources", "thin_text"}
)

# How many past verdicts to keep per domain. Enough to show a trend on the
# report without growing the document unboundedly on frequently-scanned hosts.
SCORE_HISTORY_LIMIT = 12
# Ignore re-scans closer together than this; otherwise a page someone reloads
# fills its whole history with one afternoon.
SCORE_HISTORY_MIN_GAP_HOURS = 24


def _score_history_point(result: dict, when: datetime) -> dict | None:
    """One history entry, or None when the scan has no score to record."""
    score = result.get("trust_score")
    if score is None:
        return None
    try:
        score = int(score)
    except (TypeError, ValueError):
        return None
    return {"at": when, "trust_score": score}


def _should_record_history(previous: list | None, point: dict) -> bool:
    """Record a verdict only when it is new information.

    A changed score always counts. An unchanged score counts once a day, so a
    page someone keeps reloading does not fill its history with one afternoon.
    """
    if not previous:
        return True
    last = previous[-1] if isinstance(previous, list) else None
    if not isinstance(last, dict):
        return True
    if last.get("trust_score") != point["trust_score"]:
        return True
    last_at = last.get("at")
    if not isinstance(last_at, datetime):
        return True
    gap = point["at"] - last_at
    return gap.total_seconds() >= SCORE_HISTORY_MIN_GAP_HOURS * 3600


# ──────────────────────────────────────────────
# MAJOR/TRUSTED DOMAINS
# Page BANEGA (user ko result milega) par INDEX nahi hoga (sitemap se bahar).
# ──────────────────────────────────────────────
FAMOUS_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "instagram.com", "twitter.com",
    "x.com", "spotify.com", "apple.com", "microsoft.com", "amazon.com", "netflix.com",
    "linkedin.com", "whatsapp.com", "telegram.org", "zoom.us", "github.com",
    "wikipedia.org", "reddit.com", "paypal.com", "pinterest.com", "tiktok.com",
    "binance.com", "coinbase.com", "openai.com", "cloudflare.com", "shopify.com",
    "amazon.in", "flipkart.com", "sbicard.com", "onlinesbi.sbi", "hdfcbank.com",
    "icicibank.com", "iciciprulife.com", "axisbank.com", "kotak.com", "paytm.com",
    "phonepe.com", "zerodha.com", "dhan.co", "fyers.in", "groww.in", "upstox.com",
    "delta.exchange", "angelone.in", "5paisa.com",
    "swiggy.com", "zomato.com", "myntra.com", "ajio.com", "meesho.com", "nykaa.com",
    "irctc.co.in", "uidai.gov.in", "incometax.gov.in", "epfindia.gov.in",
    "clinikally.com", "headphonezone.in", "crazygames.com",
}

SHORTENER_HOSTS = {
    "wa.link", "bit.ly", "t.co", "goo.gl", "tinyurl.com", "cutt.ly", "rebrand.ly",
    "lnkd.in", "rb.gy", "is.gd", "shorturl.at", "ow.ly", "buff.ly", "linktr.ee",
    "share.google",
}

# Hosts jahan har scan ek alag throwaway subdomain hota hai. Ek /check/ page
# per subdomain banana matlab unbounded index surface.
TRANSIENT_SUFFIXES = (
    ".app.goo.gl", ".goo.gl", ".zoom.us", ".archive.org", ".sharepoint.com",
    ".safelinks.protection.outlook.com", ".google.com", ".googleusercontent.com",
    ".firebaseapp.com", ".web.app", ".translate.goog", ".blogspot.com",
)


def is_seo_worthless(domain: str) -> bool:
    """True → page banao par index/sitemap se bahar rakho."""
    d = (domain or "").lower().strip()
    if not d:
        return True
    if d in SHORTENER_HOSTS or d in FAMOUS_DOMAINS:
        return True
    for suf in TRANSIENT_SUFFIXES:
        if d.endswith(suf):
            return True
    for fam in FAMOUS_DOMAINS:
        if d.endswith("." + fam):
            return True
    return False


def should_index_public_domain(domain: str) -> bool:
    """Domain-level veto for a /check page.

    Answers only "is this domain allowed in the index at all" — major brands,
    URL shorteners and throwaway subdomain hosts are not. Whether a given
    page has enough substance to index is a separate question, answered by
    calculate_page_quality(); both must pass.
    """
    d = normalize_domain(domain)
    return bool(d) and not is_seo_worthless(d)


def _major_domain_mongo_conditions() -> list[dict]:
    """Mongo filters matching major domains and any of their subdomains."""
    exact = sorted(FAMOUS_DOMAINS)
    suffixes = "|".join(re.escape(domain) for domain in exact)
    subdomain_pattern = re.compile(rf"\.(?:{suffixes})$", re.IGNORECASE)
    return [
        {"domain": {"$in": exact}},
        {"_id": {"$in": exact}},
        {"domain": {"$regex": subdomain_pattern}},
        {"_id": {"$regex": subdomain_pattern}},
    ]


async def sync_public_page_indexability() -> dict:
    """Enforce the major-domain noindex rule on every boot.

    This only ever *removes* pages from the index. It used to also set
    ``indexable: True`` on every non-major domain, which meant each deploy
    silently re-indexed the entire corpus and would undo any prune within
    minutes of shipping it. Whether a page is good enough to index is decided
    by calculate_page_quality() at scan time, and re-evaluated in bulk by
    scripts/reprune_public_pages.py — never here.
    """
    try:
        major_conditions = _major_domain_mongo_conditions()
        blocked_result = await pages_collection.update_many(
            {
                "$and": [
                    {"$or": major_conditions},
                    {"indexable": {"$ne": False}},
                ]
            },
            {"$set": {"indexable": False}},
        )
        updated = {
            "made_indexable": 0,
            "made_noindex": int(getattr(blocked_result, "modified_count", 0)),
        }
        logger.info("Public page indexability sync complete: %s", updated)
        return updated
    except Exception as exc:
        logger.error("Public page indexability sync failed: %s", exc)
        return {"made_indexable": 0, "made_noindex": 0, "error": str(exc)}


def get_domain_category(domain: str) -> str | None:
    """Return an optional text-only category label for the public report."""
    d = (domain or "").lower().strip()
    if ADULT_CONTENT_PATTERNS.search(d):
        return "Adult Content"
    return None


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
    # Sirf valid domain chars
    if not re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", d):
        return None
    return d


def calculate_page_quality(result: dict) -> dict:
    """
    Decide karo page index-worthy hai ya nahi.
    Returns: {"indexable": bool, "reasons": [...], "quality_score": int}

    Indexability is a set of hard requirements, not a score. The old rule —
    8 of 11 points — let a page qualify while missing domain age entirely
    (ip 2 + ssl 1 + sources 3 + text 2 = 8), and a sample of 35 live pages
    found 57% published with "Domain Created: Unknown". A scam report that
    cannot say how old the domain is has nothing to tell a reader that the
    scan table does not already show, so it does not belong in the index.

    quality_score is still computed and stored, but only for observability —
    it no longer decides anything.
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
    if decided >= MIN_DECIDED_SOURCES:
        points += 3
    elif decided >= 4:
        points += 1
        reasons.append("few_decided_sources")
    else:
        reasons.append("too_few_decided_sources")

    # 5. Explanation/AI text content kaafi hai?
    text_items = len(explanation) + len(why)
    if text_items >= MIN_TEXT_ITEMS:
        points += 2
    else:
        if text_items >= 2:
            points += 1
        reasons.append("thin_text")

    # 6. Sources list render karne layak?
    if len(sources) >= 10:
        points += 1

    # INDEX RULE: har hard requirement pass hona chahiye — score se nahi.
    # `reasons` already carries one entry per failed signal.
    blocking = [r for r in reasons if r in INDEX_BLOCKING_REASONS]
    indexable = not blocking
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
        # famous brand / shortener / transient host → page rahe par index na ho.
        # Quality decides again (it was bypassed between 2026-08-29 and this
        # change, which put the whole ~8,000-page corpus into the index two
        # weeks before the September 2026 core update). A domain that already
        # earns organic clicks overrides the gate — see has_search_demand.
        indexable = should_index_public_domain(domain) and (
            quality["indexable"] or has_search_demand(domain)
        )

        # Result se heavy/private cheezein hatao
        clean_result = {
            k: v for k, v in result.items()
            if k not in ("screenshot_bytes", "technical_report", "from_cache")
        }
        category_label = get_domain_category(domain)
        if category_label:
            clean_result["category_label"] = category_label

        now = datetime.utcnow()
        update = {
            "$set": {
                "domain": domain,
                "result": clean_result,
                "indexable": indexable,
                "quality_score": quality["quality_score"],
                "quality_reasons": quality["reasons"],
                "last_scanned": now,
            },
            "$setOnInsert": {"first_scanned": now},
            "$inc": {"scan_count": 1},
        }

        # Keep a short trail of how this domain's verdict moved over time.
        # It is the one thing on the report a template cannot generate: the
        # prose sections all restate the current scan, which the facts table
        # already shows. "Trust score fell 80 -> 45 on 12 Oct" does not.
        history_point = _score_history_point(clean_result, now)
        if history_point:
            existing = await pages_collection.find_one(
                {"_id": domain}, {"score_history": {"$slice": -1}}
            )
            previous = (existing or {}).get("score_history")
            if _should_record_history(previous, history_point):
                update["$push"] = {
                    "score_history": {
                        "$each": [history_point],
                        "$slice": -SCORE_HISTORY_LIMIT,
                    }
                }

        await pages_collection.update_one({"_id": domain}, update, upsert=True)
    except Exception as e:
        logger.error(f"save_public_scan failed for {url}: {e}")


async def get_public_page(domain: str) -> dict | None:
    d = normalize_domain(domain)
    if not d:
        return None
    try:
        return await pages_collection.find_one({"_id": d})
    except Exception as exc:
        logger.warning("Public report lookup unavailable for %s (%s)", d, type(exc).__name__)
        raise PublicPageStorageUnavailable(d) from exc


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

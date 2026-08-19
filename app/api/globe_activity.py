"""
Live data for the homepage globe.

GET /api/v1/globe-activity

What this is: the places our users have recently run checks from, and what
kind of check came back risky. It is NOT "where the scammer is" — we cannot
know that, so nothing here should ever be labelled that way on the front end.

Privacy rules baked in below:
  - only a scan category is exposed, never what the user actually pasted
  - a city+category pair only appears once MIN_CHECKS_PER_CITY separate checks
    match it, so a single person is never a dot on the map
  - locations stay at city-centroid resolution
  - no per-check timestamps go out, only a bucket age for the whole feed
"""

import logging
import time
from collections import defaultdict
from datetime import datetime, timedelta

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.core.database import db
from app.services.geo_service import available as geo_available
from app.services.geo_service import lookup as geo_lookup

logger = logging.getLogger(__name__)

router = APIRouter()

# Verdicts are free text and vary per checker ("SCAM", "SUSPICIOUS",
# "HIGH RISK SCAM", "VERY HIGH RISK SCAM"...), so match on substring.
RISKY_VERDICT_RE = "SCAM|SUSPICIOUS|HIGH RISK"
MIN_CHECKS_PER_CITY = 3      # k-anonymity floor, applied per city+category
MAX_MARKERS = 24
MAX_MARKERS_PER_CITY = 2
SCAN_FETCH_LIMIT = 1500
CACHE_TTL_SECONDS = 90

# scan type -> what we are willing to say publicly
TYPE_LABELS = {
    "url": "Phishing Attack",
    "text": "Message Scam",
    "upi": "UPI Fraud",
    "qr": "QR Code Fraud",
    "image": "Fake Payment Screenshot",
    "payment_screenshot": "Fake Payment Screenshot",
    "offer_letter": "Job Scam",
    "paypal_email": "PayPal Phishing",
    "paypal_invoice": "PayPal Invoice Scam",
    "paypal_link": "PayPal Link Scam",
}

_cache = {"at": 0.0, "payload": None}


def _severity(score) -> str:
    try:
        s = float(score or 0)
    except (TypeError, ValueError):
        s = 0.0
    if s >= 80:
        return "high"
    if s >= 50:
        return "medium"
    return "low"


def _label(scan_type: str) -> str:
    return TYPE_LABELS.get((scan_type or "").strip().lower(), "Reported Scam")


def _place_labels(geo: dict) -> tuple:
    """
    (primary, secondary) for the banner.

    GeoLite2 sometimes resolves only to a country, which used to render as
    "India, India". Some region names are also far too long for the ticker
    ("National Capital Territory of Delhi"), so fall back to the country.
    """
    city = (geo.get("city") or "").strip()
    region = (geo.get("region") or "").strip()
    country = (geo.get("country") or "").strip()

    if not city:
        return country, ""
    if not region or region == city or len(region) > 20:
        return city, country
    return city, region


async def _load_scans(since: datetime) -> list:
    try:
        cursor = (
            db.scam_checks.find(
                {
                    "created_at": {"$gte": since},
                    "client_ip": {"$exists": True, "$ne": None},
                    "verdict": {"$regex": RISKY_VERDICT_RE, "$options": "i"},
                },
                {"type": 1, "verdict": 1, "risk_score": 1, "client_ip": 1, "created_at": 1},
            )
            .sort("created_at", -1)
            .limit(SCAN_FETCH_LIMIT)
        )
        return [doc async for doc in cursor]
    except Exception as e:
        logger.warning("globe: scan fetch failed: %s", e)
        return []


def _build_markers(scans: list) -> list:
    """
    Group risky checks by city *and* check type.

    Grouping by city alone meant each city reported only its most common type.
    URL checks outnumber everything else, so UPI, message, QR and PayPal
    scams could never surface no matter how many came in. Keying on the type
    as well lets each category stand on its own, and the anonymity floor now
    applies per category, which is the stricter reading anyway.
    """
    groups = defaultdict(lambda: {"count": 0, "type": "", "score": 0, "geo": None})

    for doc in scans:
        geo = geo_lookup(doc.get("client_ip") or "")
        if not geo:
            continue
        scan_type = (doc.get("type") or "").strip().lower()
        key = (geo["country_code"], geo["region"], geo["city"], scan_type)
        g = groups[key]
        g["geo"] = geo
        g["type"] = scan_type
        g["count"] += 1
        try:
            g["score"] = max(g["score"], float(doc.get("risk_score") or 0))
        except (TypeError, ValueError):
            pass

    markers = []
    for g in groups.values():
        if g["count"] < MIN_CHECKS_PER_CITY:
            continue
        geo = g["geo"]
        top_type = g["type"]
        primary, secondary = _place_labels(geo)
        markers.append({
            "lat": geo["lat"],
            "lng": geo["lng"],
            "city": primary,
            "state": secondary,
            "country": geo["country"],
            # ready to print — avoids the caller having to guess about
            # empty halves ("India, India", "Mumbai, ")
            "place": f"{primary}, {secondary}" if secondary else primary,
            "type": _label(top_type),
            "severity": _severity(g["score"]),
            "checks": g["count"],
        })

    markers.sort(key=lambda m: m["checks"], reverse=True)

    # One city can now yield several markers (one per category). Cap how many
    # it gets so a single busy city cannot fill the globe on its own.
    per_city, kept = defaultdict(int), []
    for m in markers:
        if per_city[m["place"]] >= MAX_MARKERS_PER_CITY:
            continue
        per_city[m["place"]] += 1
        kept.append(m)
        if len(kept) >= MAX_MARKERS:
            break

    # Same-city markers share a centroid, so nudge the repeats apart. This is
    # well under the resolution we already publish, and stops the dots from
    # sitting exactly on top of each other.
    seen = defaultdict(int)
    for m in kept:
        coord = (m["lat"], m["lng"])
        n = seen[coord]
        seen[coord] += 1
        if n:
            m["lat"] = round(m["lat"] + 0.18 * n, 2)
            m["lng"] = round(m["lng"] + 0.18 * n, 2)

    return kept


@router.get("/globe-activity")
async def globe_activity():
    """Cached so the globe can poll without touching Mongo every time."""
    now = time.time()
    if _cache["payload"] is not None and (now - _cache["at"]) < CACHE_TTL_SECONDS:
        return JSONResponse(_cache["payload"])

    if not geo_available():
        payload = {"markers": [], "window": None, "reason": "geo_unavailable"}
        _cache.update(at=now, payload=payload)
        return JSONResponse(payload)

    markers, window = [], None
    # Prefer the last day; widen only if that is too quiet to be anonymous.
    for hours in (24, 24 * 7, 24 * 30):
        scans = await _load_scans(datetime.utcnow() - timedelta(hours=hours))
        markers = _build_markers(scans)
        window = f"{hours}h"
        if len(markers) >= 8:
            break

    payload = {
        "markers": markers,
        "window": window,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    _cache.update(at=now, payload=payload)
    return JSONResponse(payload)

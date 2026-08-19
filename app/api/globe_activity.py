"""
Live data for the homepage globe.

GET /api/v1/globe-activity

What this is: the places our users have recently run checks from, and what
kind of check came back risky. It is NOT "where the scammer is" — we cannot
know that, so nothing here should ever be labelled that way on the front end.

Privacy rules baked in below:
  - only a scan category is exposed, never what the user actually pasted
  - a city only appears once MIN_CHECKS_PER_CITY separate checks came from it,
    so a single person is never a dot on the map
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
MIN_CHECKS_PER_CITY = 3      # k-anonymity floor
MAX_MARKERS = 24
SCAN_FETCH_LIMIT = 1500
CACHE_TTL_SECONDS = 90

# scan type -> what we are willing to say publicly
TYPE_LABELS = {
    "url": "Phishing Attack",
    "text": "Message Scam",
    "upi": "UPI Fraud",
    "qr": "QR Code Fraud",
    "image": "Fake Payment Screenshot",
    "offer_letter": "Job Scam",
    "paypal_email": "PayPal Phishing",
    "paypal_invoice": "PayPal Invoice Scam",
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
    """Group risky checks by city, drop anything below the anonymity floor."""
    groups = defaultdict(lambda: {"count": 0, "types": defaultdict(int), "score": 0, "geo": None})

    for doc in scans:
        geo = geo_lookup(doc.get("client_ip") or "")
        if not geo:
            continue
        key = (geo["country_code"], geo["region"], geo["city"])
        g = groups[key]
        g["geo"] = geo
        g["count"] += 1
        g["types"][(doc.get("type") or "").strip().lower()] += 1
        try:
            g["score"] = max(g["score"], float(doc.get("risk_score") or 0))
        except (TypeError, ValueError):
            pass

    markers = []
    for g in groups.values():
        if g["count"] < MIN_CHECKS_PER_CITY:
            continue
        geo = g["geo"]
        top_type = max(g["types"].items(), key=lambda kv: kv[1])[0] if g["types"] else ""
        markers.append({
            "lat": geo["lat"],
            "lng": geo["lng"],
            "city": geo["city"] or geo["country"],
            "state": geo["region"] or geo["country"],
            "country": geo["country"],
            "type": _label(top_type),
            "severity": _severity(g["score"]),
            "checks": g["count"],
        })

    # busiest first, then trim
    markers.sort(key=lambda m: m["checks"], reverse=True)
    return markers[:MAX_MARKERS]


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

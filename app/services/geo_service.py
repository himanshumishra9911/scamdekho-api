"""
IP -> coarse location, for the homepage globe.

Backed by the MaxMind GeoLite2-City database. The file is NOT in the repo
(MaxMind does not allow redistribution) — the Dockerfile downloads it at
build time when MAXMIND_LICENSE_KEY is set.

If the database is missing the whole module degrades to "no location":
lookup() just returns None and the globe falls back to its curated set.
Nothing here is ever allowed to raise into a request.
"""

import ipaddress
import logging
import os
import threading

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("GEOIP_DB_PATH", "app/data/GeoLite2-City.mmdb")

_reader = None
_reader_tried = False
_lock = threading.Lock()


def _get_reader():
    """Open the mmdb once. On any failure, stay disabled and say so once."""
    global _reader, _reader_tried
    if _reader_tried:
        return _reader
    with _lock:
        if _reader_tried:
            return _reader
        _reader_tried = True
        try:
            import geoip2.database  # imported lazily so the dep stays optional
            if not os.path.exists(DB_PATH):
                logger.warning("GeoLite2 db not found at %s — globe geo disabled", DB_PATH)
                return None
            _reader = geoip2.database.Reader(DB_PATH)
            logger.info("GeoLite2 db loaded from %s", DB_PATH)
        except Exception as e:
            logger.warning("GeoLite2 unavailable (%s) — globe geo disabled", e)
            _reader = None
    return _reader


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_reserved
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
    )


def lookup(ip: str) -> dict | None:
    """
    Coarse location for an IP. City-level at best — we never want, store or
    return anything finer than that.

    Returns {city, region, country, country_code, lat, lng} or None.
    """
    if not is_public_ip(ip):
        return None
    reader = _get_reader()
    if reader is None:
        return None
    try:
        r = reader.city(ip)
    except Exception:
        return None

    lat = getattr(r.location, "latitude", None)
    lng = getattr(r.location, "longitude", None)
    if lat is None or lng is None:
        return None

    city = (r.city.name or "").strip()
    region = ""
    try:
        if r.subdivisions and len(r.subdivisions) > 0:
            region = (r.subdivisions.most_specific.name or "").strip()
    except Exception:
        region = ""
    country = (r.country.name or "").strip()
    country_code = (r.country.iso_code or "").strip()

    if not city and not country:
        return None

    return {
        "city": city,
        "region": region,
        "country": country,
        "country_code": country_code,
        # rounded: a city centroid is already coarse, this keeps it that way
        "lat": round(float(lat), 2),
        "lng": round(float(lng), 2),
    }


def available() -> bool:
    return _get_reader() is not None

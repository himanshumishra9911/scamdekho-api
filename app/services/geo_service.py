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
import shutil
import tarfile
import tempfile
import threading
import urllib.request

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("GEOIP_DB_PATH", "app/data/GeoLite2-City.mmdb")
FALLBACK_DB_PATH = "/tmp/GeoLite2-City.mmdb"
DOWNLOAD_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id=GeoLite2-City&license_key={key}&suffix=tar.gz"
)

_reader = None
_reader_tried = False
_lock = threading.Lock()
_download_lock = threading.Lock()


def _resolve_db_path() -> str | None:
    """Where the mmdb actually is, if anywhere."""
    for path in (DB_PATH, FALLBACK_DB_PATH):
        if path and os.path.exists(path):
            return path
    return None


def download_db() -> bool:
    """
    Fetch GeoLite2-City at runtime.

    The Dockerfile already tries this at build time, but Render does not
    always expose build args, so this is the safety net. Blocking and slow
    (~60MB) — call it off the request path, never inside one.
    """
    key = os.getenv("MAXMIND_LICENSE_KEY", "").strip()
    if not key:
        logger.warning("MAXMIND_LICENSE_KEY not set — cannot fetch GeoLite2")
        return False

    with _download_lock:
        existing = _resolve_db_path()
        if existing:
            return True

        # Prefer the packaged location; fall back to /tmp if it is read-only.
        target = DB_PATH
        try:
            os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
            with open(target + ".probe", "w") as fh:
                fh.write("x")
            os.remove(target + ".probe")
        except Exception:
            target = FALLBACK_DB_PATH

        tmpdir = tempfile.mkdtemp(prefix="geolite2-")
        archive = os.path.join(tmpdir, "geolite2.tar.gz")
        try:
            logger.info("Downloading GeoLite2-City...")
            urllib.request.urlretrieve(DOWNLOAD_URL.format(key=key), archive)
            with tarfile.open(archive, "r:gz") as tar:
                member = next(
                    (m for m in tar.getmembers() if m.name.endswith("GeoLite2-City.mmdb")),
                    None,
                )
                if member is None:
                    logger.error("GeoLite2 archive had no .mmdb inside")
                    return False
                member.name = os.path.basename(member.name)
                tar.extract(member, tmpdir)
            shutil.move(os.path.join(tmpdir, "GeoLite2-City.mmdb"), target)
            logger.info("GeoLite2-City ready at %s", target)

            # let the next lookup re-open the reader
            global _reader_tried, _reader
            _reader_tried = False
            _reader = None
            return True
        except Exception as e:
            logger.error("GeoLite2 download failed: %s", e)
            return False
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


def ensure_db() -> bool:
    """True if a database is present (downloading it if needed)."""
    if _resolve_db_path():
        return True
    return download_db()


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
            path = _resolve_db_path()
            if not path:
                logger.warning("GeoLite2 db not found — globe geo disabled")
                return None
            _reader = geoip2.database.Reader(path)
            logger.info("GeoLite2 db loaded from %s", path)
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

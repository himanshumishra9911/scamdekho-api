import hashlib
import json
from datetime import datetime, timedelta
from typing import Any
from app.core.database import db
from app.services.public_pages_service import save_public_scan


cache_collection = db["url_cache"]
scan_cache_collection = db["scan_cache"]

URL_CACHE_TTL_HOURS = 24 * 3
SCAN_CACHE_TTL_HOURS = 24 * 3


def _url_key(url: str) -> str:
    """Exact URL ka SHA256 hash — cache key"""
    return hashlib.sha256(url.strip().lower().encode()).hexdigest()


async def get_cached_result(url: str) -> dict | None:
    """
    Agar same exact URL pehle check hua hai (24h ke andar) toh cache se return karo.
    Returns None agar cache miss ya expired.
    """
    try:
        key = _url_key(url)
        doc = await cache_collection.find_one({"_id": key})
        if not doc:
            return None
        # TTL check
        cached_at = doc.get("cached_at")
        if not cached_at:
            return None
        if datetime.utcnow() - cached_at > timedelta(hours=URL_CACHE_TTL_HOURS):
            # Expired — delete silently
            await cache_collection.delete_one({"_id": key})
            return None
        return doc.get("result")
    except Exception:
        return None  # Cache fail = proceed normally, no crash


async def set_cached_result(url: str, result: dict) -> None:
    """
    Result ko MongoDB mein store karo 24h ke liye.
    Silently fails agar MongoDB down ho.
    """
    try:
        key = _url_key(url)
        # screenshot bytes cache mein store mat karo — heavy hai
        result_to_cache = {k: v for k, v in result.items() if k != "screenshot_bytes"}
        await cache_collection.update_one(
            {"_id": key},
            {"$set": {
                "_id": key,
                "url": url.strip().lower(),
                "result": result_to_cache,
                "cached_at": datetime.utcnow()
            }},
            upsert=True
            await save_public_scan(url, result_to_cache)
        )
    except Exception:
        pass  # Silent fail


async def setup_cache_ttl_index() -> None:
    """
    MongoDB TTL index setup — ek baar call karo app startup pe.
    Auto-delete karta hai 24h baad documents ko.
    """
    try:
        await cache_collection.create_index(
            "cached_at",
            expireAfterSeconds=URL_CACHE_TTL_HOURS * 3600,
            background=True
        )
    except Exception:
        try:
            await db.command({
                "collMod": "url_cache",
                "index": {
                    "keyPattern": {"cached_at": 1},
                    "expireAfterSeconds": URL_CACHE_TTL_HOURS * 3600,
                },
            })
        except Exception:
            pass

    try:
        await scan_cache_collection.create_index(
            "cached_at",
            expireAfterSeconds=SCAN_CACHE_TTL_HOURS * 3600,
            background=True
        )
    except Exception:
        try:
            await db.command({
                "collMod": "scan_cache",
                "index": {
                    "keyPattern": {"cached_at": 1},
                    "expireAfterSeconds": SCAN_CACHE_TTL_HOURS * 3600,
                },
            })
        except Exception:
            pass


def _normalize_payload(payload: Any) -> Any:
    if isinstance(payload, str):
        return " ".join(payload.strip().lower().split())
    if isinstance(payload, bytes):
        return hashlib.sha256(payload).hexdigest()
    if isinstance(payload, dict):
        return {str(k): _normalize_payload(v) for k, v in sorted(payload.items())}
    if isinstance(payload, list):
        return [_normalize_payload(v) for v in payload]
    return payload


def _scan_key(namespace: str, payload: Any) -> str:
    normalized = _normalize_payload(payload)
    raw = json.dumps(
        {"namespace": namespace, "payload": normalized},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(raw.encode()).hexdigest()


async def get_cached_scan(namespace: str, payload: Any) -> dict | None:
    try:
        key = _scan_key(namespace, payload)
        doc = await scan_cache_collection.find_one({"_id": key})
        if not doc:
            return None
        cached_at = doc.get("cached_at")
        if not cached_at:
            return None
        if datetime.utcnow() - cached_at > timedelta(hours=SCAN_CACHE_TTL_HOURS):
            await scan_cache_collection.delete_one({"_id": key})
            return None
        return doc.get("result")
    except Exception:
        return None


async def set_cached_scan(namespace: str, payload: Any, result: dict) -> None:
    try:
        key = _scan_key(namespace, payload)
        result_to_cache = {
            k: v for k, v in result.items()
            if k not in {"image_base64", "screenshot_bytes"}
        }
        await scan_cache_collection.update_one(
            {"_id": key},
            {"$set": {
                "_id": key,
                "namespace": namespace,
                "payload_hash": key,
                "result": result_to_cache,
                "cached_at": datetime.utcnow(),
            }},
            upsert=True
        )
    except Exception:
        pass

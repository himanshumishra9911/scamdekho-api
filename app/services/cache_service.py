import hashlib
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient
import os

MONGO_URL = os.getenv("MONGO_URL")
client = AsyncIOMotorClient(MONGO_URL)
db = client["scamdekho"]
cache_collection = db["url_cache"]

CACHE_TTL_HOURS = 24


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
        if datetime.utcnow() - cached_at > timedelta(hours=CACHE_TTL_HOURS):
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
            expireAfterSeconds=CACHE_TTL_HOURS * 3600,
            background=True
        )
    except Exception:
        pass

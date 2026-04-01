import os
import asyncio
import hashlib
import httpx
from datetime import datetime, timedelta
from motor.motor_asyncio import AsyncIOMotorClient

# ======================================
# MongoDB — screenshot cache (48h TTL)
# ======================================
MONGO_URL = os.getenv("MONGO_URL")
_mongo_client = AsyncIOMotorClient(MONGO_URL)
_db = _mongo_client["scamdekho"]
_ss_cache = _db["screenshot_cache"]
SCREENSHOT_CACHE_HOURS = 48

SCREENSHOTONE_KEY = os.getenv("SCREENSHOTONE_API_KEY", "")  # Optional fallback


def _ss_key(url: str) -> str:
    return hashlib.sha256(url.strip().lower().encode()).hexdigest()


async def _get_cached_screenshot(url: str) -> bytes | None:
    try:
        key = _ss_key(url)
        doc = await _ss_cache.find_one({"_id": key})
        if not doc:
            return None
        cached_at = doc.get("cached_at")
        if not cached_at or datetime.utcnow() - cached_at > timedelta(hours=SCREENSHOT_CACHE_HOURS):
            await _ss_cache.delete_one({"_id": key})
            return None
        data = doc.get("screenshot")
        if data:
            return bytes(data)
        return None
    except Exception:
        return None


async def _save_screenshot_cache(url: str, screenshot_bytes: bytes) -> None:
    try:
        key = _ss_key(url)
        await _ss_cache.update_one(
            {"_id": key},
            {"$set": {
                "_id": key,
                "url": url.strip().lower(),
                "screenshot": screenshot_bytes,
                "cached_at": datetime.utcnow()
            }},
            upsert=True
        )
    except Exception:
        pass


# ======================================
# PRIMARY: Playwright
# ======================================
async def _playwright_screenshot(url: str) -> bytes | None:
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
            )
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
            )
            page = await context.new_page()
            await page.goto(url, timeout=15000, wait_until="domcontentloaded")
            await asyncio.sleep(2)
            screenshot = await page.screenshot(type="jpeg", quality=80, full_page=False)
            await browser.close()
            return screenshot
    except Exception:
        return None


# ======================================
# FALLBACK: ScreenshotOne API
# ======================================
async def _screenshotone_screenshot(url: str) -> bytes | None:
    if not SCREENSHOTONE_KEY:
        return None
    try:
        import urllib.parse
        params = {
            "access_key": SCREENSHOTONE_KEY,
            "url": url,
            "format": "jpg",
            "viewport_width": 1280,
            "viewport_height": 800,
            "full_page": "false",
            "delay": 2,
            "timeout": 15,
        }
        query = urllib.parse.urlencode(params)
        api_url = f"https://api.screenshotone.com/take?{query}"
        async with httpx.AsyncClient(timeout=20.0) as c:
            r = await c.get(api_url)
            if r.status_code == 200 and r.headers.get("content-type", "").startswith("image"):
                return r.content
        return None
    except Exception:
        return None


# ======================================
# MASTER FUNCTION
# Called from router — same interface as before
# ======================================
async def capture_website_screenshot(url: str) -> bytes | None:
    """
    1. MongoDB cache check (48h)
    2. Playwright attempt
    3. ScreenshotOne API fallback (agar SCREENSHOTONE_API_KEY set ho)
    4. Cache se purana screenshot (expired bhi chalega as last resort)
    5. None return — caller handles gracefully
    """

    # ── Step 1: Cache hit ──
    cached = await _get_cached_screenshot(url)
    if cached:
        return cached

    # ── Step 2: Playwright (primary) ──
    screenshot = await _playwright_screenshot(url)

    # ── Step 3: ScreenshotOne fallback ──
    if not screenshot:
        screenshot = await _screenshotone_screenshot(url)

    # ── Step 4: Save to cache agar mile ──
    if screenshot:
        await _save_screenshot_cache(url, screenshot)
        return screenshot

    # ── Step 5: Stale cache as last resort ──
    # (Expired doc already deleted in _get_cached_screenshot,
    #  so try direct lookup without TTL check)
    try:
        key = _ss_key(url)
        doc = await _ss_cache.find_one({"_id": key})
        if doc and doc.get("screenshot"):
            return bytes(doc["screenshot"])
    except Exception:
        pass

    return None  # Caller (router) handles None gracefully


# ======================================
# SETUP: TTL index for screenshot cache
# ======================================
async def setup_screenshot_cache_index() -> None:
    try:
        await _ss_cache.create_index(
            "cached_at",
            expireAfterSeconds=SCREENSHOT_CACHE_HOURS * 3600,
            background=True
        )
    except Exception:
        pass

import time
from collections import defaultdict
from fastapi import Request, HTTPException

# ======================================
# CONFIG
# ======================================
PER_IP_LIMIT = 20       # requests per minute per IP
URL_PER_IP_LIMIT = 3   # URL checks are expensive and attract scanners
GLOBAL_LIMIT = 200      # requests per minute total
URL_GLOBAL_LIMIT = 20   # total URL checks per minute
WINDOW_SECONDS = 60

# ======================================
# IN-MEMORY STORES
# sliding window using list of timestamps
# ======================================
_ip_timestamps: dict[str, list] = defaultdict(list)
_global_timestamps: list = []
_url_ip_timestamps: dict[str, list] = defaultdict(list)
_url_global_timestamps: list = []


def _get_client_ip(request: Request) -> str:
    """Render + proxy ke peeche bhi sahi IP mile"""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _clean_window(timestamps: list, now: float) -> list:
    """60 second window ke bahar ke timestamps remove karo"""
    return [t for t in timestamps if now - t < WINDOW_SECONDS]


async def check_rate_limit(request: Request) -> None:
    """
    FastAPI dependency — router mein inject karo.
    429 raise karta hai agar limit exceed ho.
    Silently works — user ko pata nahi chalega backend reason.
    """
    now = time.time()
    ip = _get_client_ip(request)

    # ── Global limit check ──
    global _global_timestamps
    _global_timestamps = _clean_window(_global_timestamps, now)
    if len(_global_timestamps) >= GLOBAL_LIMIT:
        raise HTTPException(status_code=429, detail="Too many requests. Please try again later.")

    # ── Per-IP limit check ──
    _ip_timestamps[ip] = _clean_window(_ip_timestamps[ip], now)
    if len(_ip_timestamps[ip]) >= PER_IP_LIMIT:
        raise HTTPException(status_code=429, detail="Too many requests. Please try again later.")

    # ── Record this request ──
    _global_timestamps.append(now)
    _ip_timestamps[ip].append(now)


async def check_url_rate_limit(request: Request) -> None:
    """
    Stricter limiter for /check/url. This endpoint does network lookups,
    screenshots, AI calls, and writes to dashboard history.
    """
    now = time.time()
    ip = _get_client_ip(request)

    global _url_global_timestamps
    _url_global_timestamps = _clean_window(_url_global_timestamps, now)
    if len(_url_global_timestamps) >= URL_GLOBAL_LIMIT:
        raise HTTPException(status_code=429, detail="Too many URL checks. Please try again later.")

    _url_ip_timestamps[ip] = _clean_window(_url_ip_timestamps[ip], now)
    if len(_url_ip_timestamps[ip]) >= URL_PER_IP_LIMIT:
        raise HTTPException(status_code=429, detail="Too many URL checks. Please try again later.")

    _url_global_timestamps.append(now)
    _url_ip_timestamps[ip].append(now)

import time
from collections import defaultdict
from fastapi import Request, HTTPException

# ======================================
# CONFIG
# ======================================
PER_IP_LIMIT = 20       # requests per minute per IP
GLOBAL_LIMIT = 200      # requests per minute total
WINDOW_SECONDS = 60

# ======================================
# IN-MEMORY STORES
# sliding window using list of timestamps
# ======================================
_ip_timestamps: dict[str, list] = defaultdict(list)
_global_timestamps: list = []


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

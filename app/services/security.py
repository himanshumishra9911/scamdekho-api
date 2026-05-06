import os
from typing import Optional, Set
from urllib.parse import urlparse

from fastapi import Header, HTTPException, Request


DEFAULT_ALLOWED_ORIGINS = {
    "https://scamdekho.in",
    "https://www.scamdekho.in",
    "https://scamdekho-api.onrender.com",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
}

BLOCKED_USER_AGENT_PARTS = (
    "curl",
    "python-requests",
    "python-httpx",
    "go-http-client",
    "wget",
    "scrapy",
    "bot",
    "spider",
    "crawler",
)


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _allowed_origins() -> Set[str]:
    configured = os.getenv("ALLOWED_PUBLIC_ORIGINS")
    if not configured:
        return DEFAULT_ALLOWED_ORIGINS
    return {origin.strip().rstrip("/") for origin in configured.split(",") if origin.strip()}


def _request_origin(request: Request) -> Optional[str]:
    origin = request.headers.get("origin")
    if origin:
        return origin.rstrip("/")

    referer = request.headers.get("referer")
    if not referer:
        return None

    parsed = urlparse(referer)
    if not parsed.scheme or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _has_valid_api_key(request: Request) -> bool:
    api_key = os.getenv("PUBLIC_API_KEY")
    if not api_key:
        return False
    supplied = request.headers.get("x-api-key") or request.query_params.get("api_key")
    return supplied == api_key


async def require_public_client(request: Request) -> None:
    """
    Blocks low-effort direct scanners while still allowing the public website.
    For trusted server/API testing, set PUBLIC_API_KEY and send x-api-key.
    """
    if _has_valid_api_key(request):
        return

    user_agent = (request.headers.get("user-agent") or "").lower()
    if not user_agent or any(part in user_agent for part in BLOCKED_USER_AGENT_PARTS):
        raise HTTPException(status_code=403, detail="Forbidden")

    if _env_bool("ALLOW_DIRECT_API", default=False):
        return

    origin = _request_origin(request)
    if origin not in _allowed_origins():
        raise HTTPException(status_code=403, detail="Forbidden")


async def require_admin(
    request: Request,
    x_admin_token: Optional[str] = Header(default=None),
) -> None:
    admin_token = os.getenv("ADMIN_TOKEN")
    if not admin_token:
        return

    supplied = x_admin_token or request.query_params.get("token")
    if supplied != admin_token:
        raise HTTPException(status_code=401, detail="Admin token required")

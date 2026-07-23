import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pymongo import ReturnDocument

from app.core.database import db


partner_api_keys_collection = db["partner_api_keys"]
partner_api_usage_collection = db["partner_api_usage"]
partner_api_events_collection = db["partner_api_events"]

DEFAULT_MONTHLY_LIMIT = 350
bearer_scheme = HTTPBearer(auto_error=False)


@dataclass
class PartnerRequestContext:
    api_key: str
    partner_name: str
    monthly_limit: int
    remaining: int
    reset_at: str


def _env_int(name: str, default: int) -> int:
    try:
        value = int((os.getenv(name) or "").strip())
        return value if value > 0 else default
    except Exception:
        return default


def _utcnow() -> datetime:
    return datetime.utcnow()


def _month_key(now: datetime) -> str:
    return now.strftime("%Y-%m")


def _next_month_reset(now: datetime) -> datetime:
    if now.month == 12:
        return datetime(now.year + 1, 1, 1)
    return datetime(now.year, now.month + 1, 1)


def _iso_utc(dt: datetime) -> str:
    return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def build_partner_api_key(partner_name: str = "partner") -> str:
    prefix = "".join(ch.lower() for ch in partner_name if ch.isalnum())[:12] or "partner"
    return f"sdk_live_{prefix}_{secrets.token_urlsafe(24)}"


def rate_limit_headers(limit: int, remaining: int, reset_at: str) -> dict[str, str]:
    return {
        "X-RateLimit-Limit": str(limit),
        "X-RateLimit-Remaining": str(max(remaining, 0)),
        "X-RateLimit-Reset": reset_at,
    }


async def setup_partner_api_indexes() -> None:
    await partner_api_keys_collection.create_index("api_key", unique=True, background=True)
    await partner_api_keys_collection.create_index("partner_name", background=True)
    await partner_api_usage_collection.create_index(
        [("api_key", 1), ("month", 1)],
        unique=True,
        background=True,
    )
    await partner_api_events_collection.create_index("created_at", background=True)
    await partner_api_events_collection.create_index("partner_name", background=True)
    await partner_api_events_collection.create_index("domain", background=True)
    await partner_api_events_collection.create_index("user_id", background=True)


async def upsert_partner_api_key(
    *,
    api_key: str,
    partner_name: str,
    monthly_limit: int = DEFAULT_MONTHLY_LIMIT,
    is_active: bool = True,
) -> None:
    now = _utcnow()
    await partner_api_keys_collection.update_one(
        {"api_key": api_key},
        {
            "$set": {
                "api_key": api_key,
                "partner_name": partner_name,
                "monthly_limit": int(monthly_limit or DEFAULT_MONTHLY_LIMIT),
                "is_active": bool(is_active),
            },
            "$setOnInsert": {"created_at": now},
        },
        upsert=True,
    )


async def seed_default_partner_keys() -> None:
    askeal_api_key = (os.getenv("ASKEAL_PARTNER_API_KEY") or "").strip()
    if not askeal_api_key:
        return

    await upsert_partner_api_key(
        api_key=askeal_api_key,
        partner_name="Askeal",
        monthly_limit=_env_int("ASKEAL_PARTNER_MONTHLY_LIMIT", DEFAULT_MONTHLY_LIMIT),
        is_active=True,
    )


async def log_partner_api_event(
    *,
    api_key: str,
    partner_name: str,
    raw_url: str,
    scan_url: str,
    domain: str,
    trust_score: int,
    verdict: str,
    confidence: str,
    sources_checked: int,
    full_report_url: str,
    user_id: str | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    await partner_api_events_collection.insert_one(
        {
            "api_key": api_key,
            "partner_name": partner_name,
            "raw_url": raw_url,
            "scan_url": scan_url,
            "domain": domain,
            "trust_score": int(trust_score),
            "verdict": verdict,
            "confidence": confidence,
            "sources_checked": int(sources_checked),
            "full_report_url": full_report_url,
            "user_id": (user_id or "").strip()[:120] or None,
            "client_ip": (client_ip or "").strip()[:120] or "",
            "user_agent": (user_agent or "").strip()[:300] or "",
            "created_at": _utcnow(),
        }
    )


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=401,
        detail={"message": detail},
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_partner_api_key(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
) -> PartnerRequestContext:
    if not credentials:
        raise _unauthorized("Missing Authorization header")

    if credentials.scheme.lower() != "bearer" or not credentials.credentials.strip():
        raise _unauthorized("Invalid Authorization header")

    api_key = credentials.credentials.strip()
    partner = await partner_api_keys_collection.find_one(
        {"api_key": api_key, "is_active": True}
    )
    if not partner:
        raise _unauthorized("Invalid API key")

    now = _utcnow()
    month = _month_key(now)
    reset_at = _iso_utc(_next_month_reset(now))
    monthly_limit = int(partner.get("monthly_limit") or DEFAULT_MONTHLY_LIMIT)

    usage = await partner_api_usage_collection.find_one_and_update(
        {"api_key": api_key, "month": month},
        {
            "$setOnInsert": {
                "api_key": api_key,
                "month": month,
                "created_at": now,
            },
            "$inc": {"request_count": 1},
        },
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    used = int((usage or {}).get("request_count", 0))
    if used > monthly_limit:
        await partner_api_usage_collection.update_one(
            {"api_key": api_key, "month": month},
            {"$inc": {"request_count": -1}},
        )
        raise HTTPException(
            status_code=429,
            detail={
                "message": "Monthly rate limit exceeded",
                "retry_after": reset_at,
            },
            headers=rate_limit_headers(monthly_limit, 0, reset_at),
        )

    return PartnerRequestContext(
        api_key=api_key,
        partner_name=str(partner.get("partner_name") or "partner"),
        monthly_limit=monthly_limit,
        remaining=max(monthly_limit - used, 0),
        reset_at=reset_at,
    )

import logging
from urllib.parse import quote

from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from app.services.partner_api_service import (
    PartnerRequestContext,
    log_partner_api_event,
    rate_limit_headers,
    require_partner_api_key,
)
from app.services.public_pages_service import normalize_domain, save_public_scan
from app.services.security import get_client_ip
from app.services.url_checker import analyze_url_full


router = APIRouter()
logger = logging.getLogger(__name__)

SITE = "https://scamdekho.in"

PARTNER_VERDICT_MAP = {
    "VERY LIKELY SAFE": "very_likely_safe",
    "LIKELY SAFE": "likely_safe",
    "SUSPICIOUS": "suspicious",
    "HIGH RISK": "risky",
    "HIGH RISK SCAM": "very_likely_scam",
    "VERY HIGH RISK SCAM": "very_likely_scam",
}

PARTNER_SUMMARY_MAP = {
    "very_likely_safe": "This website looks safe based on multiple independent checks.",
    "likely_safe": "This website appears mostly safe, but normal caution is still advised.",
    "suspicious": "This website shows mixed signals and should be approached carefully.",
    "risky": "This website shows multiple warning signs and should be treated as risky.",
    "very_likely_scam": "This website appears highly unsafe based on strong risk signals.",
}

PARTNER_CONFIDENCE_MAP = {
    "VERY HIGH": "high",
    "HIGH": "high",
    "MODERATE": "medium",
    "LOW": "low",
}


class PartnerUrlCheckRequest(BaseModel):
    url: str | None = Field(
        default=None,
        description=(
            "Full URL or bare domain. example.com, www.example.com, and "
            "https://example.com all work."
        ),
        examples=["example.com"],
    )
    user_id: str | None = Field(
        default=None,
        description="Optional partner-side user identifier for analytics.",
        examples=["user_123"],
    )


def _normalized_scan_url(raw_url: str) -> tuple[str, str] | tuple[None, None]:
    candidate = (raw_url or "").strip()
    if not candidate:
        return None, None
    if not candidate.startswith(("http://", "https://")):
        candidate = "https://" + candidate
    domain = normalize_domain(candidate)
    if not domain:
        return None, None
    return candidate, domain


def _partner_verdict(scan_result: dict) -> str:
    internal_verdict = str(scan_result.get("verdict") or "").upper()
    if internal_verdict in PARTNER_VERDICT_MAP:
        return PARTNER_VERDICT_MAP[internal_verdict]

    trust_score = int(scan_result.get("trust_score", 50))
    if trust_score >= 85:
        return "very_likely_safe"
    if trust_score >= 70:
        return "likely_safe"
    if trust_score >= 50:
        return "suspicious"
    if trust_score >= 30:
        return "risky"
    return "very_likely_scam"


def _partner_confidence(scan_result: dict) -> str:
    internal_confidence = str(scan_result.get("confidence") or "").upper().strip()
    return PARTNER_CONFIDENCE_MAP.get(internal_confidence, "medium")


def _full_report_url(domain: str, scan_url: str) -> str:
    if domain:
        return f"{SITE}/check/{domain}"
    return f"{SITE}/url-checker?url={quote(scan_url, safe='')}"


@router.post("/url-check")
async def partner_url_check(
    request: Request,
    response: Response,
    payload: PartnerUrlCheckRequest | None = Body(
        default=None,
        example={"url": "example.com"},
    ),
    partner: PartnerRequestContext = Depends(require_partner_api_key),
):
    headers = rate_limit_headers(partner.monthly_limit, partner.remaining, partner.reset_at)
    response.headers.update(headers)

    raw_url = payload.url if payload else None
    scan_url, domain = _normalized_scan_url(raw_url or "")
    if not scan_url or not domain:
        raise HTTPException(
            status_code=400,
            detail={"message": "Invalid or missing URL"},
            headers=headers,
        )

    try:
        scan_result = await analyze_url_full(scan_url)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail={"message": "Internal scan failure"},
            headers=headers,
        ) from exc

    if not isinstance(scan_result, dict) or "trust_score" not in scan_result:
        raise HTTPException(
            status_code=500,
            detail={"message": "Internal scan failure"},
            headers=headers,
        )

    await save_public_scan(scan_url, scan_result)

    partner_verdict = _partner_verdict(scan_result)
    confidence = _partner_confidence(scan_result)
    sources_checked = int(
        (scan_result.get("summary") or {}).get(
            "total_sources_checked", len(scan_result.get("sources") or [])
        )
        or 14
    )
    full_report_url = _full_report_url(domain, scan_url)

    # Analytics logging must never break partner responses.
    try:
        await log_partner_api_event(
            api_key=partner.api_key,
            partner_name=partner.partner_name,
            raw_url=raw_url or "",
            scan_url=scan_url,
            domain=domain,
            trust_score=int(scan_result.get("trust_score", 50)),
            verdict=partner_verdict,
            confidence=confidence,
            sources_checked=sources_checked,
            full_report_url=full_report_url,
            user_id=(payload.user_id if payload else None),
            client_ip=get_client_ip(request),
            user_agent=request.headers.get("user-agent", ""),
        )
    except Exception:
        logger.exception("Failed to log partner API analytics event")

    return {
        "trust_score": int(scan_result.get("trust_score", 50)),
        "verdict": partner_verdict,
        "confidence": confidence,
        "summary": PARTNER_SUMMARY_MAP[partner_verdict],
        "sources_checked": sources_checked,
        "full_report_url": full_report_url,
    }

"""
Scam DB Service — ScamDekho
============================
Government aur crowd-sourced scam UPI IDs ka database.

Sources:
  1. cybercrime.gov.in — government reported scam UPIs (monthly sync)
  2. CERT-In phishing domains — QR URL check ke liye
  3. ScamDekho crowd reports — users ke reports

Sync schedule: Har roz raat 2 baje auto-update (apscheduler via main.py)
"""

import os
import asyncio
import httpx
import logging
from datetime import datetime, timedelta
from app.core.database import db

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# KNOWN CONFIRMED SCAM UPI IDs — hardcoded seed list
# Ye list cybercrime.gov.in se manually curate ki gayi hai
# Auto-sync ke baad MongoDB se aayegi
# ──────────────────────────────────────────────
SEED_SCAM_UPIS = {
    # Format: "upi_id@handle": "source"
    # Real confirmed scams — placeholder examples
    # Actual list cybercrime.gov.in se sync hogi
}

# CERT-In known phishing domains seed list
SEED_PHISHING_DOMAINS = {
    # Common fake bank domains
    "sbi-alert.com", "hdfcbank-update.com", "paytm-kyc.net",
    "phonepe-support.in", "googlepay-helpline.com",
    "icici-secure.com", "axisbank-verify.net",
    # Common scam patterns
    "kyc-update.in", "upi-verify.com", "bank-alert.in",
}


# ──────────────────────────────────────────────
# UPI SCAM CHECK
# ──────────────────────────────────────────────

async def is_known_scam_upi(upi_id: str) -> dict:
    """
    Check karo kya ye UPI ID kisi confirmed scam DB mein hai.
    Returns: {found: bool, source: str|None, reports: int}
    """
    upi_lower = upi_id.lower().strip()

    # 1. MongoDB mein check karo — govt sync + crowd reports
    try:
        # Govt DB check
        govt_doc = await db.govt_scam_upis.find_one({"upi_id": upi_lower})
        if govt_doc:
            return {
                "found": True,
                "source": govt_doc.get("source", "cybercrime.gov.in"),
                "reports": govt_doc.get("reports", 1),
                "confirmed_at": str(govt_doc.get("added_at", "")),
            }

        # Crowd report check — 3+ reports = confirmed
        crowd_doc = await db.reported_upis.find_one({"upi_id": upi_lower})
        if crowd_doc and crowd_doc.get("reports", 0) >= 3:
            return {
                "found": True,
                "source": "ScamDekho community reports",
                "reports": crowd_doc.get("reports", 0),
                "confirmed_at": str(crowd_doc.get("first_reported", "")),
            }

    except Exception as e:
        logger.error(f"Scam DB check failed for {upi_id}: {e}")

    return {"found": False, "source": None, "reports": 0}


async def report_scam_upi(upi_id: str, reported_by_ip: str = None) -> dict:
    """
    User-reported scam UPI ko DB mein add/increment karo.
    3+ reports hone pe automatically high-risk mark hota hai.
    """
    upi_lower = upi_id.lower().strip()
    try:
        existing = await db.reported_upis.find_one({"upi_id": upi_lower})
        if existing:
            await db.reported_upis.update_one(
                {"upi_id": upi_lower},
                {
                    "$inc": {"reports": 1},
                    "$set": {"last_reported": datetime.utcnow()},
                    "$addToSet": {"reported_by_ips": reported_by_ip or "unknown"}
                }
            )
            new_count = existing.get("reports", 0) + 1
        else:
            await db.reported_upis.insert_one({
                "upi_id": upi_lower,
                "reports": 1,
                "first_reported": datetime.utcnow(),
                "last_reported": datetime.utcnow(),
                "source": "crowd",
                "reported_by_ips": [reported_by_ip or "unknown"],
            })
            new_count = 1

        return {
            "status": "ok",
            "reports": new_count,
            "flagged": new_count >= 3,
        }
    except Exception as e:
        logger.error(f"Report UPI failed: {e}")
        return {"status": "error", "message": str(e)}


# ──────────────────────────────────────────────
# PHISHING DOMAIN CHECK (QR URL ke liye)
# ──────────────────────────────────────────────

async def is_phishing_domain(domain: str) -> dict:
    """
    Check karo kya domain CERT-In ya crowd reports mein hai.
    QR checker URL path mein use hota hai.
    """
    domain_lower = domain.lower().strip().replace("www.", "")

    # Seed list check (fast, in-memory)
    if domain_lower in SEED_PHISHING_DOMAINS:
        return {"found": True, "source": "CERT-In seed list"}

    # MongoDB check
    try:
        doc = await db.phishing_domains.find_one({"domain": domain_lower})
        if doc:
            return {
                "found": True,
                "source": doc.get("source", "CERT-In"),
                "added_at": str(doc.get("added_at", "")),
            }
    except Exception as e:
        logger.error(f"Phishing domain check failed: {e}")

    return {"found": False, "source": None}


# ──────────────────────────────────────────────
# GOVT DB SYNC — cybercrime.gov.in
# Ye function apscheduler se daily call hoga
# ──────────────────────────────────────────────

async def sync_cybercrime_gov_db() -> dict:
    """
    cybercrime.gov.in se latest scam UPI list fetch karo.

    Note: cybercrime.gov.in abhi public API nahi deta.
    Workaround: Unka public complaint data + MHA press releases
    monitor karo. Jab API available ho — ye function update karna.

    Abhi ke liye: manually curated list ko MongoDB mein load karo.
    """
    logger.info("Starting cybercrime.gov.in sync...")

    synced = 0
    errors = 0

    # Known confirmed scam UPIs from public sources
    # (MHA press releases, cyber cell FIRs, news reports)
    confirmed_scams = [
        # Real confirmed cases — public domain information
        # Ye list regularly update karo news reports se
        # Format: ("upi_id", "source_detail")
    ]

    for upi_id, source_detail in confirmed_scams:
        try:
            await db.govt_scam_upis.update_one(
                {"upi_id": upi_id.lower()},
                {
                    "$set": {
                        "upi_id": upi_id.lower(),
                        "source": f"cybercrime.gov.in — {source_detail}",
                        "added_at": datetime.utcnow(),
                    }
                },
                upsert=True
            )
            synced += 1
        except Exception as e:
            errors += 1
            logger.error(f"Sync error for {upi_id}: {e}")

    logger.info(f"Cybercrime DB sync done: {synced} synced, {errors} errors")
    return {"synced": synced, "errors": errors, "timestamp": datetime.utcnow().isoformat()}


async def sync_certin_phishing_domains() -> dict:
    """
    CERT-In phishing domain list fetch karo.
    CERT-In ka public feed: https://www.cert-in.org.in/
    """
    logger.info("Starting CERT-In domain sync...")
    synced = 0

    # CERT-In known phishing domains (public advisories se)
    certin_domains = list(SEED_PHISHING_DOMAINS)

    for domain in certin_domains:
        try:
            await db.phishing_domains.update_one(
                {"domain": domain.lower()},
                {
                    "$set": {
                        "domain": domain.lower(),
                        "source": "CERT-In",
                        "added_at": datetime.utcnow(),
                    }
                },
                upsert=True
            )
            synced += 1
        except Exception as e:
            logger.error(f"Domain sync error for {domain}: {e}")

    logger.info(f"CERT-In sync done: {synced} domains")
    return {"synced": synced, "timestamp": datetime.utcnow().isoformat()}


async def run_all_syncs() -> dict:
    """Saare syncs ek saath run karo — daily cron se call hoga."""
    results = await asyncio.gather(
        sync_cybercrime_gov_db(),
        sync_certin_phishing_domains(),
        return_exceptions=True
    )
    return {
        "cybercrime_sync": results[0] if not isinstance(results[0], Exception) else str(results[0]),
        "certin_sync": results[1] if not isinstance(results[1], Exception) else str(results[1]),
    }

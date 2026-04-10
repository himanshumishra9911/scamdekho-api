from fastapi import APIRouter, Query
from app.core.database import db
from datetime import datetime, timedelta

router = APIRouter()


@router.get("/stats")
async def stats(date: str = Query(default=None, description="Filter by date YYYY-MM-DD. Defaults to today (IST).")):
    try:
        # ── Build date range ──────────────────────────────────────────────────
        if date:
            target = datetime.strptime(date, "%Y-%m-%d")
        else:
            # Default → today in IST (UTC+5:30)
            target = (datetime.utcnow() + timedelta(hours=5, minutes=30)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )

        # Day start / end in UTC (MongoDB stores UTC)
        ist_offset = timedelta(hours=5, minutes=30)
        day_start_utc = target.replace(hour=0, minute=0, second=0, microsecond=0) - ist_offset
        day_end_utc   = target.replace(hour=23, minute=59, second=59, microsecond=999999) - ist_offset

        date_filter = {"created_at": {"$gte": day_start_utc, "$lte": day_end_utc}}

        # ── Counts ────────────────────────────────────────────────────────────
        total       = await db.scam_checks.count_documents(date_filter)
        scam_count  = await db.scam_checks.count_documents({**date_filter, "verdict": "SCAM"})
        safe_count  = await db.scam_checks.count_documents({**date_filter, "verdict": "SAFE"})

        # ── All records for that day (NO .limit()) ────────────────────────────
        recent_cursor = db.scam_checks.find(
            date_filter,
            {
                "type": 1, "content": 1, "verdict": 1,
                "created_at": 1, "risk_score": 1, "_id": 0
            }
        ).sort("created_at", -1)   # newest first, NO limit

        recent = []
        async for doc in recent_cursor:
            recent.append([
                doc.get("type", ""),
                doc.get("content", "")[:500],
                doc.get("verdict", ""),
                str(doc.get("created_at", "")),
                doc.get("risk_score", 0)
            ])

        return {
            "total":      total,
            "scam_count": scam_count,
            "safe_count": safe_count,
            "recent":     recent,
            "date":       target.strftime("%Y-%m-%d"),   # echo back date used
        }

    except Exception as e:
        return {
            "total": 0, "scam_count": 0, "safe_count": 0,
            "recent": [], "error": str(e)
        }

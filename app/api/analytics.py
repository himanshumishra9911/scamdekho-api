from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Query

from app.core.database import db
from app.services.security import require_admin

router = APIRouter()


def build_date_context(date: str = None):
    if date:
        target = datetime.strptime(date, "%Y-%m-%d")
    else:
        target = (datetime.utcnow() + timedelta(hours=5, minutes=30)).replace(
            hour=0, minute=0, second=0, microsecond=0
        )

    ist_offset = timedelta(hours=5, minutes=30)
    day_start_utc = target.replace(hour=0, minute=0, second=0, microsecond=0) - ist_offset
    day_end_utc = target.replace(hour=23, minute=59, second=59, microsecond=999999) - ist_offset

    return {
        "target": target,
        "date_filter": {"created_at": {"$gte": day_start_utc, "$lte": day_end_utc}},
    }


def first_value(doc: dict, *keys, default=None):
    for key in keys:
        value = doc
        for part in key.split("."):
            if not isinstance(value, dict) or part not in value:
                value = None
                break
            value = value[part]
        if value not in (None, "", []):
            return value
    return default


def list_value(value):
    if not value:
        return []
    if isinstance(value, list):
        return value
    return [value]


def number_value(value, default=0):
    try:
        if value is None or value == "":
            return default
        if isinstance(value, str):
            value = value.replace("$", "").replace(",", "").strip()
        return float(value)
    except Exception:
        return default


async def find_docs(date: str, scan_type: str):
    context = build_date_context(date)
    if scan_type == "email":
        type_or_content = {
            "$or": [
                {"type": {"$regex": "email|paypal", "$options": "i"}},
                {"content": {"$regex": "paypal|subject:|from:|@|email", "$options": "i"}},
                {"sender": {"$exists": True}},
                {"sender_email": {"$exists": True}},
                {"email_content": {"$exists": True}},
                {"subject": {"$exists": True}},
            ]
        }
    elif scan_type == "invoice":
        type_or_content = {
            "$or": [
                {"type": {"$regex": "invoice|paypal", "$options": "i"}},
                {"content": {"$regex": "invoice|paypal|receipt|amount|subscription|billing", "$options": "i"}},
                {"invoice_amount": {"$exists": True}},
                {"amount": {"$exists": True}},
                {"scam_patterns": {"$exists": True}},
                {"analysis.amount": {"$exists": True}},
                {"analysis.amount_check": {"$exists": True}},
            ]
        }
    else:
        type_or_content = {"type": {"$regex": scan_type, "$options": "i"}}

    query = {**context["date_filter"], **type_or_content}

    docs = []
    cursor = db.scam_checks.find(query, {"_id": 0}).sort("created_at", -1)
    async for doc in cursor:
        docs.append(doc)

    return context["target"], docs


@router.get("/stats", dependencies=[Depends(require_admin)])
async def stats(date: str = Query(default=None, description="Filter by date YYYY-MM-DD. Defaults to today (IST).")):
    try:
        context = build_date_context(date)
        target = context["target"]
        date_filter = context["date_filter"]

        total = await db.scam_checks.count_documents(date_filter)
        scam_count = await db.scam_checks.count_documents({**date_filter, "verdict": "SCAM"})
        safe_count = await db.scam_checks.count_documents({**date_filter, "verdict": "SAFE"})

        recent_cursor = db.scam_checks.find(
            date_filter,
            {
                "type": 1,
                "content": 1,
                "verdict": 1,
                "created_at": 1,
                "risk_score": 1,
                "client_ip": 1,
                "user_agent": 1,
                "_id": 0,
            },
        ).sort("created_at", -1)

        recent = []
        async for doc in recent_cursor:
            recent.append([
                doc.get("type", ""),
                doc.get("content", "")[:500],
                doc.get("verdict", ""),
                str(doc.get("created_at", "")),
                doc.get("risk_score", 0),
                doc.get("client_ip", ""),
                doc.get("user_agent", ""),
            ])

        return {
            "total": total,
            "scam_count": scam_count,
            "safe_count": safe_count,
            "recent": recent,
            "date": target.strftime("%Y-%m-%d"),
        }
    except Exception as e:
        return {
            "total": 0,
            "scam_count": 0,
            "safe_count": 0,
            "recent": [],
            "error": str(e),
        }


@router.get("/email-stats", dependencies=[Depends(require_admin)])
async def email_stats(date: str = Query(default=None)):
    try:
        target, docs = await find_docs(date, "email")

        recent = []
        total_risk = 0
        with_phone_count = 0

        for doc in docs:
            risk = int(number_value(first_value(doc, "risk_score", "risk_percentage"), 0))
            total_risk += risk

            phones = list_value(first_value(
                doc,
                "phones",
                "phone_numbers",
                "phone_numbers_found",
                "analysis.phones",
                "analysis.phone_numbers",
                default=[],
            ))
            if phones:
                with_phone_count += 1

            recent.append({
                "sender": first_value(doc, "sender", "sender_email", "from_email", "analysis.sender", default=""),
                "subject": first_value(doc, "subject", "email_subject", "analysis.subject", default=""),
                "verdict": first_value(doc, "verdict", default=""),
                "risk_score": risk,
                "red_flags": list_value(first_value(doc, "red_flags", "flags", "reasons", "analysis.red_flags", default=[])),
                "phones": phones,
                "created_at": str(doc.get("created_at", "")),
                "analysis": first_value(doc, "analysis", default={}),
                "email_content": first_value(doc, "email_content", "content", "body", default=""),
            })

        total = len(docs)
        return {
            "total": total,
            "scam_count": sum(1 for doc in docs if (doc.get("verdict") or "").upper() == "SCAM"),
            "safe_count": sum(1 for doc in docs if (doc.get("verdict") or "").upper() == "SAFE"),
            "avg_risk_score": round(total_risk / total, 2) if total else 0,
            "with_phone_count": with_phone_count,
            "recent": recent,
            "date": target.strftime("%Y-%m-%d"),
        }
    except Exception as e:
        return {
            "total": 0,
            "scam_count": 0,
            "safe_count": 0,
            "avg_risk_score": 0,
            "with_phone_count": 0,
            "recent": [],
            "error": str(e),
        }


@router.get("/invoice-stats", dependencies=[Depends(require_admin)])
async def invoice_stats(date: str = Query(default=None)):
    try:
        target, docs = await find_docs(date, "invoice")

        recent = []
        total_scam_amount = 0
        pattern_count = 0

        for doc in docs:
            amount = number_value(first_value(
                doc,
                "amount",
                "invoice_amount",
                "analysis.amount",
                "analysis.amount_check.amount",
                "extracted_fields.amount",
            ), 0)
            risk = int(number_value(first_value(doc, "risk_score", "risk_percentage"), 0))
            verdict = first_value(doc, "verdict", default="")
            patterns = list_value(first_value(doc, "scam_patterns", "patterns", "analysis.scam_patterns", default=[]))

            if (verdict or "").upper() == "SCAM":
                total_scam_amount += amount
            if patterns:
                pattern_count += 1

            recent.append({
                "sender": first_value(doc, "sender", "sender_email", "from_email", "analysis.sender", default=""),
                "sender_name": first_value(doc, "sender_name", "from_name", "analysis.sender_name", default=""),
                "amount": amount,
                "verdict": verdict,
                "risk_score": risk,
                "message": first_value(doc, "message", "description", "content", "analysis.message", default=""),
                "red_flags": list_value(first_value(doc, "red_flags", "flags", "reasons", "analysis.red_flags", default=[])),
                "scam_patterns": patterns,
                "analysis": first_value(doc, "analysis", default={}),
                "created_at": str(doc.get("created_at", "")),
            })

        total = len(docs)
        return {
            "total": total,
            "scam_count": sum(1 for doc in docs if (doc.get("verdict") or "").upper() == "SCAM"),
            "safe_count": sum(1 for doc in docs if (doc.get("verdict") or "").upper() == "SAFE"),
            "total_scam_amount": total_scam_amount,
            "pattern_count": pattern_count,
            "recent": recent,
            "date": target.strftime("%Y-%m-%d"),
        }
    except Exception as e:
        return {
            "total": 0,
            "scam_count": 0,
            "safe_count": 0,
            "total_scam_amount": 0,
            "pattern_count": 0,
            "recent": [],
            "error": str(e),
        }

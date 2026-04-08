from fastapi import APIRouter
from app.core.database import db

router = APIRouter()

@router.get("/stats")
async def stats():
    try:
        total = await db.scam_checks.count_documents({})
        scam_count = await db.scam_checks.count_documents({"verdict": "SCAM"})
        safe_count = await db.scam_checks.count_documents({"verdict": "SAFE"})

        recent_cursor = db.scam_checks.find(
            {},
            {"type": 1, "content": 1, "verdict": 1, "created_at": 1,
             "risk_score": 1, "_id": 0}
        ).sort("created_at", -1).allow_disk_use(True).limit(100)

        recent = []
        async for doc in recent_cursor:
            recent.append([
                doc.get("type", ""),
                doc.get("content", "")[:500],
                doc.get("verdict", ""),
                str(doc.get("created_at", "")),
                doc.get("risk_score", 0),
                None,
                {}
            ])

        return {"total": total, "scam_count": scam_count,
                "safe_count": safe_count, "recent": recent}

    except Exception as e:
        return {"total": 0, "scam_count": 0, "safe_count": 0,
                "recent": [], "error": str(e)}

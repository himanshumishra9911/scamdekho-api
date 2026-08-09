from fastapi import APIRouter
from pydantic import BaseModel, Field
from typing import Literal, Optional
from app.core.database import db
from datetime import datetime

router = APIRouter()

class FeedbackRequest(BaseModel):
    rating: int = Field(ge=1, le=5)
    comment: Optional[str] = Field(default="", max_length=2000)
    scan_type: Optional[str] = Field(default="", max_length=64)
    verdict: Optional[str] = Field(default="", max_length=32)
    request_id: Optional[str] = Field(default=None, max_length=64)
    result_correct: Optional[bool] = None
    expected_verdict: Optional[Literal["SAFE", "SUSPICIOUS", "SCAM"]] = None

@router.post("/submit")
async def submit_feedback(data: FeedbackRequest):
    try:
        request_id = (data.request_id or "").strip() or None
        linked_scan = None
        if request_id:
            linked_scan = await db.scam_checks.find_one(
                {"request_id": request_id},
                {"_id": 1, "verdict": 1, "analysis_version": 1},
            )

        await db.feedback.insert_one({
            "rating": data.rating,
            "comment": (data.comment or "").strip(),
            "scan_type": (data.scan_type or "").strip(),
            "verdict": (data.verdict or "").strip().upper(),
            "request_id": request_id,
            "result_correct": data.result_correct,
            "expected_verdict": data.expected_verdict,
            "linked_scan_id": str(linked_scan["_id"]) if linked_scan else None,
            "linked_analysis_version": (
                linked_scan.get("analysis_version") if linked_scan else None
            ),
            "created_at": datetime.utcnow()
        })
        return {"status": "ok", "linked_to_scan": bool(linked_scan)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/summary")
async def get_summary():
    try:
        total = await db.feedback.count_documents({})
        pipeline = [{"$group": {"_id": None, "avg": {"$avg": "$rating"}}}]
        result = await db.feedback.aggregate(pipeline).to_list(1)
        avg = round(result[0]["avg"], 1) if result else 0.0

        return {
            "total_reviews": total,
            "average_rating": avg,
            "status": "ok"
        }
    except Exception as e:
        return {"status": "error", "total_reviews": 0, "average_rating": 0.0}

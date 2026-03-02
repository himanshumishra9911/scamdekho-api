from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.core.database import db
from datetime import datetime

router = APIRouter()

class FeedbackRequest(BaseModel):
    rating: int
    comment: Optional[str] = ""
    scan_type: Optional[str] = ""
    verdict: Optional[str] = ""

@router.post("/submit")
async def submit_feedback(data: FeedbackRequest):
    try:
        await db.feedback.insert_one({
            "rating": data.rating,
            "comment": data.comment,
            "scan_type": data.scan_type,
            "verdict": data.verdict,
            "created_at": datetime.utcnow()
        })
        return {"status": "ok"}
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

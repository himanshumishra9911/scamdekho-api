from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional
from app.services.db_service import db

router = APIRouter()

class FeedbackRequest(BaseModel):
    rating: int          # 1-5
    comment: Optional[str] = ""
    scan_type: Optional[str] = ""  # text/url/image
    verdict: Optional[str] = ""    # SAFE/SCAM

@router.post("/submit")
async def submit_feedback(data: FeedbackRequest):
    try:
        await db["feedback"].insert_one({
            "rating": data.rating,
            "comment": data.comment,
            "scan_type": data.scan_type,
            "verdict": data.verdict,
        })
        return {"status": "ok", "message": "Feedback saved"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@router.get("/summary")
async def get_feedback_summary():
    try:
        total = await db["feedback"].count_documents({})
        
        # Average rating
        pipeline = [{"$group": {"_id": None, "avg": {"$avg": "$rating"}}}]
        result = await db["feedback"].aggregate(pipeline).to_list(1)
        avg_rating = round(result[0]["avg"], 1) if result else 0.0

        return {
            "total_reviews": total,
            "average_rating": avg_rating,
            "status": "ok"
        }
    except Exception as e:
        return {"status": "error", "total_reviews": 0, "average_rating": 0}

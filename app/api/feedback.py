import base64
import hashlib
import logging
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.core.database import db

router = APIRouter()
logger = logging.getLogger(__name__)

class FeedbackRequest(BaseModel):
    rating: int = Field(ge=1, le=5)
    comment: Optional[str] = Field(default="", max_length=2000)
    scan_type: Optional[str] = Field(default="", max_length=64)
    verdict: Optional[str] = Field(default="", max_length=32)
    request_id: Optional[str] = Field(default=None, max_length=64)
    result_correct: Optional[bool] = None
    expected_verdict: Optional[Literal["SAFE", "SUSPICIOUS", "SCAM"]] = None


async def _queue_payment_learning_candidate(
    *,
    data: FeedbackRequest,
    linked_scan: dict | None,
    feedback_id: str,
) -> bool:
    """Collect a misclassification for verified offline learning.

    Public feedback is deliberately never allowed to modify the live detector.
    That would let an attacker poison future classifications. Samples stay in a
    human-review queue until independently verified and promoted by a controlled
    training/evaluation workflow.
    """
    if not all(
        (
            linked_scan,
            (data.scan_type or "").strip() == "payment_screenshot",
            data.result_correct is False,
            data.expected_verdict,
        )
    ):
        return False

    encoded_image = linked_scan.get("image_base64")
    if not isinstance(encoded_image, str) or not encoded_image:
        return False
    try:
        image_bytes = base64.b64decode(encoded_image, validate=True)
    except (ValueError, TypeError):
        return False
    if not image_bytes:
        return False

    now = datetime.now(timezone.utc)
    sha256 = hashlib.sha256(image_bytes).hexdigest()
    expected = str(data.expected_verdict)
    await db.payment_learning_candidates.update_one(
        {"image_sha256": sha256},
        {
            "$setOnInsert": {
                "image_sha256": sha256,
                "created_at": now,
                "status": "pending_human_review",
                "promotion_eligible": False,
                "source": "user_feedback",
                "linked_scan_id": str(linked_scan.get("_id")),
                "mime_type": linked_scan.get("mime_type"),
                "filename": linked_scan.get("filename"),
                "initial_verdict": linked_scan.get("verdict"),
                "initial_risk_score": linked_scan.get("risk_score"),
                "initial_analysis_version": linked_scan.get("analysis_version"),
            },
            "$set": {"updated_at": now},
            "$inc": {
                "feedback_count": 1,
                f"label_votes.{expected}": 1,
            },
            "$addToSet": {
                "feedback_ids": feedback_id,
                "request_ids": (data.request_id or "").strip(),
            },
        },
        upsert=True,
    )
    return True

@router.post("/submit")
async def submit_feedback(data: FeedbackRequest):
    try:
        request_id = (data.request_id or "").strip() or None
        linked_scan = None
        if request_id:
            linked_scan = await db.scam_checks.find_one(
                {"request_id": request_id},
                {
                    "_id": 1,
                    "verdict": 1,
                    "risk_score": 1,
                    "analysis_version": 1,
                    "image_base64": 1,
                    "mime_type": 1,
                    "filename": 1,
                },
            )

        inserted = await db.feedback.insert_one({
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
            "created_at": datetime.now(timezone.utc)
        })
        learning_candidate_queued = False
        try:
            learning_candidate_queued = await _queue_payment_learning_candidate(
                data=data,
                linked_scan=linked_scan,
                feedback_id=str(inserted.inserted_id),
            )
        except Exception as exc:
            # Feedback remains accepted even if the optional learning queue is
            # temporarily unavailable.
            logger.warning("Could not queue payment learning candidate: %s", exc)
        return {
            "status": "ok",
            "linked_to_scan": bool(linked_scan),
            "learning_candidate_queued": learning_candidate_queued,
        }
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

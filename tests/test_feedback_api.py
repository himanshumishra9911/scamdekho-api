import asyncio
import base64
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import app.api.feedback as feedback_api
from app.api.feedback import FeedbackRequest


class FakeCollection:
    def __init__(self, found=None):
        self.found = found
        self.inserted = None
        self.updated = None

    async def find_one(self, query, projection):
        assert query == {"request_id": "req-123"}
        return self.found

    async def insert_one(self, document):
        self.inserted = document
        return SimpleNamespace(inserted_id="feedback-1")

    async def update_one(self, query, update, upsert=False):
        self.updated = {"query": query, "update": update, "upsert": upsert}
        return SimpleNamespace(upserted_id="candidate-1")


def test_feedback_rating_is_bounded():
    with pytest.raises(ValidationError):
        FeedbackRequest(rating=0)
    with pytest.raises(ValidationError):
        FeedbackRequest(rating=6)


def test_feedback_links_user_label_to_original_scan(monkeypatch):
    scans = FakeCollection(
        found={
            "_id": "scan-1",
            "verdict": "SAFE",
            "risk_score": 25,
            "analysis_version": "payment-vision-v21",
            "image_base64": base64.b64encode(b"fake-image-bytes").decode("ascii"),
            "mime_type": "image/png",
            "filename": "payment.png",
        }
    )
    feedback = FakeCollection()
    candidates = FakeCollection()
    monkeypatch.setattr(
        feedback_api,
        "db",
        SimpleNamespace(
            scam_checks=scans,
            feedback=feedback,
            payment_learning_candidates=candidates,
        ),
    )

    response = asyncio.run(
        feedback_api.submit_feedback(
            FeedbackRequest(
                rating=1,
                comment="This fake was marked safe",
                scan_type="payment_screenshot",
                verdict="safe",
                request_id="req-123",
                result_correct=False,
                expected_verdict="SCAM",
            )
        )
    )

    assert response == {
        "status": "ok",
        "linked_to_scan": True,
        "learning_candidate_queued": True,
    }
    assert feedback.inserted["request_id"] == "req-123"
    assert feedback.inserted["linked_scan_id"] == "scan-1"
    assert feedback.inserted["result_correct"] is False
    assert feedback.inserted["expected_verdict"] == "SCAM"
    assert candidates.updated["upsert"] is True
    assert candidates.updated["update"]["$setOnInsert"]["status"] == "pending_human_review"
    assert candidates.updated["update"]["$setOnInsert"]["promotion_eligible"] is False
    assert candidates.updated["update"]["$inc"]["label_votes.SCAM"] == 1

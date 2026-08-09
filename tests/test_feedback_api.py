import asyncio
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import app.api.feedback as feedback_api
from app.api.feedback import FeedbackRequest


class FakeCollection:
    def __init__(self, found=None):
        self.found = found
        self.inserted = None

    async def find_one(self, query, projection):
        assert query == {"request_id": "req-123"}
        return self.found

    async def insert_one(self, document):
        self.inserted = document
        return SimpleNamespace(inserted_id="feedback-1")


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
            "analysis_version": "payment-vision-v21",
        }
    )
    feedback = FakeCollection()
    monkeypatch.setattr(
        feedback_api,
        "db",
        SimpleNamespace(scam_checks=scans, feedback=feedback),
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

    assert response == {"status": "ok", "linked_to_scan": True}
    assert feedback.inserted["request_id"] == "req-123"
    assert feedback.inserted["linked_scan_id"] == "scan-1"
    assert feedback.inserted["result_correct"] is False
    assert feedback.inserted["expected_verdict"] == "SCAM"

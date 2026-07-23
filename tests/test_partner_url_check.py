import unittest
from datetime import datetime
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.partner_url_check import router as partner_url_check_router
from app.services import partner_api_service


class FakeCollection:
    def __init__(self, docs=None):
        self.docs = [dict(doc) for doc in (docs or [])]

    async def create_index(self, *args, **kwargs):
        return None

    async def find_one(self, filter, projection=None):
        for doc in self.docs:
            if self._matches(doc, filter):
                return dict(doc)
        return None

    async def update_one(self, filter, update, upsert=False):
        for doc in self.docs:
            if self._matches(doc, filter):
                self._apply_update(doc, update)
                return None

        if not upsert:
            return None

        new_doc = {}
        for key, value in filter.items():
            if not isinstance(value, dict):
                new_doc[key] = value
        self._apply_update(new_doc, update, is_insert=True)
        self.docs.append(new_doc)
        return None

    async def find_one_and_update(
        self,
        filter,
        update,
        upsert=False,
        return_document=None,
    ):
        for doc in self.docs:
            if self._matches(doc, filter):
                self._apply_update(doc, update)
                return dict(doc)

        if not upsert:
            return None

        new_doc = {}
        for key, value in filter.items():
            if not isinstance(value, dict):
                new_doc[key] = value
        self._apply_update(new_doc, update, is_insert=True)
        self.docs.append(new_doc)
        return dict(new_doc)

    @staticmethod
    def _matches(doc, filter):
        for key, value in filter.items():
            if isinstance(value, dict):
                return False
            if doc.get(key) != value:
                return False
        return True

    @staticmethod
    def _apply_update(doc, update, is_insert=False):
        for key, value in update.get("$setOnInsert", {}).items():
            if is_insert and key not in doc:
                doc[key] = value
        for key, value in update.get("$set", {}).items():
            doc[key] = value
        for key, value in update.get("$inc", {}).items():
            doc[key] = int(doc.get(key, 0)) + int(value)


def build_app():
    app = FastAPI()
    app.include_router(partner_url_check_router, prefix="/api/v1")
    return app


class PartnerUrlCheckTests(unittest.TestCase):
    def setUp(self):
        self.app = build_app()
        self.client = TestClient(self.app)
        self.api_keys = FakeCollection(
            [
                {
                    "api_key": "askeal-test-key",
                    "partner_name": "Askeal",
                    "created_at": datetime.utcnow(),
                    "monthly_limit": 350,
                    "is_active": True,
                }
            ]
        )
        self.usage = FakeCollection()

        self.keys_patcher = patch.object(
            partner_api_service, "partner_api_keys_collection", self.api_keys
        )
        self.usage_patcher = patch.object(
            partner_api_service, "partner_api_usage_collection", self.usage
        )
        self.keys_patcher.start()
        self.usage_patcher.start()

    def tearDown(self):
        self.keys_patcher.stop()
        self.usage_patcher.stop()

    def test_valid_url_returns_summary_only(self):
        scan_result = {
            "trust_score": 90,
            "verdict": "VERY LIKELY SAFE",
            "confidence": "HIGH",
            "summary": {"total_sources_checked": 14},
            "sources": [{"name": f"Source {i}"} for i in range(14)],
            "top_risks": ["none"],
            "explanation": ["clean"],
            "other_info": {"ip_address": "1.1.1.1"},
            "technical_report": "internal only",
        }

        with patch(
            "app.api.partner_url_check.analyze_url_full",
            new=AsyncMock(return_value=scan_result),
        ), patch(
            "app.api.partner_url_check.save_public_scan",
            new=AsyncMock(return_value=None),
        ):
            response = self.client.post(
                "/api/v1/url-check",
                headers={"Authorization": "Bearer askeal-test-key"},
                json={"url": "https://example.com"},
            )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(
            set(data.keys()),
            {
                "trust_score",
                "verdict",
                "confidence",
                "summary",
                "sources_checked",
                "full_report_url",
            },
        )
        self.assertEqual(data["trust_score"], 90)
        self.assertEqual(data["verdict"], "very_likely_safe")
        self.assertEqual(data["confidence"], "high")
        self.assertEqual(data["sources_checked"], 14)
        self.assertEqual(data["full_report_url"], "https://scamdekho.in/check/example.com")
        self.assertNotIn("sources", data)
        self.assertNotIn("technical_report", data)
        self.assertNotIn("other_info", data)
        self.assertNotIn("why", data)
        self.assertNotIn("what_to_do", data)
        self.assertNotIn("how_to_avoid", data)
        self.assertNotIn("signals", data)
        self.assertNotIn("verdict_hi", data)
        self.assertNotIn("technical_report", data)
        self.assertEqual(response.headers["X-RateLimit-Limit"], "350")
        self.assertEqual(response.headers["X-RateLimit-Remaining"], "349")
        self.assertIn("X-RateLimit-Reset", response.headers)

    def test_invalid_url_returns_400(self):
        with patch(
            "app.api.partner_url_check.analyze_url_full",
            new=AsyncMock(return_value={}),
        ), patch(
            "app.api.partner_url_check.save_public_scan",
            new=AsyncMock(return_value=None),
        ):
            response = self.client.post(
                "/api/v1/url-check",
                headers={"Authorization": "Bearer askeal-test-key"},
                json={"url": "not a valid url"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"]["message"], "Invalid or missing URL")

    def test_missing_or_invalid_api_key_returns_401(self):
        response = self.client.post("/api/v1/url-check", json={"url": "https://example.com"})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers["www-authenticate"], "Bearer")

        invalid = self.client.post(
            "/api/v1/url-check",
            headers={"Authorization": "Bearer wrong-key"},
            json={"url": "https://example.com"},
        )
        self.assertEqual(invalid.status_code, 401)
        self.assertEqual(invalid.headers["www-authenticate"], "Bearer")

    def test_monthly_limit_returns_429(self):
        self.api_keys = FakeCollection(
            [
                {
                    "api_key": "limited-key",
                    "partner_name": "Askeal",
                    "created_at": datetime.utcnow(),
                    "monthly_limit": 1,
                    "is_active": True,
                }
            ]
        )
        self.keys_patcher.stop()
        self.keys_patcher = patch.object(
            partner_api_service, "partner_api_keys_collection", self.api_keys
        )
        self.keys_patcher.start()

        with patch(
            "app.api.partner_url_check.analyze_url_full",
            new=AsyncMock(
                return_value={
                    "trust_score": 70,
                    "verdict": "LIKELY SAFE",
                    "confidence": "MODERATE",
                    "summary": {"total_sources_checked": 14},
                    "sources": [],
                }
            ),
        ), patch(
            "app.api.partner_url_check.save_public_scan",
            new=AsyncMock(return_value=None),
        ):
            first = self.client.post(
                "/api/v1/url-check",
                headers={"Authorization": "Bearer limited-key"},
                json={"url": "https://example.com"},
            )
            second = self.client.post(
                "/api/v1/url-check",
                headers={"Authorization": "Bearer limited-key"},
                json={"url": "https://example.com"},
            )

        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)
        self.assertEqual(second.json()["detail"]["message"], "Monthly rate limit exceeded")
        self.assertIn("retry_after", second.json()["detail"])
        self.assertEqual(second.headers["X-RateLimit-Limit"], "1")
        self.assertEqual(second.headers["X-RateLimit-Remaining"], "0")

    def test_internal_scan_failure_returns_500(self):
        with patch(
            "app.api.partner_url_check.analyze_url_full",
            new=AsyncMock(side_effect=RuntimeError("boom")),
        ), patch(
            "app.api.partner_url_check.save_public_scan",
            new=AsyncMock(return_value=None),
        ):
            response = self.client.post(
                "/api/v1/url-check",
                headers={"Authorization": "Bearer askeal-test-key"},
                json={"url": "https://example.com"},
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()["detail"]["message"], "Internal scan failure")


if __name__ == "__main__":
    unittest.main()

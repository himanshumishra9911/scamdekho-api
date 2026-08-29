import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.api.public_pages import build_page_html, build_scanning_page_html
from app.services import public_pages_service


class RecordingCollection:
    def __init__(self):
        self.update_one_calls = []
        self.update_many_calls = []

    async def update_one(self, *args, **kwargs):
        self.update_one_calls.append((args, kwargs))
        return SimpleNamespace(modified_count=1)

    async def update_many(self, *args, **kwargs):
        self.update_many_calls.append((args, kwargs))
        return SimpleNamespace(modified_count=1)


def minimal_doc(domain: str, stored_indexable: bool) -> dict:
    return {
        "domain": domain,
        "indexable": stored_indexable,
        "result": {
            "trust_score": 25,
            "verdict": "HIGH RISK",
            "summary": {},
            "sources": [],
            "other_info": {},
        },
    }


class PublicPageIndexingPolicyTests(unittest.IsolatedAsyncioTestCase):
    def test_only_explicit_major_domains_are_noindex(self):
        for domain in ("google.com", "news.google.com", "facebook.com"):
            with self.subTest(domain=domain):
                self.assertFalse(public_pages_service.should_index_public_domain(domain))

        for domain in (
            "adult-example.xxx",
            "casino-example.com",
            "sports-betting.example",
            "bit.ly",
            "new-unknown-site.com",
        ):
            with self.subTest(domain=domain):
                self.assertTrue(public_pages_service.should_index_public_domain(domain))

    def test_existing_page_ignores_stale_noindex_flag(self):
        html = build_page_html(minimal_doc("casino-example.com", False), [])
        self.assertIn('<meta name="robots" content="index, follow">', html)

        major_html = build_page_html(minimal_doc("google.com", True), [])
        self.assertIn('<meta name="robots" content="noindex, follow">', major_html)

    def test_unscanned_page_uses_same_policy(self):
        self.assertIn(
            '<meta name="robots" content="index, follow">',
            build_scanning_page_html("adult-example.xxx"),
        )
        self.assertIn(
            '<meta name="robots" content="noindex, follow">',
            build_scanning_page_html("facebook.com"),
        )

    async def test_low_quality_scan_is_still_indexable(self):
        collection = RecordingCollection()
        result = {"domain": "casino-example.com", "summary": {}, "sources": []}
        with patch.object(public_pages_service, "pages_collection", collection):
            await public_pages_service.save_public_scan("https://casino-example.com", result)

        stored = collection.update_one_calls[0][0][1]["$set"]
        self.assertTrue(stored["indexable"])
        self.assertLess(stored["quality_score"], 8)

    async def test_major_domain_scan_stays_noindex(self):
        collection = RecordingCollection()
        result = {"domain": "google.com", "summary": {}, "sources": []}
        with patch.object(public_pages_service, "pages_collection", collection):
            await public_pages_service.save_public_scan("https://google.com", result)

        stored = collection.update_one_calls[0][0][1]["$set"]
        self.assertFalse(stored["indexable"])

    async def test_backfill_updates_allowed_and_blocked_records_without_rescans(self):
        collection = RecordingCollection()
        with patch.object(public_pages_service, "pages_collection", collection):
            result = await public_pages_service.sync_public_page_indexability()

        self.assertEqual(result, {"made_indexable": 1, "made_noindex": 1})
        self.assertEqual(len(collection.update_many_calls), 2)
        self.assertEqual(
            collection.update_many_calls[0][0][1],
            {"$set": {"indexable": True}},
        )
        self.assertEqual(
            collection.update_many_calls[1][0][1],
            {"$set": {"indexable": False}},
        )


if __name__ == "__main__":
    unittest.main()

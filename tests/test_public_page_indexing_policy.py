import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.api.public_pages import (
    PUBLIC_REPORT_HEADERS,
    PUBLIC_SCANNING_HEADERS,
    build_page_html,
    build_scanning_page_html,
    public_check_page,
    public_check_page_head,
)
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

    def test_unscanned_page_is_always_noindex(self):
        # The scanning page is a JS-driven skeleton; a crawler never waits for
        # the scan to finish, so it must never be offered for indexing --
        # regardless of what the domain policy says about the eventual report.
        for domain in ("adult-example.xxx", "new-unknown-site.com", "facebook.com"):
            with self.subTest(domain=domain):
                html = build_scanning_page_html(domain)
                self.assertIn('<meta name="robots" content="noindex, follow">', html)
                self.assertNotIn('content="index, follow"', html)

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

    async def test_head_check_is_available_and_cdn_cacheable(self):
        response = await public_check_page_head("casino-example.com")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, b"")
        self.assertIn("s-maxage=604800", response.headers["cache-control"])
        self.assertEqual(
            response.headers["cdn-cache-control"],
            PUBLIC_REPORT_HEADERS["CDN-Cache-Control"],
        )

    async def test_head_check_rejects_invalid_domain(self):
        response = await public_check_page_head("not-a-domain")
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["cache-control"], "no-store")

    async def test_unscanned_shell_is_never_edge_cached(self):
        with patch(
            "app.api.public_pages.get_public_page",
            return_value=None,
        ):
            response = await public_check_page("new-unknown-site.com")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["cache-control"],
            PUBLIC_SCANNING_HEADERS["Cache-Control"],
        )
        self.assertEqual(response.headers["x-robots-tag"], "noindex, follow")
        self.assertEqual(response.headers["x-scamdekho-edge-cacheable"], "no")


if __name__ == "__main__":
    unittest.main()

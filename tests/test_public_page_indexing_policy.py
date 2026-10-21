import unittest
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.api.public_pages import (
    PUBLIC_REPORT_HEADERS,
    PUBLIC_SCANNING_HEADERS,
    build_page_html,
    build_scanning_page_html,
    public_check_page,
    public_check_page_head,
    sitemap_index,
    sitemap_checks_paginated,
)
from app.services import public_pages_service


class RecordingCollection:
    def __init__(self, existing=None):
        self.update_one_calls = []
        self.update_many_calls = []
        self.find_one_calls = []
        self._existing = existing

    async def update_one(self, *args, **kwargs):
        self.update_one_calls.append((args, kwargs))
        return SimpleNamespace(modified_count=1)

    async def update_many(self, *args, **kwargs):
        self.update_many_calls.append((args, kwargs))
        return SimpleNamespace(modified_count=1)

    async def find_one(self, *args, **kwargs):
        # save_public_scan reads the last score_history entry before pushing.
        self.find_one_calls.append((args, kwargs))
        return self._existing


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
            "new-unknown-site.com",
        ):
            with self.subTest(domain=domain):
                self.assertTrue(public_pages_service.should_index_public_domain(domain))

    def test_shorteners_and_throwaway_hosts_are_vetoed(self):
        # One /check/ page per shortened link or per throwaway subdomain is an
        # unbounded index surface that says nothing about a real site.
        for domain in ("bit.ly", "tinyurl.com", "t.co", "share.google"):
            with self.subTest(domain=domain):
                self.assertFalse(public_pages_service.should_index_public_domain(domain))

        for domain in ("abc.web.app", "foo.firebaseapp.com", "bar.translate.goog"):
            with self.subTest(domain=domain):
                self.assertFalse(public_pages_service.should_index_public_domain(domain))

    def test_stored_flag_decides_the_rendered_robots_tag(self):
        # A pruned page must actually serve noindex. Rendering index,follow
        # while dropping the sitemap entry leaves the page in Google's index.
        pruned = build_page_html(minimal_doc("casino-example.com", False), [])
        self.assertIn('<meta name="robots" content="noindex, follow">', pruned)

        kept = build_page_html(minimal_doc("casino-example.com", True), [])
        self.assertIn('<meta name="robots" content="index, follow">', kept)

        major_html = build_page_html(minimal_doc("google.com", True), [])
        self.assertIn('<meta name="robots" content="noindex, follow">', major_html)

    def test_doc_without_indexable_field_still_renders_indexable(self):
        doc = minimal_doc("casino-example.com", True)
        doc.pop("indexable")
        self.assertIn(
            '<meta name="robots" content="index, follow">',
            build_page_html(doc, []),
        )

    def test_unscanned_page_is_always_noindex(self):
        # The scanning page is a JS-driven skeleton; a crawler never waits for
        # the scan to finish, so it must never be offered for indexing --
        # regardless of what the domain policy says about the eventual report.
        for domain in ("adult-example.xxx", "new-unknown-site.com", "facebook.com"):
            with self.subTest(domain=domain):
                html = build_scanning_page_html(domain)
                self.assertIn('<meta name="robots" content="noindex, follow">', html)
                self.assertNotIn('content="index, follow"', html)

    async def test_scan_without_domain_age_is_not_indexable(self):
        # 57% of sampled live /check/ pages published with "Domain Created:
        # Unknown". Under the old 8-of-11 score those still qualified.
        collection = RecordingCollection()
        result = {
            "domain": "casino-example.com",
            "summary": {"positive_signals": 8, "negative_signals": 2},
            "sources": [{"name": f"s{i}"} for i in range(12)],
            "explanation": ["a", "b", "c"],
            "why": ["d", "e"],
            "other_info": {"ip_address": "1.2.3.4", "ssl_issuer": "Let's Encrypt"},
        }
        with patch.object(public_pages_service, "pages_collection", collection):
            await public_pages_service.save_public_scan("https://casino-example.com", result)

        stored = collection.update_one_calls[0][0][1]["$set"]
        self.assertFalse(stored["indexable"])
        self.assertIn("no_domain_age", stored["quality_reasons"])
        # Scores 8 under the retired rule, which is exactly the hole being closed.
        self.assertGreaterEqual(stored["quality_score"], 8)

    async def test_complete_scan_is_indexable(self):
        collection = RecordingCollection()
        result = {
            "domain": "casino-example.com",
            "summary": {"positive_signals": 8, "negative_signals": 2},
            "sources": [{"name": f"s{i}"} for i in range(12)],
            "explanation": ["a", "b", "c"],
            "why": ["d", "e"],
            "other_info": {
                "ip_address": "1.2.3.4",
                "ssl_issuer": "Let's Encrypt",
                "domain_created": "2019-04-02",
            },
        }
        with patch.object(public_pages_service, "pages_collection", collection):
            await public_pages_service.save_public_scan("https://casino-example.com", result)

        stored = collection.update_one_calls[0][0][1]["$set"]
        self.assertTrue(stored["indexable"])

    async def test_thin_scan_is_not_indexable(self):
        collection = RecordingCollection()
        result = {"domain": "casino-example.com", "summary": {}, "sources": []}
        with patch.object(public_pages_service, "pages_collection", collection):
            await public_pages_service.save_public_scan("https://casino-example.com", result)

        stored = collection.update_one_calls[0][0][1]["$set"]
        self.assertFalse(stored["indexable"])

    async def test_proven_search_demand_overrides_the_quality_gate(self):
        # hellohi.in earned 1,649 clicks in 90 days with no domain-age data.
        # The gate must not deindex a page that demonstrably works.
        demand_domain = next(iter(public_pages_service.load_search_demand_domains()))
        collection = RecordingCollection()
        result = {"domain": demand_domain, "summary": {}, "sources": []}
        with patch.object(public_pages_service, "pages_collection", collection):
            await public_pages_service.save_public_scan(f"https://{demand_domain}", result)

        stored = collection.update_one_calls[0][0][1]["$set"]
        self.assertTrue(stored["indexable"])

    async def test_scan_records_a_score_history_point(self):
        collection = RecordingCollection()
        result = {"domain": "casino-example.com", "trust_score": 42, "summary": {}, "sources": []}
        with patch.object(public_pages_service, "pages_collection", collection):
            await public_pages_service.save_public_scan("https://casino-example.com", result)

        update = collection.update_one_calls[0][0][1]
        pushed = update["$push"]["score_history"]["$each"][0]
        self.assertEqual(pushed["trust_score"], 42)
        self.assertEqual(
            update["$push"]["score_history"]["$slice"],
            -public_pages_service.SCORE_HISTORY_LIMIT,
        )

    async def test_repeat_scan_with_same_score_records_nothing_new(self):
        recent = {"score_history": [{"at": datetime.utcnow(), "trust_score": 42}]}
        collection = RecordingCollection(existing=recent)
        result = {"domain": "casino-example.com", "trust_score": 42, "summary": {}, "sources": []}
        with patch.object(public_pages_service, "pages_collection", collection):
            await public_pages_service.save_public_scan("https://casino-example.com", result)

        update = collection.update_one_calls[0][0][1]
        self.assertNotIn("$push", update)

    async def test_scan_without_score_skips_the_history_lookup(self):
        collection = RecordingCollection()
        result = {"domain": "casino-example.com", "summary": {}, "sources": []}
        with patch.object(public_pages_service, "pages_collection", collection):
            await public_pages_service.save_public_scan("https://casino-example.com", result)

        self.assertEqual(collection.find_one_calls, [])
        self.assertNotIn("$push", collection.update_one_calls[0][0][1])

    def test_search_demand_list_loads_and_skips_comments(self):
        demand = public_pages_service.load_search_demand_domains()
        self.assertIn("hellohi.in", demand)
        self.assertIn("manthread.in", demand)
        self.assertNotIn("", demand)
        self.assertFalse(any(d.startswith("#") for d in demand))

    async def test_major_domain_scan_stays_noindex(self):
        collection = RecordingCollection()
        result = {"domain": "google.com", "summary": {}, "sources": []}
        with patch.object(public_pages_service, "pages_collection", collection):
            await public_pages_service.save_public_scan("https://google.com", result)

        stored = collection.update_one_calls[0][0][1]["$set"]
        self.assertFalse(stored["indexable"])

    async def test_boot_sync_only_removes_major_domains_from_the_index(self):
        # It used to also set indexable:True on every non-major domain, so a
        # deploy re-indexed the whole corpus and undid any prune on restart.
        collection = RecordingCollection()
        with patch.object(public_pages_service, "pages_collection", collection):
            result = await public_pages_service.sync_public_page_indexability()

        self.assertEqual(result, {"made_indexable": 0, "made_noindex": 1})
        self.assertEqual(len(collection.update_many_calls), 1)
        self.assertEqual(
            collection.update_many_calls[0][0][1],
            {"$set": {"indexable": False}},
        )
        for args, _kwargs in collection.update_many_calls:
            self.assertNotEqual(args[1], {"$set": {"indexable": True}})

    async def test_head_check_is_available_and_cdn_cacheable(self):
        with patch("app.api.public_pages.get_public_page", return_value=minimal_doc("casino-example.com", True)):
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

    async def test_database_failure_is_not_a_missing_report(self):
        collection = SimpleNamespace(find_one=AsyncMock(side_effect=RuntimeError("offline")))
        with patch.object(public_pages_service, "pages_collection", collection):
            with self.assertRaises(public_pages_service.PublicPageStorageUnavailable):
                await public_pages_service.get_public_page("existing.example")

    async def test_report_outage_is_retryable_not_noindex(self):
        for handler in (public_check_page, public_check_page_head):
            with patch("app.api.public_pages.get_public_page", side_effect=public_pages_service.PublicPageStorageUnavailable("offline")):
                response = await handler("existing.example")
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.headers["retry-after"], "60")
            self.assertIn("no-store", response.headers["cache-control"])
            self.assertNotIn("x-robots-tag", response.headers)
            self.assertNotIn(b"noindex", response.body)

    async def test_missing_report_head_matches_get_cache_policy(self):
        with patch("app.api.public_pages.get_public_page", return_value=None):
            response = await public_check_page_head("new.example")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.body, b"")
        self.assertEqual(response.headers["x-robots-tag"], "noindex, follow")
        self.assertIn("no-store", response.headers["cache-control"])

    async def test_sitemap_database_errors_are_not_empty_successful_sitemaps(self):
        collection = SimpleNamespace(
            count_documents=AsyncMock(side_effect=RuntimeError("offline")),
            find=lambda *args: (_ for _ in ()).throw(RuntimeError("offline")),
        )
        with patch("app.api.public_pages.pages_collection", collection):
            responses = [await sitemap_index(), await sitemap_checks_paginated(0)]
        for response in responses:
            self.assertEqual(response.status_code, 503)
            self.assertIn("no-store", response.headers["cache-control"])
            self.assertNotIn(b"<urlset", response.body)


class ScanHistoryTests(unittest.TestCase):
    """The one section on the report a template cannot fabricate."""

    def _doc_with_history(self, points):
        doc = minimal_doc("casino-example.com", True)
        doc["first_scanned"] = datetime(2026, 4, 2)
        doc["score_history"] = [
            {"at": at, "trust_score": score} for at, score in points
        ]
        return doc

    def test_single_data_point_renders_no_history_section(self):
        # One point just restates the facts table.
        doc = self._doc_with_history([(datetime(2026, 4, 2), 25)])
        self.assertNotIn("What Has Changed", build_page_html(doc, []))

    def test_no_history_field_renders_no_history_section(self):
        self.assertNotIn("What Has Changed", build_page_html(minimal_doc("a.com", True), []))

    def test_falling_score_is_reported_as_a_fall(self):
        doc = self._doc_with_history(
            [(datetime(2026, 4, 2), 80), (datetime(2026, 9, 12), 40)]
        )
        html = build_page_html(doc, [])
        self.assertIn("What Has Changed", html)
        # minimal_doc's current trust_score is 25, first recorded is 80.
        self.assertIn("fallen 55 points", html)
        self.assertIn("02 Apr 2026", html)
        self.assertIn("12 Sep 2026", html)

    def test_malformed_history_entries_are_skipped(self):
        doc = minimal_doc("casino-example.com", True)
        doc["score_history"] = [
            "not-a-dict",
            {"at": "not-a-date", "trust_score": 10},
            {"at": datetime(2026, 4, 2)},
            {"at": datetime(2026, 4, 3), "trust_score": 60},
        ]
        # Only one usable point survives, so no section rather than a broken one.
        self.assertNotIn("What Has Changed", build_page_html(doc, []))


class ScanHistoryRecordingTests(unittest.TestCase):
    def test_first_point_is_always_recorded(self):
        point = {"at": datetime(2026, 4, 2), "trust_score": 70}
        self.assertTrue(public_pages_service._should_record_history(None, point))
        self.assertTrue(public_pages_service._should_record_history([], point))

    def test_changed_score_is_recorded_immediately(self):
        previous = [{"at": datetime(2026, 4, 2, 10), "trust_score": 70}]
        point = {"at": datetime(2026, 4, 2, 11), "trust_score": 45}
        self.assertTrue(public_pages_service._should_record_history(previous, point))

    def test_unchanged_score_is_throttled_to_once_a_day(self):
        previous = [{"at": datetime(2026, 4, 2, 10), "trust_score": 70}]
        same_day = {"at": datetime(2026, 4, 2, 18), "trust_score": 70}
        next_day = {"at": datetime(2026, 4, 3, 11), "trust_score": 70}
        self.assertFalse(public_pages_service._should_record_history(previous, same_day))
        self.assertTrue(public_pages_service._should_record_history(previous, next_day))

    def test_scan_without_a_score_produces_no_point(self):
        self.assertIsNone(
            public_pages_service._score_history_point({}, datetime(2026, 4, 2))
        )
        self.assertIsNone(
            public_pages_service._score_history_point(
                {"trust_score": "n/a"}, datetime(2026, 4, 2)
            )
        )


if __name__ == "__main__":
    unittest.main()

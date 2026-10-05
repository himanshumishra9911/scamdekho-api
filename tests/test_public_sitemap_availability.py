import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.api import public_sitemaps


class PublicSitemapAvailabilityTests(unittest.IsolatedAsyncioTestCase):
    async def test_sort_fallback_preserves_complete_results(self):
        docs = [{"domain": "saved.example"}]
        find = AsyncMock(side_effect=[RuntimeError("sort unavailable"), docs])
        with patch.object(public_sitemaps, "_find_sitemap_docs", find):
            response = await public_sitemaps.sitemap_checks_paginated(0)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"saved.example", response.body)
        self.assertEqual(find.await_count, 2)

    async def test_all_query_failures_return_retryable_503(self):
        with patch.object(public_sitemaps, "_find_sitemap_docs", AsyncMock(side_effect=RuntimeError("offline"))):
            response = await public_sitemaps.sitemap_checks_legacy()
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(response.headers["retry-after"], "60")
        self.assertNotIn(b"<urlset", response.body)

    async def test_failed_count_is_not_published_as_one_page(self):
        collection = SimpleNamespace(count_documents=AsyncMock(side_effect=RuntimeError("offline")))
        with patch.object(public_sitemaps, "pages_collection", collection):
            response = await public_sitemaps.sitemap_index()
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"<sitemapindex", response.body)

    async def test_genuine_empty_result_is_still_successful(self):
        with patch.object(public_sitemaps, "_find_sitemap_docs", AsyncMock(return_value=[])):
            response = await public_sitemaps.sitemap_checks_paginated(1)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<urlset", response.body)


if __name__ == "__main__":
    unittest.main()

import asyncio
import json
import os
import time
import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from app.content_automation.collectors import parse_feed
from app.content_automation.config import ContentAutomationConfig
from app.content_automation.integrations import (
    GoogleTokenProvider,
    official_references_for_query,
    product_links_for_query,
    research_references_for_candidate,
)
from app.content_automation.models import ArticleDraft, SourceReference, TopicCandidate
from app.content_automation.payloads import build_wordpress_draft_payload
from app.content_automation.pipeline import _can_retry_topic, _target_quotas, build_candidate_pools
from app.content_automation.quality import QualityGate
from app.content_automation.topic_engine import consolidate_candidates, score_candidate, similarity
from app.content_automation.writer import ArticleWriter


class ContentAutomationTests(unittest.TestCase):
    def test_daily_limit_is_hard_capped_at_three(self):
        with patch.dict(os.environ, {"CONTENT_MAX_DRAFTS_PER_DAY": "99"}, clear=False):
            config = ContentAutomationConfig.from_env()
        self.assertEqual(config.max_drafts_per_day, 3)

    def test_live_run_requires_google_credentials_and_sheet(self):
        config = ContentAutomationConfig(
            enabled=True,
            openai_api_key="test-key",
            wordpress_username="automation",
            wordpress_application_password="application-password",
        )
        errors = config.validate_for_run(dry_run=False)
        self.assertTrue(any("GOOGLE_SERVICE_ACCOUNT" in error for error in errors))
        self.assertIn("GOOGLE_SHEET_ID is required", errors)

    def test_default_threshold_accepts_fresh_news_opportunities(self):
        config = ContentAutomationConfig(
            relevance_terms=["scam"],
            maximum_sources=4,
        )
        candidate = TopicCandidate(
            title="New online scam warning for Indian users",
            source_type="news",
            source_name="Trusted News",
            url="https://example.org/scam-warning",
            published_at=datetime.now(timezone.utc),
        )
        ranked = consolidate_candidates([candidate], config)
        self.assertEqual(len(ranked), 1)
        self.assertGreaterEqual(
            ranked[0].opportunity_score,
            config.minimum_opportunity_score,
        )

    def test_daily_mix_is_two_gsc_topics_and_one_news_topic(self):
        candidates = [
            TopicCandidate("fake payment checker", "gsc", "GSC", "https://scamdekho.in"),
            TopicCandidate("scam website checker", "gsc", "GSC", "https://scamdekho.in"),
            TopicCandidate("scam dekho", "gsc", "GSC", "https://scamdekho.in"),
            TopicCandidate("New UPI fraud warning in India", "news", "News", "https://example.com/news"),
        ]
        pools = build_candidate_pools(candidates)
        self.assertEqual(_target_quotas(3), {"gsc": 2, "news": 1})
        self.assertEqual(len(pools["gsc"]), 2)
        self.assertEqual(len(pools["news"]), 1)

    def test_source_skip_can_retry_same_day_without_retrying_ai_quality_failure(self):
        run_key = "daily:2026-08-01"
        self.assertTrue(_can_retry_topic(
            {"status": "skipped_insufficient_sources", "run_key": run_key},
            run_key,
        ))
        self.assertFalse(_can_retry_topic(
            {"status": "quality_failed", "run_key": run_key},
            run_key,
        ))
        self.assertTrue(_can_retry_topic(
            {"status": "quality_failed", "run_key": "daily:2026-07-31"},
            run_key,
        ))

    def test_gsc_decline_increases_opportunity_score(self):
        stable = TopicCandidate(
            "fake payment checker", "gsc", "GSC", "https://scamdekho.in",
            impressions=500, clicks=10, position=8,
        )
        declining = TopicCandidate(
            "fake payment checker", "gsc", "GSC", "https://scamdekho.in",
            impressions=500, clicks=10, position=8,
            impression_change=-400, click_change=-15,
        )
        self.assertGreater(score_candidate(declining), score_candidate(stable))

    def test_gsc_pool_prioritizes_largest_traffic_decline(self):
        small_drop = TopicCandidate(
            "scam website checker", "gsc", "GSC", "https://scamdekho.in",
            impressions=1000, click_change=-2, impression_change=-100,
            opportunity_score=95,
        )
        large_drop = TopicCandidate(
            "fake payment checker", "gsc", "GSC", "https://scamdekho.in",
            impressions=500, click_change=-20, impression_change=-400,
            opportunity_score=70,
        )
        pools = build_candidate_pools([small_drop, large_drop])
        self.assertEqual(pools["gsc"][0].title, "fake payment checker")

    def test_gsc_queries_receive_two_independent_official_sources(self):
        references = official_references_for_query("fake payment upi gpay")
        hosts = {reference.url.split("/")[2] for reference in references}
        self.assertGreaterEqual(len(hosts), 2)
        self.assertTrue(any("npci.org.in" in host for host in hosts))

    def test_news_queries_receive_two_independent_official_sources(self):
        candidate = TopicCandidate(
            "New online shopping scam reported in India",
            "news",
            "Trusted News",
            "https://www.thehindu.com/example",
            excerpt="A current report about an online shopping scam.",
        )
        candidate.ensure_reference()
        references = research_references_for_candidate(candidate, [])
        hosts = {reference.url.split("/")[2] for reference in references}
        self.assertIn("www.thehindu.com", hosts)
        self.assertGreaterEqual(len(hosts), 2)
        self.assertTrue(any("cybercrime.gov.in" in host for host in hosts))

    def test_writer_uses_model_compatible_completion_token_parameter(self):
        captured = {}

        class FakeCompletions:
            async def create(self, **kwargs):
                captured.update(kwargs)
                payload = {
                    "title": "Online Scam Safety Checks for Indian Users",
                    "slug": "online-scam-safety-checks-india",
                    "meta_description": "Practical online scam safety checks for Indian users, based on current trusted guidance and prepared as a draft for human review.",
                    "excerpt": "Practical online scam safety checks.",
                    "primary_keyword": "online scam safety",
                    "secondary_keywords": ["online fraud"],
                    "html": "<h2>What to check</h2><p>Verify the request.</p>",
                    "faqs": [],
                }
                return SimpleNamespace(
                    choices=[SimpleNamespace(message=SimpleNamespace(content=json.dumps(payload)))]
                )

        writer = object.__new__(ArticleWriter)
        writer.config = ContentAutomationConfig(content_model="test-model")
        writer.client = SimpleNamespace(
            chat=SimpleNamespace(completions=FakeCompletions())
        )
        candidate = TopicCandidate(
            "Online scam safety",
            "news",
            "Trusted News",
            "https://www.thehindu.com/example",
            primary_keyword="online scam safety",
        )
        references = official_references_for_query(candidate.title)
        asyncio.run(writer.write(candidate, references, []))
        self.assertEqual(captured["max_completion_tokens"], 3800)
        self.assertNotIn("max_tokens", captured)

    def test_google_token_refresh_is_serialized(self):
        provider = GoogleTokenProvider({"client_email": "test@example.com"})
        refresh_count = 0

        def fake_refresh():
            nonlocal refresh_count
            if provider._credentials is None:
                refresh_count += 1
                time.sleep(0.05)
                provider._credentials = object()
            return "test-token"

        provider._refresh_sync = fake_refresh

        async def run_concurrently():
            return await asyncio.gather(provider.access_token(), provider.access_token())

        tokens = asyncio.run(run_concurrently())
        self.assertEqual(tokens, ["test-token", "test-token"])
        self.assertEqual(refresh_count, 1)

    def test_product_pages_are_prioritized_for_internal_links(self):
        payment = product_links_for_query("fake PhonePe payment screenshot")
        website = product_links_for_query("scam website checker")
        self.assertTrue(payment[0]["url"].endswith("/fake-payment-screenshot-checker"))
        self.assertTrue(website[0]["url"].endswith("/url-checker"))

    def test_rss_parser_extracts_topic(self):
        xml = """<?xml version="1.0"?>
        <rss><channel><item>
          <title>New UPI scam warning for Indian users</title>
          <link>https://example.org/upi-warning</link>
          <description>Officials shared practical safety checks.</description>
          <pubDate>Thu, 30 Jul 2026 08:00:00 GMT</pubDate>
        </item></channel></rss>"""
        items = parse_feed(xml, "rss", "Example")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].source_type, "rss")
        self.assertEqual(items[0].url, "https://example.org/upi-warning")
        self.assertIsNotNone(items[0].published_at)

    def test_near_duplicate_topics_are_consolidated(self):
        config = ContentAutomationConfig(
            relevance_terms=["upi", "scam"],
            maximum_sources=4,
        )
        first = TopicCandidate(
            title="New UPI scam warning for Indian users",
            source_type="news",
            source_name="One",
            url="https://one.example/story",
            published_at=datetime.now(timezone.utc),
        )
        second = TopicCandidate(
            title="UPI scam warning issued for users in India",
            source_type="rss",
            source_name="Two",
            url="https://two.example/story",
            published_at=datetime.now(timezone.utc),
        )
        self.assertGreaterEqual(similarity(first.title, second.title), 0.5)
        merged = consolidate_candidates([first, second], config)
        self.assertEqual(len(merged), 1)
        self.assertEqual(len(merged[0].source_references), 2)
        self.assertIn("confirmed across", merged[0].why_chosen)

    def test_quality_gate_accepts_complete_source_grounded_draft(self):
        paragraphs = "".join(
            f"<p>UPI scam safety advice helps users verify payment requests before acting. "
            f"This practical section explains a different warning sign and a safe response step {i}. "
            "Users should confirm requests through an official app or phone number.</p>"
            for i in range(35)
        )
        html = (
            "<h2>What happened</h2>" + paragraphs[: len(paragraphs) // 4]
            + "<h2>Warning signs</h2>" + paragraphs[len(paragraphs) // 4 : len(paragraphs) // 2]
            + "<h2>How to verify</h2>" + paragraphs[len(paragraphs) // 2 : 3 * len(paragraphs) // 4]
            + "<h2>What users should do</h2>" + paragraphs[3 * len(paragraphs) // 4 :]
            + '<p><a href="https://scamdekho.in/blog/guide-one">Guide one</a> '
            + '<a href="https://scamdekho.in/blog/guide-two">Guide two</a></p>'
        )
        references = [
            SourceReference("Source one", "https://example.com/one", "Example"),
            SourceReference("Source two", "https://example.org/two", "Example Org"),
        ]
        draft = ArticleDraft(
            title="UPI Scam Warning Signs Every Indian User Should Know",
            slug="upi-scam-warning-signs-india",
            meta_description=(
                "Learn the latest UPI scam warning signs, how to verify payment requests, "
                "and the practical steps Indian users can take before sending money."
            ),
            excerpt="A practical UPI scam safety guide.",
            content_html=html,
            primary_keyword="upi scam",
            secondary_keywords=["upi fraud", "payment safety"],
            faqs=[
                {"question": "One?", "answer": "Answer one."},
                {"question": "Two?", "answer": "Answer two."},
                {"question": "Three?", "answer": "Answer three."},
            ],
            schema={},
            references=references,
        )
        report = QualityGate("https://scamdekho.in", 75).evaluate(draft)
        self.assertTrue(report.passed, report.issues)
        self.assertGreaterEqual(report.score, 90)

    def test_wordpress_payload_is_always_a_draft(self):
        article = ArticleDraft(
            title="A careful source-grounded safety update",
            slug="careful-safety-update",
            meta_description="A factual summary prepared for review before publication.",
            excerpt="Summary",
            content_html="<p>Draft body</p>",
            primary_keyword="safety update",
            secondary_keywords=[],
            faqs=[],
            schema={},
            references=[],
        )
        payload = build_wordpress_draft_payload(article, [7])
        self.assertEqual(payload["status"], "draft")
        self.assertNotIn("featured_media", payload)
        self.assertEqual(payload["categories"], [7])


if __name__ == "__main__":
    unittest.main()

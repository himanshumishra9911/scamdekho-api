import os
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from app.content_automation.collectors import parse_feed
from app.content_automation.config import ContentAutomationConfig
from app.content_automation.models import ArticleDraft, SourceReference, TopicCandidate
from app.content_automation.payloads import build_wordpress_draft_payload
from app.content_automation.quality import QualityGate
from app.content_automation.topic_engine import consolidate_candidates, similarity


class ContentAutomationTests(unittest.TestCase):
    def test_daily_limit_is_hard_capped_at_three(self):
        with patch.dict(os.environ, {"CONTENT_MAX_DRAFTS_PER_DAY": "99"}, clear=False):
            config = ContentAutomationConfig.from_env()
        self.assertEqual(config.max_drafts_per_day, 3)

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

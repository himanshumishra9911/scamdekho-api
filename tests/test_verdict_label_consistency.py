import re
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from app.api.public_pages import build_page_html
from app.services import public_pages_service, seo_content_engine
from app.utils.scoring import display_verdict


def doc_with(trust_score: int, stored_verdict: str) -> dict:
    """A page whose stored verdict disagrees with its trust score.

    This is the shape that shipped the bug: v1.py wrote a binary
    "SCAM" if ts < 40 else "SAFE" into result["verdict"], while the ring,
    meta description and summary line were all derived from trust_score.
    """
    return {
        "domain": "example-test.com",
        "indexable": True,
        "result": {
            "trust_score": trust_score,
            "verdict": stored_verdict,
            "summary": {},
            "sources": [],
            "other_info": {},
        },
    }


class VerdictLabelTests(unittest.TestCase):
    def test_bands(self):
        self.assertEqual(display_verdict(92), "SAFE")
        self.assertEqual(display_verdict(70), "SAFE")
        self.assertEqual(display_verdict(69), "SUSPICIOUS")
        self.assertEqual(display_verdict(50), "SUSPICIOUS")
        self.assertEqual(display_verdict(48), "HIGH RISK")
        self.assertEqual(display_verdict(30), "HIGH RISK")
        self.assertEqual(display_verdict(19), "SCAM")

    def test_label_ignores_a_contradictory_stored_verdict(self):
        # getmodpc.net shipped exactly this: score 48, red ring, and the word
        # SAFE, because the stored verdict said SAFE.
        html = build_page_html(doc_with(48, "SAFE"), [])
        self.assertNotIn(">SAFE<", html)
        self.assertIn("HIGH RISK", html)

    def test_two_pages_on_the_same_score_get_the_same_label(self):
        # soleplay.inc (SCAM) and getmodpc.net (SAFE) both scored 48.
        a = build_page_html(doc_with(48, "SCAM"), [])
        b = build_page_html(doc_with(48, "SAFE"), [])
        grab = lambda h: re.search(r'verdict-big"[^>]*>(\w[\w ]*)<', h).group(1)
        self.assertEqual(grab(a), grab(b))

    def test_label_never_contradicts_the_ring_colour(self):
        red, green = "#dc2626", "#16a34a"
        for score in (5, 19, 29, 35, 48, 55, 69, 75, 92, 100):
            with self.subTest(score=score):
                html = build_page_html(doc_with(score, "SAFE"), [])
                m = re.search(r'verdict-big" style="color:(#[0-9a-f]{6});">(\w[\w ]*)<', html)
                colour, label = m.group(1), m.group(2)
                if colour == red:
                    self.assertIn(label, ("SCAM", "HIGH RISK"))
                elif colour == green:
                    self.assertEqual(label, "SAFE")


class SeoContentVersionTests(unittest.IsolatedAsyncioTestCase):
    async def test_stale_article_version_forces_one_regeneration(self):
        """The reason the 25 Aug label fix had to be reverted.

        A render-time label fix corrects every page instantly, but the stored
        article was written against the old verdict. Without a version gate the
        cache never expires and the page argues with itself.
        """
        calls = []

        class Collection:
            async def update_one(self, *args, **kwargs):
                calls.append(kwargs or args)
                return SimpleNamespace(modified_count=1)

        doc = {
            "domain": "example-test.com",
            "result": {"trust_score": 48},
            "seo_content": "<p>stale article calling it safe</p>",
            "seo_content_score": 48,
            "seo_content_version": 1,
        }

        async def fake_generate(domain, result):
            return "<p>regenerated</p>"

        with patch.object(public_pages_service, "pages_collection", Collection()), \
             patch.object(seo_content_engine, "generate_seo_content", fake_generate):
            out = await seo_content_engine.ensure_seo_content(dict(doc))
        self.assertEqual(out, "<p>regenerated</p>")

        # Same doc at the current version must NOT spend a GPT call.
        doc_current = dict(doc, seo_content_version=seo_content_engine.SEO_CONTENT_VERSION)

        async def explode(domain, result):
            raise AssertionError("regenerated a page that was already current")

        with patch.object(public_pages_service, "pages_collection", Collection()), \
             patch.object(seo_content_engine, "generate_seo_content", explode):
            out2 = await seo_content_engine.ensure_seo_content(doc_current)
        self.assertEqual(out2, doc["seo_content"])


if __name__ == "__main__":
    unittest.main()

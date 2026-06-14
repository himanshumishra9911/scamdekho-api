"""
seo_content_engine.py  —  ScamDekho
====================================
Har /check/{domain} page ke liye 400-500 word UNIQUE content GPT se banata hai,
HEADINGS ke saath (ScamAdviser jaisa: section-wise).

COST CONTROL:
  - Content top-level doc.seo_content me cache hota hai (re-scan pe wipe NAHI hota).
  - Sirf tab regenerate hota hai jab content missing ho YA trust score badal jaye (>6 points).
  - Pageview pe kabhi GPT call nahi → page DB se serve → $0.
  - Model: gpt-4.1-nano (sabse sasta). 50k pages ≈ $15 one-time.
  - Fail ho to None → template fallback chalega.

File location: app/services/seo_content_engine.py
"""

import os
import json
import html as html_lib
import logging
from openai import AsyncOpenAI

logger = logging.getLogger(__name__)

client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Sabse sasta model. Account pe na ho to "gpt-4o-mini" env me set kar dena.
SEO_CONTENT_MODEL = os.getenv("SEO_CONTENT_MODEL", "gpt-4.1-nano")

# Score itna badle tabhi content dobara banega (paisa bachane ke liye)
REGEN_SCORE_DELTA = 6

SYSTEM_PROMPT = (
    "You are an SEO copywriter for ScamDekho, a website-safety checker for Indian users. "
    "You write clear, factual, original website reviews split into labelled sections. "
    "STRICT RULES: Use ONLY the facts provided — never invent owner names, dates, scores, or sources. "
    "Simple English, neutral and helpful tone, no fluff, no repetition. Total 400-500 words across all sections. "
    "Return ONLY valid JSON, no markdown."
)


def _esc(s: str) -> str:
    return html_lib.escape(s or "")


def _compact_facts(domain: str, result: dict) -> str:
    other = result.get("other_info") or {}
    summary = result.get("summary") or {}
    sources = result.get("sources") or []
    pos = [s.get("message", "") for s in sources if s.get("status") == "positive"][:8]
    neg = [s.get("message", "") for s in sources if s.get("status") == "negative"][:8]
    return "\n".join([
        f"Domain: {domain}",
        f"Trust score: {result.get('trust_score', 50)}/100",
        f"Verdict: {result.get('verdict', 'UNKNOWN')}",
        f"Domain created: {other.get('domain_created', 'Unknown')}",
        f"SSL issuer: {other.get('ssl_issuer', 'Unknown')}",
        f"Server location: {other.get('server_location', 'Unknown')}",
        f"Blacklisted: {result.get('blacklisted', False)}",
        f"Checks passed: {summary.get('positive_signals', 0)} | flagged: {summary.get('negative_signals', 0)} | neutral: {summary.get('neutral_signals', 0)}",
        f"Positive signals: {'; '.join(p for p in pos if p) or 'none'}",
        f"Warning signals: {'; '.join(n for n in neg if n) or 'none'}",
    ])


async def generate_seo_content(domain: str, result: dict) -> str | None:
    """
    Section-wise 400-500 word content banao. Success -> HTML (h3 + p), fail -> None.
    """
    try:
        facts = _compact_facts(domain, result)
        user_prompt = (
            f"Write a website safety review of '{domain}' as 5-6 labelled sections, 400-500 words total.\n\n"
            f"FACTS (use only these, invent nothing):\n{facts}\n\n"
            f"Use these section headings in order: "
            f"'Trust Score Overview', 'Domain Age & History', 'SSL & Connection Security', "
            f"'Reputation & Blacklist Check', 'Hosting & Technical Signals', 'Conclusion: Is {domain} Safe?'. "
            f"Skip a section only if there is no data for it. Each section body is 1 short paragraph (60-90 words). "
            f"Naturally include phrases like 'is {domain} legit', 'is {domain} safe', '{domain} review' where they fit.\n\n"
            f'Return JSON exactly like: {{"sections":[{{"heading":"...","body":"..."}}]}}'
        )

        resp = await client.chat.completions.create(
            model=SEO_CONTENT_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.6,
            max_tokens=850,
            response_format={"type": "json_object"},
        )
        data = json.loads(resp.choices[0].message.content or "{}")
        sections = data.get("sections") or []
        if not sections:
            return None

        html = ""
        for sec in sections:
            heading = (sec.get("heading") or "").strip()
            body = (sec.get("body") or "").strip()
            if not body:
                continue
            if heading:
                html += f"<h3>{_esc(heading)}</h3>"
            html += f"<p>{_esc(body)}</p>"

        return html if len(html) > 150 else None

    except Exception as e:
        logger.error(f"SEO content gen failed for {domain}: {e}")
        return None


async def ensure_seo_content(doc: dict) -> str | None:
    """
    generate-once-cache-forever + re-scan smart:
      - Agar seo_content hai AUR score zyada nahi badla -> wahi return (GPT NAHI, $0)
      - Missing ya score kaafi badal gaya -> ek baar generate, top-level save, return
    seo_content TOP-LEVEL store hota hai (result ke andar nahi) taaki re-scan pe wipe na ho.
    """
    from app.services.public_pages_service import pages_collection

    result = doc.get("result") or {}
    current_score = int(result.get("trust_score", 50))

    cached = doc.get("seo_content")
    cached_score = doc.get("seo_content_score")
    if cached and cached_score is not None and abs(int(cached_score) - current_score) <= REGEN_SCORE_DELTA:
        return cached  # cache hit — koi GPT call nahi

    domain = doc.get("domain")
    if not domain:
        return cached

    content = await generate_seo_content(domain, result)
    if not content:
        return cached  # generate fail -> jo purana tha wahi (ya None -> template)

    try:
        await pages_collection.update_one(
            {"_id": domain},
            {"$set": {"seo_content": content, "seo_content_score": current_score}},
        )
    except Exception as e:
        logger.error(f"Could not cache seo_content for {domain}: {e}")

    return content

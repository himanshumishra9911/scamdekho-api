"""
seo_content_engine.py  —  ScamDekho
====================================
Har /check/{domain} page ke liye 400-500 word UNIQUE content GPT se banata hai.

COST CONTROL (ye sabse important hai):
  - Content sirf EK BAAR generate hota hai, phir result.seo_content me DB me save.
  - Pageview pe kabhi GPT call nahi hota → page DB se serve hota hai → $0.
  - Sirf un domains pe generate hota hai jo actually khulte/index hote hain (lazy).
  - Model: gpt-4.1-nano (sabse sasta). 50k pages ≈ $15 one-time.
  - GPT fail ho to None return → template fallback chalega, paisa waste nahi.

File location: app/services/seo_content_engine.py
"""

import os
import logging
from openai import AsyncOpenAI

logger = logging.getLogger(__name__)

client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# Sabse sasta model. Account pe na ho to "gpt-4o-mini" set kar dena env me.
SEO_CONTENT_MODEL = os.getenv("SEO_CONTENT_MODEL", "gpt-4.1-nano")

SYSTEM_PROMPT = (
    "You are an SEO copywriter for ScamDekho, a website-safety checker for Indian users. "
    "You write clear, factual, original 400-500 word reviews of whether a website is legit or a scam. "
    "STRICT RULES: Only use the facts provided — never invent owner names, dates, scores or sources. "
    "Write in simple English, neutral and helpful tone. No marketing fluff, no repetition. "
    "Each review must read uniquely based on the specific data given. "
    "Output 4-6 short paragraphs of plain prose. Do NOT use markdown, headings, bullet points, or HTML — just paragraphs separated by blank lines."
)


def _compact_facts(domain: str, result: dict) -> str:
    """GPT ko sirf zaroori facts bhejo (kam tokens = kam paisa)."""
    other = result.get("other_info") or {}
    summary = result.get("summary") or {}
    sources = result.get("sources") or []

    pos = [s.get("message", "") for s in sources if s.get("status") == "positive"][:8]
    neg = [s.get("message", "") for s in sources if s.get("status") == "negative"][:8]

    lines = [
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
    ]
    return "\n".join(lines)


async def generate_seo_content(domain: str, result: dict) -> str | None:
    """
    400-500 word unique content banao. Success pe HTML paragraphs return,
    fail pe None (caller template fallback use karega).
    """
    try:
        facts = _compact_facts(domain, result)
        user_prompt = (
            f"Write a 400-500 word website safety review for '{domain}'.\n\n"
            f"FACTS (use only these, do not invent anything):\n{facts}\n\n"
            f"Structure: (1) opening that states the domain, its trust score and what it means; "
            f"(2) domain age / history; (3) SSL & connection security; (4) reputation / blacklist results; "
            f"(5) hosting & technical signals; (6) a short closing recommendation on whether to trust it. "
            f"Naturally include phrases like 'is {domain} legit', 'is {domain} safe', and '{domain} review' "
            f"where they fit. Keep it factual and specific to the data above."
        )

        resp = await client.chat.completions.create(
            model=SEO_CONTENT_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.6,          # thodi variation taaki pages alag lagein
            max_tokens=750,           # ~500 words ka safe limit
        )
        text = (resp.choices[0].message.content or "").strip()
        if len(text) < 200:           # bahut chhota = fail maano
            return None

        # plain paragraphs ko <p> me wrap karo
        paras = [p.strip() for p in text.split("\n") if p.strip()]
        html = "".join(
            f'<p style="margin-bottom:14px;line-height:1.8;color:#334155;">{_esc(p)}</p>'
            for p in paras
        )
        return html

    except Exception as e:
        logger.error(f"SEO content gen failed for {domain}: {e}")
        return None


def _esc(s: str) -> str:
    import html as _h
    return _h.escape(s or "")


# ──────────────────────────────────────────────
# ENSURE HELPER — generate-once-cache-forever
# Page route ya seeder dono isse call kar sakte hain.
# ──────────────────────────────────────────────
async def ensure_seo_content(doc: dict) -> str | None:
    """
    Agar is domain ka seo_content pehle se DB me hai → wahi return (GPT call NAHI).
    Nahi hai → ek baar generate, DB me save, phir return.
    """
    from app.services.public_pages_service import pages_collection

    result = doc.get("result") or {}
    existing = result.get("seo_content")
    if existing:
        return existing                      # cache hit — $0

    domain = doc.get("domain")
    if not domain:
        return None

    content = await generate_seo_content(domain, result)
    if not content:
        return None

    # DB me hamesha ke liye save — dobara kabhi generate nahi hoga
    try:
        await pages_collection.update_one(
            {"_id": domain},
            {"$set": {"result.seo_content": content}},
        )
    except Exception as e:
        logger.error(f"Could not cache seo_content for {domain}: {e}")

    return content

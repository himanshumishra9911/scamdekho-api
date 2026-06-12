"""
Public Check Pages Router — ScamDekho
======================================
SSR HTML pages: /check/{domain}
Sitemap:        /sitemap-checks.xml
Widget API:     /api/v1/recent-checks

File location: app/api/public_pages.py
"""

import html as html_lib
from datetime import datetime
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, Response, JSONResponse

from app.services.public_pages_service import (
    get_public_page,
    get_recent_pages,
    get_indexable_domains_for_sitemap,
    normalize_domain,
)

router = APIRouter()

SITE = "https://scamdekho.in"


def esc(s) -> str:
    return html_lib.escape(str(s or ""))


def verdict_color(ts: int) -> tuple:
    if ts >= 70:
        return ("#16a34a", "#f0fdf4", "looks safe")
    if ts >= 50:
        return ("#d97706", "#fffbeb", "looks suspicious")
    return ("#dc2626", "#fef2f2", "is high risk")


def build_page_html(doc: dict, related: list) -> str:
    domain = esc(doc["domain"])
    r = doc.get("result", {})
    ts = int(r.get("trust_score", 50))
    verdict = esc(r.get("verdict", "UNKNOWN"))
    color, bg, verdict_phrase = verdict_color(ts)
    other = r.get("other_info") or {}
    summary = r.get("summary") or {}
    sources = r.get("sources") or []
    explanation = r.get("explanation") or []
    last_scanned = doc.get("last_scanned")
    last_str = last_scanned.strftime("%B %d, %Y") if isinstance(last_scanned, datetime) else "Recently"
    last_iso = last_scanned.strftime("%Y-%m-%d") if isinstance(last_scanned, datetime) else ""
    scan_count = int(doc.get("scan_count", 1))
    indexable = bool(doc.get("indexable"))
    robots = "index, follow" if indexable else "noindex, follow"

    canonical = f"{SITE}/check/{domain}"
    title = f"Is {domain} Legit or a Scam? Trust Score: {ts}/100 | ScamDekho"
    meta_desc = (
        f"{domain} review: trust score {ts}/100 ({verdict}). "
        f"We checked {summary.get('total_sources_checked', 14)} security sources including phishing "
        f"blacklists, SSL, domain age and malware databases. Free website safety check."
    )

    # ── Source cards ──
    src_html = ""
    for s in sources:
        st = s.get("status", "neutral")
        icon = "✔" if st == "positive" else "✖" if st == "negative" else "—"
        c = "#16a34a" if st == "positive" else "#dc2626" if st == "negative" else "#94a3b8"
        cbg = "#f0fdf4" if st == "positive" else "#fef2f2" if st == "negative" else "#f8fafc"
        src_html += (
            f'<div style="background:{cbg};border:1px solid #e2e8f0;border-radius:10px;padding:12px 14px;">'
            f'<div style="display:flex;justify-content:space-between;gap:8px;">'
            f'<strong style="font-size:13px;color:#334155;">{esc(s.get("name"))}</strong>'
            f'<span style="color:{c};font-weight:800;">{icon}</span></div>'
            f'<div style="font-size:12px;color:#475569;margin-top:4px;">{esc(s.get("message"))}</div>'
            f'{f"<div style=\'font-size:11px;color:#94a3b8;margin-top:3px;\'>{esc(s.get(\'detail\'))}</div>" if s.get("detail") else ""}'
            f"</div>"
        )

    # ── Explanation / analysis text ──
    expl_html = "".join(
        f'<li style="margin-bottom:8px;line-height:1.7;">{esc(e)}</li>' for e in explanation[:10]
    )

    # ── Info grid ──
    def info_cell(label, value):
        return (
            f'<div style="background:#f8fafc;border:1px solid #eef2f7;border-radius:8px;padding:10px 13px;">'
            f'<div style="font-size:10px;font-weight:700;color:#94a3b8;text-transform:uppercase;">{label}</div>'
            f'<div style="font-size:13px;font-weight:600;color:#334155;margin-top:3px;">{esc(value or "Unknown")}</div></div>'
        )

    info_html = (
        info_cell("Domain Created", other.get("domain_created"))
        + info_cell("SSL Issuer", other.get("ssl_issuer"))
        + info_cell("Server Location", other.get("server_location"))
        + info_cell("Trust Score", f"{ts}/100 — {verdict}")
    )

    # ── Related domains ──
    related_html = ""
    for rel in related:
        if rel.get("domain") == doc["domain"]:
            continue
        rd = esc(rel.get("domain"))
        rts = int((rel.get("result") or {}).get("trust_score", 50))
        rc, _, _ = verdict_color(rts)
        related_html += (
            f'<a href="/check/{rd}" style="display:flex;justify-content:space-between;padding:10px 14px;'
            f'background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;text-decoration:none;margin-bottom:8px;">'
            f'<span style="color:#334155;font-weight:600;font-size:14px;">{rd}</span>'
            f'<span style="color:{rc};font-weight:800;font-size:14px;">{rts}/100</span></a>'
        )

    # ── Verdict-based answer text (unique per page) ──
    if ts >= 70:
        answer = (
            f"Based on our automated analysis, {domain} appears to be legitimate with a trust score of {ts}/100. "
            f"It passed {summary.get('positive_signals', 0)} of our security checks including phishing blacklists, "
            f"SSL verification and domain history. As always, stay cautious when sharing personal or payment details online."
        )
    elif ts >= 50:
        answer = (
            f"Our analysis of {domain} returned a trust score of {ts}/100, which means it shows some warning signs. "
            f"{summary.get('negative_signals', 0)} security checks raised concerns. We recommend verifying this website "
            f"through official sources before entering any personal or payment information."
        )
    else:
        answer = (
            f"Warning: {domain} scored only {ts}/100 in our security analysis, with {summary.get('negative_signals', 0)} "
            f"checks raising red flags. This website shows characteristics commonly associated with scam or unsafe sites. "
            f"We strongly recommend not entering any personal, login, or payment details on this website."
        )

    # ── Schema ──
    schema = f"""
<script type="application/ld+json">
{{"@context":"https://schema.org","@type":"WebPage","name":"Is {domain} Legit or a Scam?","url":"{canonical}","dateModified":"{last_iso}","description":"{esc(meta_desc)}","isPartOf":{{"@type":"WebSite","name":"ScamDekho","url":"{SITE}"}}}}
</script>
<script type="application/ld+json">
{{"@context":"https://schema.org","@type":"BreadcrumbList","itemListElement":[
{{"@type":"ListItem","position":1,"name":"Home","item":"{SITE}/"}},
{{"@type":"ListItem","position":2,"name":"Website Checker","item":"{SITE}/url-checker"}},
{{"@type":"ListItem","position":3,"name":"{domain}","item":"{canonical}"}}]}}
</script>
<script type="application/ld+json">
{{"@context":"https://schema.org","@type":"FAQPage","mainEntity":[
{{"@type":"Question","name":"Is {domain} legit or a scam?","acceptedAnswer":{{"@type":"Answer","text":"{esc(answer)}"}}}},
{{"@type":"Question","name":"What is the trust score of {domain}?","acceptedAnswer":{{"@type":"Answer","text":"{domain} has a trust score of {ts} out of 100 based on {summary.get('total_sources_checked', 14)} automated security checks including phishing databases, SSL analysis, domain age and malware scanning. Last checked: {last_str}."}}}}]}}
</script>"""

    ring_pct = ts * 3.39  # 2*pi*54 ≈ 339

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(title)}</title>
<meta name="description" content="{esc(meta_desc)}">
<link rel="canonical" href="{canonical}">
<meta name="robots" content="{robots}">
<meta property="og:title" content="{esc(title)}">
<meta property="og:description" content="{esc(meta_desc)}">
<meta property="og:url" content="{canonical}">
<meta property="og:type" content="website">
<link rel="icon" href="{SITE}/favicon/favicon.ico">
{schema}
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f8fafc;color:#0f172a;line-height:1.6}}
.wrap{{max-width:760px;margin:0 auto;padding:24px 16px 60px}}
.topbar{{background:#0f172a;padding:14px 16px}}
.topbar a{{color:#fff;text-decoration:none;font-weight:800;font-size:18px}}
.topbar a span{{color:#0ea5e9}}
.card{{background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:24px;margin-bottom:18px}}
h1{{font-size:clamp(20px,4vw,28px);margin-bottom:6px}}
h2{{font-size:18px;margin:0 0 14px;color:#0f172a}}
.cta{{display:block;text-align:center;background:linear-gradient(135deg,#0ea5e9,#0284c7);color:#fff;padding:14px;border-radius:10px;text-decoration:none;font-weight:700;margin-top:16px}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:10px}}
.grid-src{{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px}}
@media(max-width:600px){{.grid2{{grid-template-columns:1fr}}}}
.muted{{color:#64748b;font-size:13px}}
</style>
</head>
<body>
<div class="topbar"><a href="{SITE}/">Scam<span>Dekho</span></a></div>
<div class="wrap">

<div class="card" style="text-align:center;background:{bg};">
  <p class="muted" style="margin-bottom:8px;">Website Safety Report · Last checked: {last_str} · Checked {scan_count} time{"s" if scan_count != 1 else ""}</p>
  <h1>Is <span style="color:#0284c7;">{domain}</span> Legit or a Scam?</h1>
  <div style="width:130px;height:130px;position:relative;margin:18px auto;">
    <svg viewBox="0 0 120 120" style="transform:rotate(-90deg);width:130px;height:130px;">
      <circle cx="60" cy="60" r="54" fill="none" stroke="#e5e7eb" stroke-width="10"/>
      <circle cx="60" cy="60" r="54" fill="none" stroke="{color}" stroke-width="10" stroke-linecap="round"
        stroke-dasharray="339" stroke-dashoffset="{339 - ring_pct:.0f}"/>
    </svg>
    <div style="position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:30px;font-weight:800;">{ts}<small style="font-size:13px;color:#64748b;">/100</small></div>
  </div>
  <div style="font-size:22px;font-weight:800;color:{color};">{verdict}</div>
  <p style="font-size:14px;color:#334155;max-width:560px;margin:10px auto 0;">{esc(answer)}</p>
</div>

<div class="card">
  <h2>Domain Information</h2>
  <div class="grid2">{info_html}</div>
</div>

<div class="card">
  <h2>Security Scan Results ({summary.get('total_sources_checked', len(sources))} Sources Checked)</h2>
  <p class="muted" style="margin-bottom:12px;">{summary.get('positive_signals',0)} passed · {summary.get('negative_signals',0)} flagged risk · {summary.get('neutral_signals',0)} neutral</p>
  <div class="grid-src">{src_html}</div>
</div>

<div class="card">
  <h2>Why {domain} Got This Score</h2>
  <ul style="padding-left:20px;font-size:14px;color:#334155;">{expl_html}</ul>
  <a class="cta" href="{SITE}/url-checker">Check Another Website Free →</a>
</div>

<div class="card">
  <h2>Recently Checked Websites</h2>
  {related_html if related_html else '<p class="muted">No related checks yet.</p>'}
</div>

<div class="card">
  <p class="muted" style="line-height:1.7;">
    <strong>Disclaimer:</strong> This is an automated AI-generated risk assessment based on publicly available
    security data at the time of scanning. It may not be 100% accurate and should not be treated as a definitive
    judgment of any business. Scores can change as new data becomes available.
    Website owner? <a href="mailto:support@scamdekho.in?subject=Dispute report for {domain}" style="color:#0284c7;">Dispute this result</a>
    and we will re-review your website.
  </p>
</div>

</div>
</body>
</html>"""


# ──────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────

@router.get("/check/{domain}", response_class=HTMLResponse)
async def public_check_page(domain: str):
    d = normalize_domain(domain)
    if not d:
        return HTMLResponse(
            "<h1>Invalid domain</h1><p><a href='https://scamdekho.in/url-checker'>Check a website →</a></p>",
            status_code=404,
        )

    doc = await get_public_page(d)
    if not doc:
        # Page abhi exist nahi karta — user ko tool par bhejo (scan karne par ban jayega)
        return HTMLResponse(
            f"""<!DOCTYPE html><html><head><title>Check {esc(d)} — ScamDekho</title>
            <meta name="robots" content="noindex"></head>
            <body style="font-family:sans-serif;text-align:center;padding:60px 20px;">
            <h1>We haven't analyzed {esc(d)} yet</h1>
            <p>Run a free instant scan to get its trust score.</p>
            <a href="https://scamdekho.in/url-checker" style="display:inline-block;background:#0ea5e9;color:#fff;
            padding:12px 28px;border-radius:8px;text-decoration:none;font-weight:700;margin-top:14px;">
            Scan {esc(d)} Now →</a></body></html>""",
            status_code=404,
        )

    related = await get_recent_pages(limit=7)
    page = build_page_html(doc, related)
    return HTMLResponse(page, headers={"Cache-Control": "public, max-age=3600"})


@router.get("/sitemap-checks.xml")
async def sitemap_checks():
    docs = await get_indexable_domains_for_sitemap(limit=5000)
    items = ""
    for doc in docs:
        lastmod = ""
        ls = doc.get("last_scanned")
        if isinstance(ls, datetime):
            lastmod = f"<lastmod>{ls.strftime('%Y-%m-%d')}</lastmod>"
        items += f"<url><loc>{SITE}/check/{esc(doc['domain'])}</loc>{lastmod}<changefreq>weekly</changefreq><priority>0.6</priority></url>"
    xml = f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{items}</urlset>'
    return Response(content=xml, media_type="application/xml")


@router.get("/api/v1/recent-checks")
async def recent_checks():
    """url-checker page ke 'Recently Checked' widget ke liye."""
    docs = await get_recent_pages(limit=10)
    return JSONResponse({
        "checks": [
            {
                "domain": doc.get("domain"),
                "trust_score": (doc.get("result") or {}).get("trust_score", 50),
                "url": f"{SITE}/check/{doc.get('domain')}",
            }
            for doc in docs
        ]
    })

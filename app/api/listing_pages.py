"""
listing_pages.py  —  ScamDekho
===============================
ScamAdviser-style HTML "sitemap" hub + listing pages.
Ye saare /check/{domain} pages ko link karte hain → Googlebot ko crawl path milta
hai → orphan problem khatam → auto-index.

Pages:
  /sitemap                  -> hub (4 categories ko link karta hai)
  /sitemap/daily/new        -> last 24h me add hue domains   (1000/page, paginated)
  /sitemap/daily/top        -> last 24h ke most-checked domains
  /sitemap/weekly/new       -> last 7 days me add hue domains
  /sitemap/weekly/top       -> last 7 days ke most-checked domains
  /sitemap/daily/new/2 ...  -> pagination (page 2,3,...)

Sirf indexable=True domains dikhte hain (famous/junk filter automatically apply).

SETUP (app/main.py me 2 lines):
  from app.api.listing_pages import router as listing_router
  app.include_router(listing_router)

Footer me link add karo:  <a href="/sitemap">Sitemap</a>

File location: app/api/listing_pages.py
"""

from datetime import datetime, timedelta
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from app.services.public_pages_service import pages_collection
from app.api.public_pages import _navbar_html, _footer_html, _nav_js, esc, SITE, verdict_color

router = APIRouter()

PER_PAGE = 1000

# GA + AdSense — har listing page ke <head> me
HEAD_SCRIPTS = """
<script async src="https://www.googletagmanager.com/gtag/js?id=G-Q4BNB3E2K4"></script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){dataLayer.push(arguments);}gtag('js',new Date());gtag('config','G-Q4BNB3E2K4');</script>
<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-3772619201860644" crossorigin="anonymous"></script>
"""

# section meta: (browser title, h1, intro paragraph)
SECTIONS = {
    ("daily", "new"): (
        "Daily New Websites Checked",
        "Daily New Websites — Checked in the Last 24 Hours",
        "These are the newest websites added to ScamDekho in the last 24 hours. Each one has been "
        "automatically analysed across 14+ trust and safety signals — domain age, SSL, blacklists, "
        "server reputation and more. Click any website to see its full scam-check report and trust score.",
    ),
    ("daily", "top"): (
        "Daily Top Websites",
        "Daily Top Websites — Most Checked in the Last 24 Hours",
        "The most-checked websites on ScamDekho over the last 24 hours. These domains are getting the "
        "most attention from users verifying whether they are legit or a scam. Tap a website to read its "
        "detailed safety analysis and community trust score.",
    ),
    ("weekly", "new"): (
        "Weekly New Websites Checked",
        "Weekly New Websites — Added in the Last 7 Days",
        "All the new websites ScamDekho has analysed over the past 7 days. From suspicious online stores "
        "to crypto and investment platforms, each domain is scored for scam risk using live data. Open any "
        "entry to see the full report.",
    ),
    ("weekly", "top"): (
        "Weekly Top Websites",
        "Weekly Top Websites — Most Checked in the Last 7 Days",
        "The most popular websites checked on ScamDekho during the last 7 days. These are the domains "
        "people are most actively investigating for legitimacy and safety. Select any website for its "
        "complete trust analysis.",
    ),
}


# ──────────────────────────────────────────────
# DB helpers
# ──────────────────────────────────────────────
def _query(period: str, kind: str):
    """Return (filter, sort_field, sort_dir)."""
    days = 1 if period == "daily" else 7
    cutoff = datetime.utcnow() - timedelta(days=days)
    if kind == "new":
        return ({"indexable": True, "first_scanned": {"$gte": cutoff}}, "first_scanned", -1)
    # top = most checked in window
    return ({"indexable": True, "last_scanned": {"$gte": cutoff}}, "scan_count", -1)


async def _count(filt: dict) -> int:
    try:
        return await pages_collection.count_documents(filt)
    except Exception:
        return 0


async def _fetch(filt: dict, sort_field: str, skip: int, limit: int) -> list:
    try:
        cursor = pages_collection.find(
            filt, {"domain": 1, "result.trust_score": 1, "last_scanned": 1, "scan_count": 1}
        ).sort(sort_field, -1).skip(skip).limit(limit)
        return [d async for d in cursor]
    except Exception:
        return []


# ──────────────────────────────────────────────
# HTML builders
# ──────────────────────────────────────────────
def _links_html(items: list) -> str:
    out = ""
    for d in items:
        dom = esc(d.get("domain"))
        ts = int((d.get("result") or {}).get("trust_score", 50))
        c, _, _ = verdict_color(ts)
        out += (
            f'<a class="chk-link" href="{SITE}/check/{dom}">'
            f'<span class="chk-dom">{dom}</span>'
            f'<span class="chk-score" style="color:{c};">{ts}</span></a>'
        )
    return out or '<p class="muted">No websites in this period yet — check back soon.</p>'


def _pagination(base: str, page: int, total_pages: int) -> str:
    if total_pages <= 1:
        return ""
    out = '<nav class="pager" aria-label="Pagination">'
    if page > 1:
        prev = base if page == 2 else f"{base}/{page-1}"
        out += f'<a rel="prev" href="{prev}">‹ Prev</a>'
    start, end = max(1, page - 2), min(total_pages, page + 2)
    for p in range(start, end + 1):
        href = base if p == 1 else f"{base}/{p}"
        cls = "active" if p == page else ""
        out += f'<a class="{cls}" href="{href}">{p}</a>'
    if page < total_pages:
        out += f'<a rel="next" href="{base}/{page+1}">Next ›</a>'
    out += "</nav>"
    return out


def _shell(title: str, description: str, canonical: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(title)}</title>
<meta name="description" content="{esc(description)}">
<link rel="canonical" href="{canonical}">
<meta name="robots" content="index, follow">
<meta property="og:title" content="{esc(title)}">
<meta property="og:description" content="{esc(description)}">
<meta property="og:url" content="{canonical}">
<meta name="theme-color" content="#0ea5e9">
<link rel="icon" type="image/x-icon" href="{SITE}/favicon/favicon.ico">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet"/>
<link rel="stylesheet" href="{SITE}/style.css">
<link rel="stylesheet" href="{SITE}/mobile.css">
{HEAD_SCRIPTS}
<style>
.navbar{{background:rgba(255,255,255,0.95)!important;backdrop-filter:blur(12px);box-shadow:0 2px 12px rgba(0,0,0,0.06)!important;position:fixed!important;top:0;width:100%;z-index:1000!important;display:flex;align-items:center;justify-content:space-between;padding:0 60px;height:80px;}}
.navbar .site-logo{{height:170px;width:auto;object-fit:contain;}}
.navbar .nav-links{{display:flex;align-items:center;gap:35px;margin-left:auto;}}
.navbar .nav-links a{{color:#333!important;text-decoration:none;font-size:14px;font-weight:700;}}
.navbar .nav-links a:hover{{color:#0B5ED7!important;}}
.nav-dropdown{{position:relative;}}
.nav-dropdown-btn{{display:flex;align-items:center;gap:5px;color:#333!important;background:none;border:none;font-size:14px;font-weight:700;padding:0;cursor:pointer;font-family:inherit;}}
.nav-dropdown-btn i{{font-size:11px;transition:transform .2s;}}
.nav-dropdown.open .nav-dropdown-btn i{{transform:rotate(180deg);}}
.nav-dropdown-menu{{display:none;position:absolute;top:calc(100% + 8px);left:0;background:#fff;border:1px solid #e2e8f0;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.12);min-width:240px;padding:8px;z-index:200;}}
.nav-dropdown.open .nav-dropdown-menu{{display:block;}}
.nav-dropdown-menu a{{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;color:#334155!important;text-decoration:none;font-size:13px;font-weight:500;}}
.nav-dropdown-menu a:hover{{background:#f0f9ff;color:#0284c7!important;}}
.nav-dropdown-menu a i{{color:#0ea5e9;width:16px;text-align:center;}}
.nav-dropdown-divider{{height:1px;background:#f1f5f9;margin:4px 0;}}
.menu-toggle{{display:none;background:none;border:none;cursor:pointer;margin-left:auto;}}
.menu-toggle span{{display:block;width:24px;height:2.5px;margin:5px 0;background:#0a2a52;border-radius:3px;}}
.footer{{background:#0f172a;color:#94a3b8;padding:60px 6% 0;margin-top:40px;}}
.footer-container{{display:grid;grid-template-columns:1.4fr 1fr 1fr;gap:40px;max-width:1100px;margin:0 auto;padding-bottom:40px;}}
.footer-brand h3{{color:#fff;font-size:22px;font-weight:800;margin-bottom:12px;}}
.footer-brand p{{font-size:13px;line-height:1.8;margin-bottom:8px;}}
.footer-brand .support-email a{{color:#0ea5e9;text-decoration:none;}}
.footer-links h4,.footer-services h4{{color:#fff;font-size:14px;font-weight:700;margin-bottom:14px;}}
.footer-links a,.footer-services a{{display:block;color:#94a3b8;text-decoration:none;font-size:13px;margin-bottom:8px;}}
.footer-links a:hover,.footer-services a:hover{{color:#0ea5e9;}}
.footer-bottom{{border-top:1px solid rgba(255,255,255,0.08);padding:20px 0;text-align:center;font-size:12px;color:#64748b;}}
*{{box-sizing:border-box;}}
body{{font-family:'Segoe UI',system-ui,sans-serif;background:#f1f5f9;color:#0f172a;margin:0;line-height:1.6;}}
.wrap{{max-width:1040px;margin:0 auto;padding:110px 16px 40px;}}
.crumb{{font-size:12px;color:#64748b;margin:0 0 14px;}}
.crumb a{{color:#0284c7;text-decoration:none;}}
.head-card{{background:#fff;border:1px solid #e6ebf1;border-radius:16px;padding:28px;margin-bottom:20px;}}
h1{{font-size:clamp(22px,4vw,30px);margin:0 0 12px;font-weight:800;}}
.intro{{color:#475569;font-size:15px;margin:0 0 8px;}}
.muted{{color:#64748b;font-size:14px;padding:20px;}}
.tabs{{display:flex;gap:10px;flex-wrap:wrap;margin:18px 0 0;}}
.tabs a{{font-size:13px;font-weight:600;color:#334155;text-decoration:none;background:#f1f5f9;border:1px solid #e2e8f0;padding:7px 14px;border-radius:20px;}}
.tabs a:hover{{background:#e0f2fe;color:#0284c7;}}
.tabs a.on{{background:#0ea5e9;color:#fff;border-color:#0ea5e9;}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px;background:#fff;border:1px solid #e6ebf1;border-radius:16px;padding:18px;}}
.chk-link{{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:10px 13px;background:#f8fafc;border:1px solid #e8edf3;border-radius:9px;text-decoration:none;}}
.chk-link:hover{{background:#f0f9ff;border-color:#bae6fd;}}
.chk-dom{{color:#334155;font-weight:600;font-size:13.5px;word-break:break-all;}}
.chk-score{{font-weight:800;font-size:13px;white-space:nowrap;}}
.hub-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px;margin-top:6px;}}
.hub-card{{display:block;background:#fff;border:1px solid #e6ebf1;border-radius:14px;padding:22px;text-decoration:none;transition:.15s;}}
.hub-card:hover{{border-color:#7dd3fc;box-shadow:0 6px 20px rgba(14,165,233,0.12);transform:translateY(-2px);}}
.hub-card i{{font-size:22px;color:#0ea5e9;}}
.hub-card h3{{margin:12px 0 6px;font-size:16px;color:#0f172a;}}
.hub-card p{{margin:0;font-size:13px;color:#64748b;}}
.pager{{display:flex;gap:8px;justify-content:center;flex-wrap:wrap;margin:24px 0 0;}}
.pager a{{font-size:14px;font-weight:600;color:#334155;text-decoration:none;background:#fff;border:1px solid #e2e8f0;padding:8px 14px;border-radius:8px;}}
.pager a:hover{{background:#f0f9ff;color:#0284c7;}}
.pager a.active{{background:#0ea5e9;color:#fff;border-color:#0ea5e9;}}
@media(max-width:768px){{
  .navbar{{height:70px!important;padding:0 12px!important;}}
  .navbar img.site-logo{{height:100px!important;width:160px!important;}}
  .navbar .nav-links{{display:none;position:fixed;top:70px;left:0;width:100%;flex-direction:column;background:#fff;border-radius:0 0 18px 18px;box-shadow:0 20px 40px rgba(0,0,0,0.1);z-index:999;padding:0;gap:0;}}
  .navbar .nav-links.active{{display:flex;}}
  .navbar .nav-links a{{padding:16px!important;font-size:16px!important;border-bottom:1px solid #eef2f7;}}
  .menu-toggle{{display:block!important;}}
  .nav-dropdown{{width:100%;text-align:center;}}
  .nav-dropdown-btn{{width:100%;padding:16px!important;font-size:16px!important;border-bottom:1px solid #eef2f7;justify-content:center;}}
  .nav-dropdown-menu{{position:static;box-shadow:none;border:none;border-radius:0;padding:0 0 0 20px;min-width:unset;}}
  .grid{{grid-template-columns:1fr;}}
  .footer-container{{grid-template-columns:1fr;}}
}}
</style>
</head>
<body>
{_navbar_html()}
<main class="wrap">
{body}
</main>
{_footer_html()}
{_nav_js()}
</body>
</html>"""


def _tabs(active_period: str, active_kind: str) -> str:
    items = [
        ("daily", "new", "Daily New"),
        ("daily", "top", "Daily Top"),
        ("weekly", "new", "Weekly New"),
        ("weekly", "top", "Weekly Top"),
    ]
    out = '<div class="tabs">'
    for p, k, label in items:
        on = "on" if (p == active_period and k == active_kind) else ""
        out += f'<a class="{on}" href="{SITE}/sitemap/{p}/{k}">{label}</a>'
    out += f'<a href="{SITE}/url-checker">Check a Website →</a></div>'
    return out


# ──────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────
@router.get("/sitemap", response_class=HTMLResponse)
async def sitemap_hub():
    cards = [
        ("daily", "new", "fa-clock", "Daily New Domains", "Websites added in the last 24 hours"),
        ("daily", "top", "fa-fire", "Daily Top Domains", "Most-checked websites today"),
        ("weekly", "new", "fa-calendar-plus", "Weekly New Domains", "New websites from the last 7 days"),
        ("weekly", "top", "fa-arrow-trend-up", "Weekly Top Domains", "Most-checked websites this week"),
    ]
    grid = '<div class="hub-grid">'
    for p, k, icon, h, d in cards:
        grid += (
            f'<a class="hub-card" href="{SITE}/sitemap/{p}/{k}">'
            f'<i class="fa-solid {icon}"></i><h3>{h}</h3><p>{d}</p></a>'
        )
    grid += "</div>"
    body = f"""
  <nav class="crumb"><a href="{SITE}/">Home</a> › <span>Sitemap</span></nav>
  <div class="head-card">
    <h1>ScamDekho Sitemap — Browse Checked Websites</h1>
    <p class="intro">Explore every website verified on ScamDekho for scams, phishing and online safety.
    Browse the newest and most-checked domains by day and week. Each website has a full report with a
    live trust score based on 14+ data sources.</p>
    {grid}
  </div>"""
    return HTMLResponse(
        _shell("ScamDekho Sitemap — Browse Checked Websites",
               "Browse every website checked on ScamDekho for scams and safety. Daily and weekly new and top domains with full trust reports.",
               f"{SITE}/sitemap", body),
        headers={"Cache-Control": "public, max-age=1800"},
    )


@router.get("/sitemap/{period}/{kind}", response_class=HTMLResponse)
async def sitemap_list(period: str, kind: str):
    return await _listing(period, kind, 1)


@router.get("/sitemap/{period}/{kind}/{page}", response_class=HTMLResponse)
async def sitemap_list_paged(period: str, kind: str, page: int):
    return await _listing(period, kind, page)


async def _listing(period: str, kind: str, page: int):
    period = (period or "").lower()
    kind = (kind or "").lower()
    if (period, kind) not in SECTIONS:
        return HTMLResponse(
            _shell("Not Found | ScamDekho", "Page not found.", f"{SITE}/sitemap",
                   f'<div class="head-card"><h1>Page Not Found</h1>'
                   f'<p class="intro">Try the <a href="{SITE}/sitemap">sitemap hub</a>.</p></div>'),
            status_code=404,
        )

    try:
        page = max(1, int(page))
    except Exception:
        page = 1

    title, h1, intro = SECTIONS[(period, kind)]
    filt, sort_field, _ = _query(period, kind)
    total = await _count(filt)
    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    page = min(page, total_pages)
    items = await _fetch(filt, sort_field, (page - 1) * PER_PAGE, PER_PAGE)

    base = f"{SITE}/sitemap/{period}/{kind}"
    canonical = base if page == 1 else f"{base}/{page}"
    page_title = title if page == 1 else f"{title} — Page {page}"

    body = f"""
  <nav class="crumb"><a href="{SITE}/">Home</a> › <a href="{SITE}/sitemap">Sitemap</a> › <span>{esc(title)}</span></nav>
  <div class="head-card">
    <h1>{esc(h1)}</h1>
    <p class="intro">{esc(intro)}</p>
    <p class="muted" style="padding:0;">{total:,} websites · Page {page} of {total_pages}</p>
    {_tabs(period, kind)}
  </div>
  <div class="grid">{_links_html(items)}</div>
  {_pagination(base, page, total_pages)}"""

    return HTMLResponse(
        _shell(f"{page_title} | ScamDekho",
               f"{intro} Browse {total:,} checked websites on ScamDekho.",
               canonical, body),
        headers={"Cache-Control": "public, max-age=1800"},
    )

"""
Public Check Pages Router — ScamDekho  (FINAL — fully replace this file)
========================================================================
/check/{domain}            -> SSR safety report page (unique content per domain)
/sitemap-index.xml         -> master sitemap
/sitemap-checks-{n}.xml    -> paginated sitemaps (5000 each)
/api/v1/recent-checks      -> recent checks widget API

Features:
  - ScamDekho header + footer (site jaisa)
  - Unique 400-500 word content via GPT (cached forever) + template fallback
  - Auto unique meta (title/description/keywords/OG/twitter)
  - Professional design + proper H1/H2/H3 (SEO)
  - AdSense-SAFE ad slots (clearly labelled, well spaced, away from buttons)

File location: app/api/public_pages.py
"""

import html as html_lib
from datetime import datetime
from fastapi import APIRouter
from fastapi.responses import HTMLResponse, Response, JSONResponse

from app.services.public_pages_service import (
    get_domain_category,
    get_public_page,
    get_recent_pages,
    normalize_domain,
    pages_collection,
    should_index_public_domain,
)
from app.services.seo_content_engine import ensure_seo_content

router = APIRouter()

SITE = "https://scamdekho.in"
# The scan API is on its own host — scamdekho.in does not proxy /api/v1.
API_BASE = "https://api.scamdekho.in"
SITEMAP_PAGE_SIZE = 5000


def esc(s) -> str:
    return html_lib.escape(str(s or ""))


def verdict_color(ts: int) -> tuple:
    if ts >= 70:
        return ("#16a34a", "#f0fdf4", "looks safe")
    if ts >= 50:
        return ("#d97706", "#fffbeb", "looks suspicious")
    return ("#dc2626", "#fef2f2", "is high risk")


def is_adult_category_label(category_label) -> bool:
    label = str(category_label or "").strip().lower()
    return any(term in label for term in ("adult", "18+", "nsfw"))


# ══════════════════════════════════════════════════════════════════
# UNIQUE CONTENT (template fallback — jab GPT na chale)
# ══════════════════════════════════════════════════════════════════

def _highlights_from_sources(sources: list):
    positives, negatives = [], []
    for s in sources:
        st = s.get("status")
        msg = (s.get("message") or "").strip()
        if not msg:
            continue
        if st == "positive":
            positives.append(msg)
        elif st == "negative":
            negatives.append(msg)
    return positives, negatives


def _analysis_sections(doc: dict, ts: int, domain: str, summary_line: str):
    """Headings ke saath sections (ScamAdviser jaisa). Har section data se unique."""
    r = doc.get("result", {})
    other = r.get("other_info") or {}
    sources = {s.get("name"): s for s in (r.get("sources") or [])}
    summary = r.get("summary") or {}
    sections = []

    # 1. Trust Score Overview
    if ts >= 70:
        lead = (f"{domain} has a trust score of {ts}/100, which suggests it is generally considered safe. "
                f"It passed {summary.get('positive_signals', 0)} of our security checks. A high score means the "
                f"site is unlikely to be involved in scams, but you should still review the details below.")
    elif ts >= 50:
        lead = (f"{domain} has a trust score of {ts}/100, which places it in the 'mixed signals' range. "
                f"{summary.get('negative_signals', 0)} checks raised concerns. It is not clearly a scam, but you "
                f"should verify it before trusting it with sensitive information.")
    else:
        lead = (f"{domain} has a low trust score of {ts}/100, with {summary.get('negative_signals', 0)} checks "
                f"raising red flags. This places it in the high-risk range and the site shows characteristics "
                f"commonly linked to scams. Avoid sharing personal or payment data.")
    sections.append(("Trust Score Overview", lead))

    # 2. Domain Age & History
    da = sources.get("Domain Age", {})
    created = other.get("domain_created")
    if created and created not in ("Unknown", "", None):
        sections.append(("Domain Age & History",
            f"The domain was created on {created}. {da.get('detail') or ''} An established domain usually reflects "
            f"a long-standing online presence, which can add to credibility. Older domains are generally more "
            f"trustworthy, though scammers sometimes buy aged domains, so age alone is not a guarantee."))
    else:
        sections.append(("Domain Age & History",
            f"We could not reliably determine the registration date of {domain}. When the domain age is hidden or "
            f"unavailable, extra caution is recommended before sharing any personal or payment information."))

    # 3. SSL & Connection Security
    ssl = sources.get("SSL Certificate", {})
    http = sources.get("HTTP Analysis", {})
    if ssl.get("status") == "positive":
        sections.append(("SSL & Connection Security",
            f"A valid SSL certificate was found for {domain} (issuer: {other.get('ssl_issuer', 'a trusted CA')}). "
            f"SSL encrypts the data exchanged between you and the website. Note that scammers can also install free "
            f"SSL, so a padlock alone does not prove safety — but its absence is a clear warning sign."))
    else:
        extra = f" There are also issues reported with HTTP: {http.get('message','')}." if http.get("status") == "negative" else ""
        sections.append(("SSL & Connection Security",
            f"The website does not currently have a valid SSL certificate. SSL is important for encrypting data "
            f"exchanged between you and the site.{extra} Avoid submitting personal or financial details on {domain} "
            f"unless you can confirm the connection is secure."))

    # 4. Reputation & Blacklist Check
    bad = [n for n in ["Google Safe Browsing", "VirusTotal", "PhishTank", "OpenPhish", "URLhaus", "PhishDestroy", "AbuseIPDB"]
           if sources.get(n, {}).get("status") == "negative"]
    if bad:
        sections.append(("Reputation & Blacklist Check",
            f"{domain} was flagged by: {', '.join(bad)}. Being listed on phishing or malware databases is a serious "
            f"red flag and usually means the website should be avoided entirely."))
    else:
        vt = sources.get("VirusTotal", {})
        vt_note = f" {vt.get('message','')}." if vt.get("message") else ""
        sections.append(("Reputation & Blacklist Check",
            f"{domain} has not been blacklisted. It passed major safety databases including Google Safe Browsing, "
            f"OpenPhish, URLhaus and PhishTank, all returning clean results.{vt_note} These positive signals suggest "
            f"the site is unlikely to host malware or phishing threats."))

    # 5. Hosting & Technical Signals
    loc = other.get("server_location")
    ip_src = sources.get("IP & Hosting", {})
    if loc and loc not in ("Unknown", "", None):
        sections.append(("Hosting & Technical Signals",
            f"{domain} is hosted on a server located in {loc}. {ip_src.get('detail') or ''} Hosting location is not "
            f"proof of fraud on its own, but combined with the other signals it helps build the overall risk picture."))

    # 6. Conclusion
    sections.append((f"Conclusion: Is {domain} Safe?", summary_line))
    return sections


def _summary_line(domain: str, ts: int) -> str:
    if ts >= 70:
        return (f"In summary, {domain} appears to be legitimate and reliable based on our automated checks "
                f"(trust score {ts}/100). As always, stay cautious with personal and payment data.")
    if ts >= 50:
        return (f"In summary, {domain} shows some mixed signals (trust score {ts}/100). It is not clearly a scam, "
                f"but verify it through official sources before trusting it fully.")
    return (f"In summary, {domain} shows several characteristics commonly associated with risky or scam websites "
            f"(trust score {ts}/100). We strongly recommend not entering personal, login, or payment details.")


def _faq_items(domain, ts, verdict, verdict_phrase, total_sources, answer, summary_line, last_str):
    return [
        (f"Is {domain} legit or a scam?", answer),
        (f"Is {domain} safe?",
         f"{domain} has a trust score of {ts}/100 ({verdict_phrase}) based on {total_sources} automated "
         f"security checks. {summary_line}"),
        (f"Is {domain} a real or fake website?",
         f"Our automated analysis rates {domain} at {ts}/100 ({verdict}). Review the source-by-source "
         f"breakdown above before trusting it with personal or payment details."),
        (f"What is the trust score of {domain}?",
         f"{domain} has a trust score of {ts} out of 100 based on {total_sources} automated checks including "
         f"phishing databases, SSL, domain age and malware scanning. Last checked {last_str}."),
    ]


# ══════════════════════════════════════════════════════════════════
# CHROME + ADS
# ══════════════════════════════════════════════════════════════════

NAV_CSS = """.sdnav2-wrap{ position:fixed; top:16px; left:0; right:0; z-index:2000; padding:0 20px; font-family:Manrope,'Segoe UI',system-ui,sans-serif; }.sdnav2{ max-width:1280px; margin:0 auto; display:flex; align-items:center; gap:20px; height:106px; padding:0 12px 0 22px; background:#FFFFFF; border:1px solid #E9EDF3; border-radius:18px; box-shadow:0 10px 34px rgba(16,20,30,0.09); box-sizing:border-box; }.sdnav2-logo{ display:flex; align-items:center; height:100%; flex-shrink:0; }.sdnav2-logo img{ height:auto; width:auto; max-width:200px; max-height:58px; object-fit:contain; display:block; }.sdnav2-search{ display:flex; align-items:center; gap:10px; flex:1 1 0; min-width:150px; max-width:300px; height:44px; padding:0 5px 0 16px; background:#F3F6FA; border:1px solid #E9EDF3; border-radius:999px; margin:0; }.sdnav2-search input{ flex:1 1 0; min-width:0; background:transparent; border:none; outline:none; font-family:inherit; font-size:13px; color:#14171F; padding:0; }.sdnav2-search button{ width:34px; height:34px; border-radius:50%; background:#0B63C5; border:none; cursor:pointer; display:flex; align-items:center; justify-content:center; flex-shrink:0; padding:0; }.sdnav2-links{ display:flex; align-items:center; gap:22px; margin-left:auto; }.sdnav2-links > a{ color:#4B5563; text-decoration:none; font-size:13.5px; font-weight:600; white-space:nowrap; transition:color .15s; }.sdnav2-links > a:hover{ color:#0B63C5; }.sdnav2-dropdown{ position:relative; }.sdnav2-dropdown-btn{ display:flex; align-items:center; gap:6px; background:none; border:none; cursor:pointer; font-family:inherit; color:#4B5563; font-size:13.5px; font-weight:600; padding:0; white-space:nowrap; }.sdnav2-dropdown-btn:hover{ color:#0B63C5; }.sdnav2-dropdown-btn svg{ transition:transform .2s; }.sdnav2-dropdown.open .sdnav2-dropdown-btn svg{ transform:rotate(180deg); }.sdnav2-dropdown-menu{ display:none; position:absolute; top:calc(100% + 16px); left:50%; transform:translateX(-50%); background:#FFFFFF; border:1px solid #E5E9F0; border-radius:14px; box-shadow:0 2px 10px rgba(16,20,30,0.06), 0 12px 32px rgba(16,20,30,0.08); min-width:260px; padding:8px; z-index:200; }.sdnav2-dropdown.open .sdnav2-dropdown-menu{ display:block; }.sdnav2-dropdown-menu a{ display:flex; align-items:center; gap:10px; padding:10px 12px; border-radius:9px; color:#14171F; text-decoration:none; font-size:13px; font-weight:600; }.sdnav2-dropdown-menu a:hover{ background:#F3F6FA; color:#0B63C5; }.sdnav2-dropdown-divider{ height:1px; background:#F1F4F9; margin:6px 0; }.sdnav2-cta{ flex-shrink:0; background:#F5811F; color:#FFFFFF !important; text-decoration:none; font-size:13.5px; font-weight:700; padding:12px 22px; border-radius:999px; white-space:nowrap; box-shadow:0 6px 18px rgba(245,129,31,0.28); }.sdnav2-toggle{ display:none; background:none; border:none; cursor:pointer; margin-left:8px; padding:4px; }.sdnav2-toggle span{ display:block; width:22px; height:2.5px; margin:5px 0; background:#14171F; border-radius:3px; }@media (max-width:1079px){ .sdnav2-logo img{ height:auto; max-width:160px; } }@media (max-width:940px){ .sdnav2-search{ display:none; } }@media (max-width: 860px){.sdnav2-wrap{ top:clamp(8px,2.6vw,12px); left:0; right:0; padding:0 clamp(8px,3vw,12px); }.sdnav2{ position:relative; border-radius:16px; height:clamp(60px,17vw,74px); padding:0 clamp(6px,2.4vw,10px) 0 clamp(10px,3.6vw,14px); gap:clamp(6px,2.6vw,12px); }.sdnav2-logo img{ height:auto; max-width:min(160px,34vw); }.sdnav2-search{ display:none; }.sdnav2-links{ display:none; position:absolute; top:calc(100% + 10px); left:0; right:0; width:auto; max-height:calc(100vh - 120px); overflow-y:auto; flex-direction:column; align-items:stretch; gap:0; margin-left:0; background:#FFFFFF; border:1px solid #E9EDF3; border-radius:16px; box-shadow:0 18px 44px rgba(16,20,30,0.16); z-index:999; padding:6px 0; }.sdnav2-links.active{ display:flex; }.sdnav2-links > a{ padding:15px 22px; font-size:15px; border-bottom:1px solid #F1F4F9; }.sdnav2-dropdown{ width:100%; }.sdnav2-dropdown-btn{ width:100%; padding:15px 22px; font-size:15px; border-bottom:1px solid #F1F4F9; justify-content:space-between; }.sdnav2-dropdown-menu{ position:static; transform:none; box-shadow:none; border:none; border-radius:0; padding:0 0 0 22px; min-width:unset; }.sdnav2-dropdown.open .sdnav2-dropdown-menu{ display:flex; flex-direction:column; }.sdnav2-dropdown-menu a{ padding:12px; border-radius:0; border-bottom:1px solid #F8FAFC; }.sdnav2-cta{ padding:clamp(7px,2.2vw,10px) clamp(10px,3.6vw,16px); font-size:clamp(10.5px,3vw,12.5px); margin-left:auto; }.sdnav2-toggle{ display:block; margin-left:clamp(2px,1vw,6px); }}"""


def _navbar_html() -> str:
    """Same navbar the rest of the site uses (see homepage sdnav2)."""
    return f"""
<style>{NAV_CSS}</style>
<div class="sdnav2-wrap" id="sdnav2Wrap"><nav class="sdnav2">
  <a href="{SITE}/" class="sdnav2-logo"><img src="{SITE}/logo-wide.webp" alt="ScamDekho - Check Before You Click"></a>
  <form class="sdnav2-search" id="sdnav2Search" action="{SITE}/url-checker" method="get">
    <svg width="16" height="16" viewBox="0 0 24 24"><circle cx="11" cy="11" r="6.5" fill="none" stroke="#8A93A3" stroke-width="2"></circle><path d="M16 16l4.5 4.5" stroke="#8A93A3" stroke-width="2" stroke-linecap="round"></path></svg>
    <input type="text" name="q" placeholder="Paste a URL to check" aria-label="Paste a URL to check">
    <button type="submit" aria-label="Check for scam"><svg width="15" height="15" viewBox="0 0 24 24"><path d="M12 19V6M6 12l6-6 6 6" fill="none" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"></path></svg></button>
  </form>
  <div class="sdnav2-links" id="sdnav2Links">
    <a href="{SITE}/">Home</a>
    <div class="sdnav2-dropdown" id="sdnav2Services">
      <button type="button" class="sdnav2-dropdown-btn" onclick="sdnav2ToggleServices(event)" aria-expanded="false" aria-controls="sdnav2ServicesMenu">Services
        <svg width="10" height="10" viewBox="0 0 24 24"><path d="M4 8l8 8 8-8" fill="none" stroke="#4B5563" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path></svg></button>
      <div class="sdnav2-dropdown-menu" id="sdnav2ServicesMenu" role="menu">
        <a href="{SITE}/scam-message-checker" role="menuitem">Message Scam Checker</a>
        <a href="{SITE}/url-checker" role="menuitem">Website / URL Checker</a>
        <a href="{SITE}/fake-payment-screenshot-checker" role="menuitem">Screenshot Scam Checker</a>
        <a href="{SITE}/upi-qr-checker" role="menuitem">UPI &amp; QR Code Checker</a>
        <div class="sdnav2-dropdown-divider"></div>
        <a href="{SITE}/fake-offer-letter-checker" role="menuitem">Job Offer Letter Checker</a>
        <a href="{SITE}/paypal-email-checker" role="menuitem">PayPal Email Checker</a>
        <a href="{SITE}/paypal-invoice-checker" role="menuitem">PayPal Invoice Checker</a>
      </div>
    </div>
    <a href="{SITE}/blog/">Blog</a>
    <a href="{SITE}/global/">Global</a>
    <a href="{SITE}/about">About</a>
  </div>
  <a href="{SITE}/#reportModal" class="sdnav2-cta">Report a Scam</a>
  <button class="sdnav2-toggle" id="sdnav2Toggle" aria-label="Toggle Menu" aria-expanded="false"><span></span><span></span><span></span></button>
</nav></div>"""

def _footer_html() -> str:
    return f"""
<footer class="footer">
  <div class="footer-container">
    <div class="footer-brand">
      <h3>ScamDekho</h3>
      <p>India's free scam checker. Verify suspicious links, messages, and websites instantly before you lose money.</p>
      <p class="support-email">Support: <a href="mailto:support@scamdekho.in">support@scamdekho.in</a></p>
    </div>
    <div class="footer-services">
      <h4>Our Tools</h4>
      <a href="{SITE}/paypal-email-checker">PayPal Email Checker</a>
      <a href="{SITE}/paypal-invoice-checker">PayPal Invoice Checker</a>
      <a href="{SITE}/scam-message-checker">Message Scam Checker</a>
      <a href="{SITE}/url-checker">Website / URL Checker</a>
      <a href="{SITE}/fake-payment-screenshot-checker">Screenshot Scam Checker</a>
      <a href="{SITE}/upi-qr-checker">UPI & QR Code Checker</a>
      <a href="{SITE}/fake-offer-letter-checker">Job Offer Letter Checker</a>
    </div>
    <div class="footer-links">
      <h4>Quick Links</h4>
      <a href="{SITE}/">Home</a>
      <a href="{SITE}/privacy-policy">Privacy Policy</a>
      <a href="{SITE}/terms-and-conditions">Terms & Conditions</a>
      <a href="{SITE}/disclaimer">Disclaimer</a>
      <a href="{SITE}/contact">Contact Us</a>
      <a href="{SITE}/about">About</a>
      <a href="{SITE}/url-checker">Check a Website</a>
      <a href="/sitemap">Website Sitemap</a>
    </div>
  </div>
  <div class="footer-bottom">© 2026 ScamDekho. All Rights Reserved.</div>
</footer>"""


def _nav_js() -> str:
    return """
<script>
function sdNormalizeDomain(v){
  var d=(v||"").trim().toLowerCase();
  if(d.indexOf("http://")===0||d.indexOf("https://")===0){
    try{ d=new URL(d).hostname; }catch(e){ d=d.replace(/^https?:\\/\\//,""); }
  }
  d=d.split("/")[0].split("?")[0].split("#")[0].split(":")[0].trim();
  if(d.indexOf("www.")===0) d=d.slice(4);
  if(!d||d.indexOf(".")===-1||d.length>100) return null;
  if(/^\\d{1,3}(\\.\\d{1,3}){3}$/.test(d)) return null;
  if(!/^[a-z0-9.-]+\\.[a-z]{2,}$/.test(d)) return null;
  return d;
}
function sdnav2ToggleServices(e){ e.stopPropagation(); document.getElementById("sdnav2Services").classList.toggle("open"); }
document.addEventListener("click",function(e){
  var dd=document.getElementById("sdnav2Services");
  if(dd&&!dd.contains(e.target)) dd.classList.remove("open");
});
(function(){
  var t=document.getElementById("sdnav2Toggle"), l=document.getElementById("sdnav2Links");
  if(t&&l){ t.addEventListener("click",function(){
    var o=l.classList.toggle("active");
    t.setAttribute("aria-expanded",o);
    document.body.style.overflow=o?"hidden":"";
  }); }
  var f=document.getElementById("sdnav2Search");
  if(f){ f.addEventListener("submit",function(e){
    var input=f.querySelector("input[name=q]");
    var d=sdNormalizeDomain(input?input.value:"");
    if(d){ e.preventDefault(); window.location.href="https://scamdekho.in/check/"+encodeURIComponent(d); }
  }); }
})();
</script>"""

# ══════════════════════════════════════════════════════════════════
# MAIN PAGE BUILDER
# ══════════════════════════════════════════════════════════════════

def build_page_html(doc: dict, related: list, seo_html: str = None) -> str:
    raw_domain = str(doc["domain"])
    domain = esc(raw_domain)
    r = doc.get("result", {})
    ts = int(r.get("trust_score", 50))
    verdict = esc(r.get("verdict", "UNKNOWN"))
    color, bg, verdict_phrase = verdict_color(ts)
    other = r.get("other_info") or {}
    category_label = r.get("category_label") or r.get("category") or get_domain_category(doc.get("domain"))
    summary = r.get("summary") or {}
    sources = r.get("sources") or []
    total_sources = summary.get("total_sources_checked", len(sources)) or 14
    last_scanned = doc.get("last_scanned")
    last_str = last_scanned.strftime("%B %d, %Y") if isinstance(last_scanned, datetime) else "Recently"
    last_iso = last_scanned.strftime("%Y-%m-%d") if isinstance(last_scanned, datetime) else ""
    scan_count = int(doc.get("scan_count", 1))
    # Recompute at render time so a stale stored flag cannot suppress a page
    # while the deployment-time backfill is still running.
    indexable = should_index_public_domain(raw_domain)
    robots = "index, follow" if indexable else "noindex, follow"
    canonical = f"{SITE}/check/{domain}"

    # ── AUTO META ──
    title = f"Is {domain} Legit or a Scam? Trust Score {ts}/100 | ScamDekho"
    meta_desc = (
        f"Is {domain} safe or a scam? {domain} has a trust score of {ts}/100 ({verdict_phrase}). "
        f"We checked {total_sources} sources — SSL, domain age, phishing blacklists & malware. "
        f"Free instant website safety report."
    )
    meta_keywords = (
        f"{domain} review, is {domain} legit, is {domain} safe, {domain} scam or legit, "
        f"{domain} trust score, {domain} reviews, {domain} fake or real"
    )
    og_image = f"{SITE}/og-image.jpg"

    # ── verdict answer (unique) ──
    if ts >= 70:
        answer = (f"Based on our automated analysis, {domain} appears legitimate with a trust score of {ts}/100. "
                  f"It passed {summary.get('positive_signals', 0)} security checks. Stay cautious when sharing payment details online.")
    elif ts >= 50:
        answer = (f"Our analysis of {domain} returned a trust score of {ts}/100 with some warning signs. "
                  f"{summary.get('negative_signals', 0)} checks raised concerns. Verify via official sources first.")
    else:
        answer = (f"Warning: {domain} scored {ts}/100, with {summary.get('negative_signals', 0)} checks raising red flags. "
                  f"This site shows scam-like characteristics. Do not enter personal, login, or payment details.")

    summary_line = _summary_line(domain, ts)

    # ── content (GPT if available, else template with headings) ──
    template_sections = _analysis_sections(doc, ts, domain, summary_line)
    template_html = "".join(f'<h3>{esc(h)}</h3><p>{esc(b)}</p>' for h, b in template_sections)
    analysis_html = seo_html if seo_html else template_html

    # ── highlights ──
    positives, negatives = _highlights_from_sources(sources)
    pos_html = "".join(
        f'<li><i class="fa-solid fa-circle-check"></i>{esc(p)}</li>' for p in positives[:10]
    ) or '<li class="neutral-li">No strong positive signals detected.</li>'
    neg_html = "".join(
        f'<li><i class="fa-solid fa-triangle-exclamation"></i>{esc(n)}</li>' for n in negatives[:10]
    ) or '<li class="neutral-li">No major risk signals detected.</li>'

    # ── facts ──
    def fact(label, value):
        return (f'<div class="fact-cell"><div class="fact-k">{label}</div>'
                f'<div class="fact-v">{esc(value or "Unknown")}</div></div>')
    facts_html = (
        (fact("Category", category_label) if category_label else "")
        + fact("Domain Created", other.get("domain_created"))
        + fact("SSL Issuer", other.get("ssl_issuer"))
        + fact("Server Location", other.get("server_location"))
        + fact("IP Address", other.get("ip_address"))
        + fact("Trust Score", f"{ts}/100")
        + fact("Verdict", verdict)
    )

    # ── source grid ──
    src_html = ""
    for s in sources:
        st = s.get("status", "neutral")
        icon = "✔" if st == "positive" else "✖" if st == "negative" else "—"
        cls = "src-pos" if st == "positive" else "src-neg" if st == "negative" else "src-neu"
        src_html += (
            f'<div class="src-cell {cls}">'
            f'<div class="src-top"><strong>{esc(s.get("name"))}</strong><span class="src-icon">{icon}</span></div>'
            f'<div class="src-msg">{esc(s.get("message"))}</div></div>'
        )

    # ── FAQ (visible + schema) ──
    faqs = _faq_items(domain, ts, verdict, verdict_phrase, total_sources, answer, summary_line, last_str)
    faq_visible = "".join(
        f'<div class="faq-item"><h3>{esc(q)}</h3><p>{esc(a)}</p></div>' for q, a in faqs
    )
    faq_schema_items = ",".join(
        f'{{"@type":"Question","name":"{esc(q)}","acceptedAnswer":{{"@type":"Answer","text":"{esc(a)}"}}}}'
        for q, a in faqs
    )

    # ── related (internal links) ──
    related_html = ""
    for rel in related:
        if rel.get("domain") == doc["domain"]:
            continue
        rd = esc(rel.get("domain"))
        rts = int((rel.get("result") or {}).get("trust_score", 50))
        rc, _, _ = verdict_color(rts)
        related_html += (
            f'<a href="{SITE}/check/{rd}" class="rel-row">'
            f'<span class="rel-domain">{rd}</span>'
            f'<span class="rel-score" style="color:{rc};">{rts}/100</span></a>'
        )

    ring_pct = ts * 3.39

    schema = f"""
<script type="application/ld+json">
{{"@context":"https://schema.org","@type":"WebPage","name":"Is {domain} Legit or a Scam?","url":"{canonical}","dateModified":"{last_iso}","description":"{esc(meta_desc)}","isPartOf":{{"@type":"WebSite","name":"ScamDekho","url":"{SITE}"}},"publisher":{{"@type":"Organization","name":"ScamDekho","url":"{SITE}","logo":{{"@type":"ImageObject","url":"{SITE}/logo.webp"}}}}}}
</script>
<script type="application/ld+json">
{{"@context":"https://schema.org","@type":"BreadcrumbList","itemListElement":[
{{"@type":"ListItem","position":1,"name":"Home","item":"{SITE}/"}},
{{"@type":"ListItem","position":2,"name":"Website Checker","item":"{SITE}/url-checker"}},
{{"@type":"ListItem","position":3,"name":"{domain}","item":"{canonical}"}}]}}
</script>
<script type="application/ld+json">
{{"@context":"https://schema.org","@type":"FAQPage","mainEntity":[{faq_schema_items}]}}
</script>"""

    show_age_gate = is_adult_category_label(category_label)
    body_class = ' class="adult-gated age-gate-active"' if show_age_gate else ""
    content_open = '<div class="age-gated-content">' if show_age_gate else ""
    content_close = "</div>" if show_age_gate else ""
    age_gate_head_script = ""
    age_gate_css = ""
    age_gate_html = ""
    age_gate_script = ""

    if show_age_gate:
        age_gate_key = f"scamdekho_age_confirmed:{doc['domain']}"
        age_gate_head_script = f"""
<script>
try {{
  if (sessionStorage.getItem("{age_gate_key}") === "true") {{
    document.documentElement.classList.add("age-confirmed");
  }}
}} catch (e) {{}}
</script>"""
        age_gate_css = """
/* ===== AGE VERIFICATION ===== */
body.adult-gated {font-family:'Segoe UI',system-ui,-apple-system,BlinkMacSystemFont,sans-serif;}
body.adult-gated.age-gate-active {overflow:hidden;}
html.age-confirmed body.adult-gated,
body.adult-gated.age-confirmed {overflow:auto;}
body.adult-gated .age-gated-content {filter:blur(8px);pointer-events:none;user-select:none;transition:filter .22s ease, opacity .22s ease;}
html.age-confirmed body.adult-gated .age-gated-content,
body.adult-gated.age-confirmed .age-gated-content {filter:none;pointer-events:auto;user-select:auto;}
.age-gate-overlay {position:fixed;inset:0;z-index:5000;display:flex;align-items:center;justify-content:center;padding:22px;background:rgba(15,23,42,.74);backdrop-filter:blur(4px);animation:ageGateFade .2s ease-out;}
html.age-confirmed .age-gate-overlay,
body.adult-gated.age-confirmed .age-gate-overlay,
.age-gate-overlay[hidden] {display:none;}
.age-gate-card {width:min(100%,460px);background:#fff;color:#0f172a;border-radius:16px;padding:30px 28px;text-align:center;box-shadow:0 24px 80px rgba(2,6,23,.35);font-family:'Segoe UI',system-ui,-apple-system,BlinkMacSystemFont,sans-serif;}
.age-gate-icon {width:58px;height:58px;margin:0 auto 16px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:#fff7ed;color:#d97706;font-size:30px;}
.age-gate-card h2 {font-size:24px;line-height:1.25;margin:0 0 10px;color:#0f172a;font-weight:800;letter-spacing:0;}
.age-gate-card p {font-size:15px;line-height:1.7;margin:0 0 22px;color:#475569;}
.age-gate-actions {display:grid;gap:12px;}
.age-gate-btn {width:100%;border:0;border-radius:10px;padding:13px 16px;font-size:14px;font-weight:800;line-height:1.35;cursor:pointer;transition:transform .15s ease, box-shadow .15s ease, background .15s ease;font-family:inherit;}
.age-gate-btn:hover {transform:translateY(-1px);}
.age-gate-continue {background:#16a34a;color:#fff;box-shadow:0 10px 22px rgba(22,163,74,.24);}
.age-gate-continue:hover {background:#15803d;}
.age-gate-back {background:#f1f5f9;color:#991b1b;border:1px solid #e2e8f0;}
.age-gate-back:hover {background:#e2e8f0;color:#7f1d1d;}
.age-gate-exit {opacity:0;transition:opacity .18s ease;}
@keyframes ageGateFade {from {opacity:0;} to {opacity:1;}}
@media(max-width:480px) {
  .age-gate-overlay {align-items:flex-start;padding:76px 14px 20px;}
  .age-gate-card {padding:24px 18px;border-radius:14px;}
  .age-gate-card h2 {font-size:21px;}
  .age-gate-card p {font-size:14px;}
  .age-gate-btn {font-size:13px;padding:12px 13px;}
}
"""
        age_gate_html = """
<div class="age-gate-overlay" id="ageGate" role="dialog" aria-modal="true" aria-labelledby="ageGateTitle" aria-describedby="ageGateMessage">
  <div class="age-gate-card">
    <div class="age-gate-icon" aria-hidden="true">&#9888;&#65039;</div>
    <h2 id="ageGateTitle">Adult Content Warning</h2>
    <p id="ageGateMessage">This page contains analysis of a website that may host adult content. Please confirm your age to continue.</p>
    <div class="age-gate-actions">
      <button type="button" class="age-gate-btn age-gate-continue" id="ageGateContinue">&#10003; I am 18 or older - Continue</button>
      <button type="button" class="age-gate-btn age-gate-back" id="ageGateBack">&#10007; Go Back</button>
    </div>
  </div>
</div>"""
        age_gate_script = f"""
<script>
(function () {{
  var storageKey = "{age_gate_key}";
  var body = document.body;
  var gate = document.getElementById("ageGate");
  if (!body || !gate) return;

  function confirmAge() {{
    try {{
      sessionStorage.setItem(storageKey, "true");
    }} catch (e) {{}}
    document.documentElement.classList.add("age-confirmed");
    body.classList.remove("age-gate-active");
    body.classList.add("age-confirmed");
    gate.classList.add("age-gate-exit");
    window.setTimeout(function () {{
      gate.setAttribute("hidden", "hidden");
    }}, 180);
  }}

  try {{
    if (sessionStorage.getItem(storageKey) === "true") {{
      confirmAge();
      return;
    }}
  }} catch (e) {{}}

  body.classList.add("age-gate-active");
  var continueButton = document.getElementById("ageGateContinue");
  var backButton = document.getElementById("ageGateBack");
  if (continueButton) continueButton.addEventListener("click", confirmAge);
  if (backButton) backButton.addEventListener("click", function () {{
    window.location.href = "/";
  }});
}})();
</script>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(title)}</title>
<meta name="description" content="{esc(meta_desc)}">
<meta name="keywords" content="{esc(meta_keywords)}">
<meta name="author" content="ScamDekho Team">
<link rel="canonical" href="{canonical}">
<meta name="robots" content="{robots}">
<meta property="og:title" content="{esc(title)}">
<meta property="og:description" content="{esc(meta_desc)}">
<meta property="og:url" content="{canonical}">
<meta property="og:type" content="website">
<meta property="og:image" content="{og_image}">
<meta property="og:site_name" content="ScamDekho">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="{esc(title)}">
<meta name="twitter:description" content="{esc(meta_desc)}">
<meta name="twitter:image" content="{og_image}">
<meta name="theme-color" content="#0ea5e9">
<link rel="icon" type="image/x-icon" href="{SITE}/favicon/favicon.ico">
<link rel="apple-touch-icon" sizes="180x180" href="{SITE}/favicon/apple-touch-icon.png">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet"/>
<link rel="stylesheet" href="{SITE}/style.css">
<link rel="stylesheet" href="{SITE}/mobile.css">
<script async src="https://www.googletagmanager.com/gtag/js?id=G-Q4BNB3E2K4"></script>
<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-3772619201860644"
crossorigin="anonymous"></script>
<script data-grow-initializer="">!(function(){{window.growMe||((window.growMe=function(e){{window.growMe._.push(e);}}),(window.growMe._=[]));var e=document.createElement("script");(e.type="text/javascript"),(e.src="https://faves.grow.me/main.js"),(e.defer=!0),e.setAttribute("data-grow-faves-site-id","U2l0ZTo5NDU1YTI4My03ZjQ2LTQ2MTUtYmExYS0zODQ1ZGQxMmI4MTQ=");var t=document.getElementsByTagName("script")[0];t.parentNode.insertBefore(e,t);}})();</script>
<script>window.dataLayer=window.dataLayer||[];function gtag(){{dataLayer.push(arguments);}}gtag('js',new Date());gtag('config','G-Q4BNB3E2K4');</script>
{schema}
{age_gate_head_script}
<style>
/* ===== NAVBAR ===== */
.navbar{{background:rgba(255,255,255,0.95)!important;backdrop-filter:blur(12px);box-shadow:0 2px 12px rgba(0,0,0,0.06)!important;position:fixed!important;top:0;width:100%;z-index:1000!important;display:flex;align-items:center;justify-content:space-between;padding:0 60px;height:80px;}}
.navbar .site-logo{{height:170px;width:auto;object-fit:contain;}}
.navbar .nav-links{{display:flex;align-items:center;gap:35px;margin-left:auto;}}
.navbar .nav-links a{{color:#333!important;text-decoration:none;font-size:14px;font-weight:700;transition:color .2s;}}
.navbar .nav-links a:hover{{color:#0B5ED7!important;}}
.nav-dropdown{{position:relative;}}
.nav-dropdown-btn{{display:flex;align-items:center;gap:5px;color:#333!important;background:none;border:none;font-size:14px;font-weight:700;padding:0;cursor:pointer;font-family:inherit;transition:color .2s;}}
.nav-dropdown-btn:hover{{color:#0B5ED7!important;}}
.nav-dropdown-btn i{{font-size:11px;transition:transform .2s;}}
.nav-dropdown.open .nav-dropdown-btn i{{transform:rotate(180deg);}}
.nav-dropdown-menu{{display:none;position:absolute;top:calc(100% + 8px);left:0;background:#fff;border:1px solid #e2e8f0;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.12);min-width:240px;padding:8px;z-index:200;}}
.nav-dropdown.open .nav-dropdown-menu{{display:block;}}
.nav-dropdown-menu a{{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;color:#334155!important;text-decoration:none;font-size:13px;font-weight:500;transition:background .15s;}}
.nav-dropdown-menu a:hover{{background:#f0f9ff;color:#0284c7!important;}}
.nav-dropdown-menu a i{{color:#0ea5e9;width:16px;text-align:center;}}
.nav-dropdown-divider{{height:1px;background:#f1f5f9;margin:4px 0;}}
.menu-toggle{{display:none;background:none;border:none;cursor:pointer;margin-left:auto;}}
.menu-toggle span{{display:block;width:24px;height:2.5px;margin:5px 0;background:#0a2a52;border-radius:3px;}}
/* ===== FOOTER ===== */
.footer{{background:#0f172a;color:#94a3b8;padding:60px 6% 0;margin-top:40px;}}
.footer-container{{display:grid;grid-template-columns:1.4fr 1fr 1fr;gap:40px;max-width:1100px;margin:0 auto;padding-bottom:40px;}}
.footer-brand h3{{color:#fff;font-size:22px;font-weight:800;margin-bottom:12px;}}
.footer-brand p{{font-size:13px;line-height:1.8;margin-bottom:8px;}}
.footer-brand .support-email a{{color:#0ea5e9;text-decoration:none;}}
.footer-links h4,.footer-services h4{{color:#fff;font-size:14px;font-weight:700;margin-bottom:14px;}}
.footer-links a,.footer-services a{{display:block;color:#94a3b8;text-decoration:none;font-size:13px;margin-bottom:8px;transition:color .2s;}}
.footer-links a:hover,.footer-services a:hover{{color:#0ea5e9;}}
.footer-bottom{{border-top:1px solid rgba(255,255,255,0.08);padding:20px 0;text-align:center;font-size:12px;color:#64748b;}}
/* ===== BASE ===== */
*{{box-sizing:border-box;}}
body{{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#f1f5f9;color:#0f172a;margin:0;line-height:1.65;}}
.report-wrap{{max-width:760px;margin:0 auto;padding:150px 16px 40px;}}
.crumb{{font-size:12px;color:#64748b;margin:0 0 14px;}}
.crumb a{{color:#0284c7;text-decoration:none;}}
.card{{background:#fff;border:1px solid #e6ebf1;border-radius:16px;padding:28px;margin-bottom:20px;box-shadow:0 1px 3px rgba(15,23,42,0.04);}}
h1{{font-size:clamp(22px,4.5vw,30px);line-height:1.25;margin:0 0 10px;font-weight:800;letter-spacing:-0.01em;}}
h2{{font-size:20px;margin:0 0 16px;font-weight:700;color:#0f172a;letter-spacing:-0.01em;}}
h3{{font-size:15px;margin:0 0 6px;font-weight:700;color:#1e293b;}}
p{{margin:0 0 14px;color:#334155;}}
.muted{{color:#64748b;font-size:13px;}}
.summary-line{{font-weight:600;color:#0f172a;margin-top:6px;}}
/* hero */
.hero{{text-align:center;}}
.ring-wrap{{width:140px;height:140px;position:relative;margin:20px auto;}}
.ring-num{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:32px;font-weight:800;}}
.ring-num small{{font-size:14px;color:#64748b;}}
.verdict-big{{font-size:23px;font-weight:800;margin-top:4px;}}
.hero p{{max-width:580px;margin:12px auto 0;font-size:14.5px;}}
/* highlights */
.hl-grid{{display:grid;grid-template-columns:1fr 1fr;gap:22px;}}
.hl-col-title{{font-weight:700;font-size:13px;text-transform:uppercase;letter-spacing:.04em;margin-bottom:10px;}}
.hl-grid ul{{list-style:none;padding:0;margin:0;font-size:14px;}}
.hl-grid li{{display:flex;gap:9px;align-items:flex-start;margin-bottom:10px;line-height:1.5;}}
.hl-grid li i{{margin-top:3px;}}
.hl-pos .hl-col-title{{color:#15803d;}}
.hl-pos li{{color:#166534;}} .hl-pos li i{{color:#16a34a;}}
.hl-neg .hl-col-title{{color:#b91c1c;}}
.hl-neg li{{color:#991b1b;}} .hl-neg li i{{color:#dc2626;}}
.neutral-li{{color:#64748b!important;}}
/* analysis prose */
.analysis p{{line-height:1.85;font-size:15px;}}
/* facts */
.facts-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px;}}
.fact-cell{{background:#f8fafc;border:1px solid #eef2f7;border-radius:10px;padding:12px 14px;}}
.fact-k{{font-size:10px;font-weight:700;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em;}}
.fact-v{{font-size:14px;font-weight:600;color:#334155;margin-top:4px;word-break:break-all;}}
/* sources */
.grid-src{{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px;}}
.src-cell{{border:1px solid #e2e8f0;border-radius:10px;padding:13px 15px;}}
.src-top{{display:flex;justify-content:space-between;gap:8px;align-items:center;}}
.src-top strong{{font-size:13px;color:#334155;}}
.src-icon{{font-weight:800;}}
.src-msg{{font-size:12px;color:#475569;margin-top:5px;line-height:1.5;}}
.src-pos{{background:#f0fdf4;}} .src-pos .src-icon{{color:#16a34a;}}
.src-neg{{background:#fef2f2;}} .src-neg .src-icon{{color:#dc2626;}}
.src-neu{{background:#f8fafc;}} .src-neu .src-icon{{color:#94a3b8;}}
/* cta */
.cta{{display:block;text-align:center;background:linear-gradient(135deg,#0ea5e9,#0284c7);color:#fff;padding:15px;border-radius:12px;text-decoration:none;font-weight:700;margin-top:22px;font-size:15px;}}
.cta:hover{{filter:brightness(1.05);}}
/* faq */
.faq-item{{padding:16px 0;border-bottom:1px solid #eef2f7;}}
.faq-item:last-child{{border-bottom:none;padding-bottom:0;}}
.faq-item p{{margin:0;font-size:14px;color:#475569;}}
/* related */
.rel-row{{display:flex;justify-content:space-between;align-items:center;padding:12px 15px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;text-decoration:none;margin-bottom:9px;}}
.rel-row:hover{{background:#f0f9ff;}}
.rel-domain{{color:#334155;font-weight:600;font-size:14px;}}
.rel-score{{font-weight:800;font-size:14px;}}
/* ===== AD SLOTS (AdSense-safe) ===== */
.ad-wrap{{margin:30px 0;padding:10px;background:#fafbfc;border:1px solid #eef2f7;border-radius:12px;text-align:center;min-height:120px;overflow:hidden;}}
.ad-label{{display:block;font-size:10px;letter-spacing:.08em;text-transform:uppercase;color:#b6c0cc;margin-bottom:6px;}}
/* ===== DESKTOP SIDE RAILS ===== */
/* Fixed position, so they sit in the empty gutter beside the 760px column and
   never affect the content flow. Shown only when the gutter is wide enough. */
.sd-rail{{display:none;}}
.sd-rail ins{{display:block;}}
.sd-rail:not(:has(ins[data-ad-status='filled'])) .ad-label{{visibility:hidden;}}
/* max()/min() keep a rail on screen even when a scrollbar eats part of the
   gutter, which is what pushed it off the edge at exactly the breakpoint. */
@media(min-width:1440px){{
  .sd-rail{{display:block;position:fixed;top:150px;width:300px;z-index:5;text-align:center;}}
  .sd-rail-left{{left:max(12px, calc(50% - 700px));}}
  .sd-rail-right{{left:min(calc(100% - 312px), calc(50% + 400px));}}
  .sd-rail ins{{min-height:600px;}}
}}
@media(min-width:1180px) and (max-width:1439px){{
  .sd-rail-right{{display:block;position:fixed;top:150px;width:160px;z-index:5;text-align:center;left:min(calc(100% - 172px), calc(50% + 400px));}}
  .sd-rail-right ins{{min-height:600px;}}
}}
{age_gate_css}
/* mobile */
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
  .report-wrap{{padding:110px 12px 30px;}}
  .card{{padding:20px;}}
  .hl-grid,.facts-grid{{grid-template-columns:1fr;gap:16px;}}
  .footer-container{{grid-template-columns:1fr;}}
}}
</style>
</head>
<body{body_class}>

{age_gate_html}
{content_open}
{_navbar_html()}

<main class="report-wrap">

  <aside class="sd-rail sd-rail-left" aria-label="Advertisement">
    <span class="ad-label">Advertisement</span>
    <ins class="adsbygoogle"
         data-ad-client="ca-pub-3772619201860644"
         data-ad-slot="6697065974"
         data-ad-format="vertical"
         data-full-width-responsive="false"></ins>
    <script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
  </aside>
  <aside class="sd-rail sd-rail-right" aria-label="Advertisement">
    <span class="ad-label">Advertisement</span>
    <ins class="adsbygoogle"
         data-ad-client="ca-pub-3772619201860644"
         data-ad-slot="6697065974"
         data-ad-format="vertical"
         data-full-width-responsive="false"></ins>
    <script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
  </aside>

  <nav class="crumb" aria-label="Breadcrumb">
    <a href="{SITE}/">Home</a> › <a href="{SITE}/url-checker">Website Checker</a> › <span>{domain}</span>
  </nav>

  <!-- HERO -->
  <section class="card hero" style="background:{bg};">
    <p class="muted">Website Safety Report · Last checked {last_str} · Checked {scan_count} time{"s" if scan_count != 1 else ""}</p>
    <h1>Is {domain} Legit or a Scam?</h1>
    <div class="ring-wrap">
      <svg viewBox="0 0 120 120" style="transform:rotate(-90deg);width:140px;height:140px;">
        <circle cx="60" cy="60" r="54" fill="none" stroke="#e5e7eb" stroke-width="10"/>
        <circle cx="60" cy="60" r="54" fill="none" stroke="{color}" stroke-width="10" stroke-linecap="round"
          stroke-dasharray="339" stroke-dashoffset="{339 - ring_pct:.0f}"/>
      </svg>
      <div class="ring-num">{ts}<small>/100</small></div>
    </div>
    <div class="verdict-big" style="color:{color};">{verdict}</div>
    <p>{esc(answer)}</p>
  </section>

  <!-- HIGHLIGHTS -->
  <div class="ad-wrap">
  <span class="ad-label">Advertisement</span>
  <ins class="adsbygoogle"
       style="display:block"
       data-ad-client="ca-pub-3772619201860644"
       data-ad-slot="8340491187"
       data-ad-format="auto"
       data-full-width-responsive="true"></ins>
  <script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
</div>
  <section class="card">
    <h2>Is {domain} Safe? Quick Highlights</h2>
    <div class="hl-grid">
      <div class="hl-pos"><div class="hl-col-title">Positive Signals</div><ul>{pos_html}</ul></div>
      <div class="hl-neg"><div class="hl-col-title">Warning Signals</div><ul>{neg_html}</ul></div>
    </div>
  </section>

  <!-- ANALYSIS -->
  <section class="card analysis">
    <h2>{domain} Review &amp; Detailed Analysis</h2>
    {analysis_html}
  </section>
  <div class="ad-wrap">
  <span class="ad-label">Advertisement</span>
  <ins class="adsbygoogle"
       style="display:block"
       data-ad-client="ca-pub-3772619201860644"
       data-ad-slot="3750509483"
       data-ad-format="auto"
       data-full-width-responsive="true"></ins>
  <script>(adsbygoogle = window.adsbygoogle || []).push({{}});</script>
</div>

  <!-- FACTS -->
  <section class="card">
    <h2>Facts About {domain}</h2>
    <div class="facts-grid">{facts_html}</div>
  </section>

  <!-- SOURCES -->
  <section class="card">
    <h2>Security Scan Results — {total_sources} Sources Checked</h2>
    <p class="muted" style="margin-bottom:14px;">{summary.get('positive_signals',0)} passed · {summary.get('negative_signals',0)} flagged · {summary.get('neutral_signals',0)} neutral</p>
    <div class="grid-src">{src_html}</div>
    <a class="cta" href="{SITE}/url-checker">Check Another Website for Free →</a>
  </section>

  <!-- FAQ -->
  <section class="card">
    <h2>Frequently Asked Questions</h2>
    {faq_visible}
  </section>

  <!-- RELATED -->
  <section class="card">
    <h2>Recently Checked Websites</h2>
    {related_html if related_html else '<p class="muted">No related checks yet.</p>'}
  </section>

  <!-- DISCLAIMER -->
  <section class="card">
    <p class="muted" style="line-height:1.7;margin:0;">
      <strong>Disclaimer:</strong> This is an automated risk assessment based on publicly available security
      data at the time of scanning. It may not be 100% accurate and should not be treated as a definitive
      judgment of any business. Scores can change as new data becomes available.
      Website owner? <a href="mailto:support@scamdekho.in?subject=Dispute report for {domain}" style="color:#0284c7;">Dispute this result</a>.
    </p>
  </section>

</main>

{_footer_html()}
{content_close}
{_nav_js()}
{age_gate_script}
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════
# ROUTES
# ══════════════════════════════════════════════════════════════════

def build_scanning_page_html(domain: str) -> str:
    """Shown once, for a domain we have never scanned. Kicks off the real
    scan client-side, then reloads into the cached SSR report."""
    d = esc(domain)
    robots = "index, follow" if should_index_public_domain(domain) else "noindex, follow"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Checking {d} — ScamDekho</title>
<meta name="robots" content="{robots}">
<meta name="description" content="Running a free safety check on {d} — trust score, SSL, domain age and blacklist status.">
<link rel="canonical" href="{SITE}/check/{d}">
<link rel="icon" type="image/x-icon" href="{SITE}/favicon/favicon.ico">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet"/>
<link rel="stylesheet" href="{SITE}/style.css">
<link rel="stylesheet" href="{SITE}/mobile.css">
<style>
.sd-scan-wrap{{max-width:680px;margin:0 auto;padding:160px 20px 90px;text-align:center;font-family:'Segoe UI',system-ui,sans-serif;}}
@media(max-width:860px){{.sd-scan-wrap{{padding-top:120px;}}}}
.sd-scan-dom{{font-size:clamp(21px,4vw,30px);font-weight:800;color:#0f172a;margin:0 0 10px;word-break:break-all;}}
.sd-scan-sub{{color:#64748b;font-size:15px;margin:0 0 30px;}}
.sd-spin{{width:46px;height:46px;margin:0 auto 24px;border:4px solid #e2e8f0;border-top-color:#0B63C5;border-radius:50%;animation:sdspin .9s linear infinite;}}
@keyframes sdspin{{to{{transform:rotate(360deg);}}}}
.sd-steps{{list-style:none;padding:0;margin:0 auto;max-width:330px;text-align:left;}}
.sd-steps li{{padding:9px 0;color:#94a3b8;font-size:14px;transition:color .3s;}}
.sd-steps li.on{{color:#0f172a;font-weight:600;}}
.sd-steps li::before{{content:"\\25CB  ";color:#cbd5e1;}}
.sd-steps li.on::before{{content:"\\25CF  ";color:#16a34a;}}
.sd-err{{display:none;background:#fef2f2;border:1px solid #fecaca;color:#991b1b;border-radius:12px;padding:20px;margin-top:8px;font-size:14px;}}
.sd-err a{{color:#0B63C5;font-weight:700;}}
</style>
</head>
<body>
{_navbar_html()}
<main class="sd-scan-wrap">
  <div class="sd-spin" id="sdSpin"></div>
  <h1 class="sd-scan-dom">Checking {d}</h1>
  <p class="sd-scan-sub">Running a free safety scan across 14 sources. This takes a few seconds.</p>
  <ul class="sd-steps" id="sdSteps">
    <li class="on">Resolving domain &amp; SSL certificate</li>
    <li>Checking domain age &amp; ownership</li>
    <li>Matching against phishing blacklists</li>
    <li>Scoring and building your report</li>
  </ul>
  <div class="sd-err" id="sdErr">
    We could not complete the scan for <strong>{d}</strong> right now.
    <br><a href="{SITE}/url-checker">Try it on the URL checker &rarr;</a>
  </div>
</main>
{_footer_html()}
{_nav_js()}
<script>
(function(){{
  var steps=document.querySelectorAll("#sdSteps li"), i=0;
  var tick=setInterval(function(){{
    i++; if(i<steps.length){{ steps[i].classList.add("on"); }} else {{ clearInterval(tick); }}
  }}, 2200);
  var done=false;
  function fail(){{
    if(done) return;
    done=true;
    clearInterval(tick);
    document.getElementById("sdSpin").style.display="none";
    document.getElementById("sdSteps").style.display="none";
    document.getElementById("sdErr").style.display="block";
  }}
  // A full scan is ~15-20s; give up rather than spin forever.
  setTimeout(fail, 90000);
  fetch("{API_BASE}/api/v1/check/url", {{
    method:"POST",
    headers:{{"Content-Type":"application/json"}},
    body:JSON.stringify({{url:"https://{d}"}})
  }}).then(function(r){{
    if(!r.ok) throw new Error("scan failed");
    return r.json();
  }}).then(function(){{
    if(done) return;
    done=true;
    // page now exists server-side -> reload into the real report
    window.location.replace("{SITE}/check/{d}?scanned=1");
  }}).catch(fail);
}})();
</script>
</body>
</html>"""


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
        # Not scanned yet -> render instantly and run the scan in the browser.
        # The scan writes the page (save_public_scan), so the reload below
        # lands on the normal SSR report and the sitemap picks it up.
        return HTMLResponse(build_scanning_page_html(d), status_code=200)

    # generate-once-cache-forever (sirf jab page actually khule)
    seo_html = await ensure_seo_content(doc)

    related = await get_recent_pages(limit=7)
    page = build_page_html(doc, related, seo_html)
    return HTMLResponse(page, headers={"Cache-Control": "public, max-age=3600"})


@router.get("/sitemap-index.xml")
async def sitemap_index():
    try:
        total = await pages_collection.count_documents({"indexable": True})
    except Exception:
        total = 0
    page_count = max(1, (total + SITEMAP_PAGE_SIZE - 1) // SITEMAP_PAGE_SIZE)
    items = "".join(
        f"<sitemap><loc>{SITE}/sitemap-checks-{i}.xml</loc></sitemap>" for i in range(page_count)
    )
    xml = (f'<?xml version="1.0" encoding="UTF-8"?>'
           f'<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{items}</sitemapindex>')
    return Response(content=xml, media_type="application/xml")


@router.get("/sitemap-checks-{page}.xml")
async def sitemap_checks_paginated(page: int):
    skip = page * SITEMAP_PAGE_SIZE
    try:
        cursor = pages_collection.find(
            {"indexable": True}, {"domain": 1, "last_scanned": 1}
        ).sort("last_scanned", -1).skip(skip).limit(SITEMAP_PAGE_SIZE)
        docs = [doc async for doc in cursor]
    except Exception:
        docs = []
    items = ""
    for doc in docs:
        lastmod = ""
        ls = doc.get("last_scanned")
        if isinstance(ls, datetime):
            lastmod = f"<lastmod>{ls.strftime('%Y-%m-%d')}</lastmod>"
        items += (f"<url><loc>{SITE}/check/{esc(doc['domain'])}</loc>{lastmod}"
                  f"<changefreq>weekly</changefreq><priority>0.6</priority></url>")
    xml = (f'<?xml version="1.0" encoding="UTF-8"?>'
           f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{items}</urlset>')
    return Response(content=xml, media_type="application/xml")


@router.get("/sitemap-checks.xml")
async def sitemap_checks_legacy():
    return await sitemap_checks_paginated(0)


@router.get("/api/v1/recent-checks")
async def recent_checks():
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

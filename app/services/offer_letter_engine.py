import os
import json
import base64
import io
import re
import traceback
from datetime import datetime
from typing import Optional
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))


# =====================================================
# 1. REFERENCE DATA
# =====================================================

KNOWN_COMPANY_DOMAINS = {
    "tcs.com", "infosys.com", "wipro.com", "hcltech.com", "techmahindra.com",
    "cognizant.com", "capgemini.com", "accenture.com", "deloitte.com", "ibm.com",
    "oracle.com", "microsoft.com", "google.com", "amazon.com", "amazon.in",
    "flipkart.com", "zoho.com", "freshworks.com", "ltimindtree.com", "mphasis.com",
    "persistent.com", "coforge.com", "birlasoft.com", "hexaware.com", "niit.com",
    "mindtree.com", "lti.com", "cyient.com", "zensar.com", "sasken.com",
    "reliance.com", "ril.com", "adani.com", "tata.com", "tatasteel.com",
    "godrej.com", "mahindra.com", "bajaj.com", "larsentoubro.com", "lntecc.com",
    "aditya-birla.com", "vedanta.com", "jsw.in",
    "icicibank.com", "hdfcbank.com", "sbi.co.in", "axisbank.com", "kotak.com",
    "yesbank.in", "idfcfirst.com", "rbl.bank", "indusind.com", "bankofbaroda.co.in",
    "pnb.co.in", "canarabank.com", "unionbankofindia.co.in",
    "airtel.com", "jio.com", "vodafone.com", "vi.com",
    "paytm.com", "zomato.com", "swiggy.com", "ola.com", "uber.com",
    "myntra.com", "nykaa.com", "meesho.com", "cred.club", "razorpay.com",
    "phonepe.com", "policybazaar.com", "byju.com", "unacademy.com",
    "sharechat.com", "dream11.com", "groww.in", "zerodha.com", "upstox.com",
    "sunpharma.com", "cipla.com", "drreddy.com", "biocon.com", "lupin.com",
    "mankindpharma.com", "torrentpharma.com",
    "hul.co.in", "itcportal.com", "dabur.com", "marico.com", "nestleindia.com",
    "britannia.co.in", "parle.com", "amul.coop",
    "pwc.com", "ey.com", "kpmg.com", "mckinsey.com", "bain.com", "bcg.com",
    "ongcindia.com", "ntpc.co.in", "iocl.com", "bhel.com", "sail.co.in",
    "gail.co.in", "coalindia.in", "drdo.gov.in",
}

GENERIC_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.in", "yahoo.co.in", "outlook.com",
    "hotmail.com", "rediffmail.com", "protonmail.com", "mail.com",
    "aol.com", "yandex.com", "icloud.com", "live.com", "msn.com",
    "zohomail.com", "tutanota.com", "gmx.com", "fastmail.com",
}

# --- FIX #1: Soft scoring — each signal has a weight (0-1) instead of hard penalty ---
# weight = how much this signal should influence the trust score
# direction = "negative" (lowers trust) or "positive" (raises trust)

SCAM_FEE_PATTERNS = [
    (r"registration\s*fee", 0.9, "Registration fee demand"),
    (r"security\s*deposit", 0.85, "Security deposit demand"),
    (r"training\s*fee", 0.8, "Training fee demand"),
    (r"processing\s*fee", 0.8, "Processing fee demand"),
    (r"onboarding\s*fee", 0.8, "Onboarding fee demand"),
    (r"joining\s*fee", 0.8, "Joining fee demand"),
    (r"documentation\s*fee", 0.7, "Documentation fee demand"),
    (r"verification\s*fee", 0.7, "Verification fee demand"),
    (r"uniform\s*fee", 0.7, "Uniform fee demand"),
    (r"kit\s*fee", 0.7, "Kit fee demand"),
    (r"laptop\s*deposit", 0.7, "Laptop deposit demand"),
    (r"caution\s*deposit", 0.7, "Caution deposit demand"),
    (r"refundable\s*deposit", 0.75, "Refundable deposit demand"),
    (r"advance\s*payment", 0.8, "Advance payment demand"),
    (r"pay\s*(?:rs\.?|inr|₹)\s*\d+", 0.85, "Direct payment amount mentioned"),
    (r"transfer\s*(?:rs\.?|inr|₹)\s*\d+", 0.85, "Money transfer demand"),
    (r"send\s*(?:rs\.?|inr|₹)\s*\d+", 0.85, "Money send demand"),
    (r"bharti\s*shulk", 0.8, "Bharti shulk (Hindi fee demand)"),
    (r"registration\s*charges", 0.8, "Registration charges"),
    (r"security\s*money", 0.8, "Security money demand"),
    (r"pay\s*before\s*joining", 0.75, "Pay before joining"),
    (r"fees?\s*payment", 0.7, "Fee payment mentioned"),
    (r"bank\s*transfer\s*required", 0.7, "Bank transfer required"),
    (r"(?:upi|google\s*pay|phonepe|paytm)\s*(?:id|payment|transfer)?", 0.6, "UPI/payment app mentioned"),
    # Visa/foreign job scam patterns
    (r"bear\s*(?:your\s*)?(?:visa|work\s*permit)\s*(?:expenses?|cost|charges?|fees?)", 0.7, "Visa/work permit expense demand"),
    (r"visa\s*(?:processing\s*)?(?:fee|charges?|cost|expenses?)", 0.7, "Visa fee/charges mentioned"),
    (r"pay\s*(?:for\s*)?(?:visa|work\s*permit)", 0.7, "Pay for visa/permit demand"),
    (r"visa\s*deposit", 0.75, "Visa deposit demand"),
    (r"embassy\s*(?:fee|charges?)", 0.65, "Embassy fee mentioned"),
    (r"immigration\s*(?:fee|charges?|cost)", 0.65, "Immigration fee mentioned"),
    (r"work\s*permit\s*(?:fee|charges?|cost|expenses?)", 0.7, "Work permit fee demand"),
    (r"stamping\s*(?:fee|charges?)", 0.6, "Stamping fee demand"),
]

# Foreign job scam patterns (separate from fee — structural red flags)
FOREIGN_JOB_SCAM_PATTERNS = [
    (r"bear\s*(?:your\s*)?(?:visa|work\s*permit)\s*(?:expenses?|cost)", 0.7, "Candidate asked to bear visa expenses"),
    (r"passport\s*(?:number|no\.?|#)[\s:]+[A-Z0-9]", 0.5, "Passport number in offer letter (unusual)"),
    (r"(?:work\s*permit|visa)\s*(?:will\s*be\s*)?(?:sent|provided|arranged)\s*(?:to|by)\s*(?:your\s*)?(?:embassy|country)", 0.6, "Visa sent to embassy claim"),
    (r"(?:food\s*packing|fruit\s*picking|farm\s*work|warehouse\s*helper|cleaner|dishwasher|caregiver)\s*(?:job|role|position|designation)?", 0.5, "Low-skill foreign job role"),
    (r"(?:new\s*zealand|australia|canada|uk|dubai|qatar|saudi|oman|bahrain|kuwait|malaysia|singapore)\s*(?:job|work|employment|company|offer)", 0.4, "Foreign country job offer"),
    (r"(?:shortlisted|selected)\s*(?:for|in)\s*(?:our\s*)?(?:company|organization)(?:\s*in\s*(?:new\s*zealand|australia|canada|uk|dubai|abroad))?", 0.35, "Shortlisted without proper process"),
    (r"(?:work\s*permit|employment\s*visa|labor\s*card)", 0.3, "Work permit/employment visa mentioned"),
    (r"(?:accommodation|food|medical)\s*(?:will\s*be\s*)?(?:provided|arranged|free)", 0.25, "Too-good benefits for low-skill job"),
    (r"(?:labor\s*authority|labour\s*authority|labor\s*rules?\s*act)", 0.3, "Fake labor authority reference"),
    (r"(?:apply(?:ing)?\s*visa\s*in|visa\s*application\s*for)\s*(?:new\s*zealand|australia|canada|uk|dubai)", 0.5, "Applying visa in foreign country"),
]

URGENCY_PATTERNS = [
    (r"join\s*within\s*24\s*hours?", 0.7, "Join within 24 hours"),
    (r"respond\s*immediately", 0.6, "Respond immediately"),
    (r"offer\s*expires?\s*today", 0.7, "Offer expires today"),
    (r"last\s*date\s*today", 0.6, "Last date today"),
    (r"join\s*tomorrow", 0.5, "Join tomorrow"),
    (r"urgent\s*joining", 0.5, "Urgent joining"),
    (r"immediate\s*joining\s*required", 0.5, "Immediate joining required"),
    (r"confirm\s*within\s*\d+\s*hour", 0.6, "Confirm within hours"),
    (r"reply\s*urgently", 0.5, "Reply urgently"),
    (r"act\s*now", 0.4, "Act now"),
    (r"limited\s*(?:time|period|seats?)", 0.4, "Limited time/seats"),
    (r"once\s*in\s*a\s*lifetime", 0.5, "Once in a lifetime"),
    (r"golden\s*opportunity", 0.4, "Golden opportunity"),
]

LEGITIMATE_COMPONENTS = [
    (r"ctc\s*break\s*-?up", 0.8, "CTC breakup present"),
    (r"basic\s*salary", 0.6, "Basic salary mentioned"),
    (r"\bhra\b", 0.5, "HRA component"),
    (r"provident\s*fund|\bpf\b|\bepf\b", 0.6, "PF/EPF mentioned"),
    (r"gratuity", 0.5, "Gratuity mentioned"),
    (r"medical\s*insurance|health\s*insurance|group\s*insurance", 0.5, "Insurance mentioned"),
    (r"leave\s*policy|annual\s*leave|casual\s*leave|sick\s*leave", 0.4, "Leave policy"),
    (r"probation\s*period", 0.5, "Probation period mentioned"),
    (r"notice\s*period", 0.5, "Notice period mentioned"),
    (r"background\s*verification|bgv", 0.5, "Background verification"),
    (r"reporting\s*manager|reporting\s*to", 0.5, "Reporting manager mentioned"),
    (r"cin[\s:]+[A-Z0-9]", 0.7, "CIN number present"),
    (r"gstin?[\s:]+\d", 0.6, "GST number present"),
    (r"pan[\s:]+[A-Z]{5}\d{4}[A-Z]", 0.5, "Company PAN present"),
    (r"employee\s*(?:code|id|number)", 0.4, "Employee ID/Code"),
    (r"designation", 0.5, "Designation mentioned"),
    (r"department", 0.4, "Department mentioned"),
    (r"date\s*of\s*joining|joining\s*date|doj", 0.5, "Joining date present"),
    (r"annual\s*ctc|per\s*annum|p\.?a\.?", 0.5, "Annual CTC/PA mentioned"),
    (r"professional\s*tax", 0.4, "Professional tax mentioned"),
    (r"esi\b|employees?\s*state\s*insurance", 0.5, "ESI mentioned"),
    (r"non[\s-]*compete|non[\s-]*disclosure|nda\b|nca\b", 0.4, "Legal clauses present"),
    (r"intellectual\s*property|confidentiality", 0.4, "IP/Confidentiality clause"),
    (r"terms?\s*and\s*conditions?|t&c", 0.3, "Terms and conditions"),
]

MLM_PATTERNS = [
    (r"network\s*marketing", 0.8, "Network marketing"),
    (r"multi[\s-]*level", 0.8, "Multi-level marketing"),
    (r"direct\s*selling", 0.5, "Direct selling"),
    (r"recruit\s*(?:people|members|team)", 0.6, "Recruit people/team"),
    (r"downline|upline", 0.8, "Downline/upline structure"),
    (r"earn\s*from\s*home", 0.4, "Earn from home"),
    (r"unlimited\s*earning", 0.6, "Unlimited earning promise"),
    (r"no\s*experience\s*(?:needed|required)", 0.4, "No experience needed"),
    (r"work\s*from\s*home.*earn.*lakh", 0.6, "WFH earn lakhs"),
    (r"daily\s*payment|daily\s*income", 0.5, "Daily payment/income"),
    (r"commission\s*based\s*only", 0.5, "Commission only"),
    (r"investment\s*opportunity.*job", 0.6, "Investment as job"),
]

# --- FIX #2: Context-based salary ranges ---
# Maps detected role keywords to expected salary ranges (LPA) for India
ROLE_SALARY_RANGES = {
    # Entry-level / Fresher roles
    "fresher": (1.5, 12),
    "intern": (0.5, 6),
    "trainee": (1, 8),
    "junior": (2, 15),
    "associate": (2, 18),
    "graduate": (1.5, 12),
    "entry level": (1.5, 10),
    # Mid-level
    "software engineer": (3, 35),
    "developer": (3, 35),
    "systems engineer": (3, 20),
    "analyst": (3, 25),
    "consultant": (5, 40),
    "team lead": (8, 45),
    "senior": (6, 50),
    "lead": (8, 50),
    # Senior / Management
    "manager": (10, 60),
    "architect": (15, 70),
    "director": (20, 100),
    "vice president": (25, 120),
    "vp": (25, 120),
    "head": (15, 80),
    "principal": (15, 60),
    "cto": (20, 150),
    "ceo": (20, 200),
    "cfo": (20, 150),
    # Support / Operations
    "data entry": (1.5, 5),
    "customer support": (1.5, 6),
    "executive": (2, 15),
    "coordinator": (2, 10),
    "clerk": (1.5, 5),
    "receptionist": (1.5, 5),
    "peon": (1, 3),
    "driver": (1, 4),
    "security guard": (1, 3),
    # Specialized
    "data scientist": (6, 50),
    "machine learning": (6, 50),
    "devops": (5, 40),
    "cloud": (5, 45),
    "product manager": (10, 50),
}

SUSPICIOUS_CREATION_TOOLS = ["canva", "google docs", "libreoffice", "wps office", "smallpdf", "ilovepdf"]
LEGIT_CREATION_TOOLS = ["microsoft word", "adobe acrobat", "adobe indesign", "sap", "oracle", "workday"]


# =====================================================
# 2. TEXT EXTRACTION
# =====================================================

def extract_text_from_pdf(file_bytes: bytes) -> str:
    try:
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(file_bytes))
        return "".join(page.extract_text() or "" for page in reader.pages).strip()
    except Exception as e:
        print("PDF EXTRACT ERROR:", e)
        return ""


def extract_text_from_doc(file_bytes: bytes) -> str:
    try:
        import docx
        doc = docx.Document(io.BytesIO(file_bytes))
        return "\n".join(para.text for para in doc.paragraphs).strip()
    except Exception as e:
        print("DOC EXTRACT ERROR:", e)
        return ""


# =====================================================
# 3. PDF METADATA FORENSICS
# =====================================================

def extract_pdf_metadata(file_bytes: bytes) -> dict:
    meta = {
        "creator": None, "producer": None, "author": None,
        "creation_date": None, "modification_date": None,
        "is_editable": False, "page_count": 0, "has_images": False,
        "has_forms": False, "font_count": 0, "fonts_used": [],
        "file_size_kb": round(len(file_bytes) / 1024, 1),
        "signals": [],
    }

    try:
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(file_bytes))
        info = reader.metadata
        if info:
            meta["creator"] = str(info.get("/Creator", "")) or None
            meta["producer"] = str(info.get("/Producer", "")) or None
            meta["author"] = str(info.get("/Author", "")) or None
            meta["creation_date"] = str(info.get("/CreationDate")) if info.get("/CreationDate") else None
            meta["modification_date"] = str(info.get("/ModDate")) if info.get("/ModDate") else None

        meta["page_count"] = len(reader.pages)
        for page in reader.pages:
            if "/Annots" in page:
                for annot in (page["/Annots"] or []):
                    try:
                        if annot.get_object().get("/Subtype") == "/Widget":
                            meta["is_editable"] = True
                            break
                    except Exception:
                        pass
            if "/XObject" in page.get("/Resources", {}):
                meta["has_images"] = True
    except Exception as e:
        print("PDF META ERROR:", e)

    try:
        import fitz
        doc = fitz.open(stream=file_bytes, filetype="pdf")
        all_fonts = set()
        for page in doc:
            for font in page.get_fonts():
                if font[3]:
                    all_fonts.add(font[3])
        meta["fonts_used"] = list(all_fonts)[:20]
        meta["font_count"] = len(all_fonts)
    except Exception:
        pass

    # Generate signals
    sigs = meta["signals"]
    combined_tools = ((meta["creator"] or "") + " " + (meta["producer"] or "")).lower()
    for tool in SUSPICIOUS_CREATION_TOOLS:
        if tool in combined_tools:
            sigs.append(("warning", f"Created using '{tool}' (unusual for corporate)", 0.3))
    for tool in LEGIT_CREATION_TOOLS:
        if tool in combined_tools:
            sigs.append(("positive", f"Created with '{tool}' (corporate standard)", 0.3))
    if not meta["creator"] and not meta["producer"] and not meta["author"]:
        sigs.append(("warning", "No PDF metadata (stripped or manual)", 0.2))
    if meta["is_editable"]:
        sigs.append(("warning", "Editable form fields (possible tampering)", 0.4))
    if meta["file_size_kb"] < 20 and meta["page_count"] >= 1:
        sigs.append(("warning", f"Tiny file ({meta['file_size_kb']}KB)", 0.2))
    if meta["font_count"] > 8:
        sigs.append(("warning", f"{meta['font_count']} fonts (inconsistent)", 0.2))
    if not meta["has_images"] and meta["page_count"] >= 1:
        sigs.append(("warning", "No images/logos (missing letterhead)", 0.3))
    if meta["creation_date"] and meta["modification_date"] and meta["creation_date"] != meta["modification_date"]:
        sigs.append(("info", "Modified after creation", 0.1))

    return meta


# =====================================================
# 4. EXTERNAL DOMAIN AGE CHECK (FIX #5)
# =====================================================

# In-memory cache: domain -> (result_dict, timestamp)
_whois_cache = {}
WHOIS_CACHE_TTL = 3600  # Cache for 1 hour (seconds)
WHOIS_TIMEOUT = 5  # Max seconds to wait for WHOIS


def check_domain_age(domain: str) -> dict:
    """
    Check domain age via python-whois with caching.
    WHOIS fail = completely neutral (zero weight, no penalty).
    Results cached for 1 hour to avoid repeated lookups.
    """
    import time

    result = {
        "domain": domain,
        "age_days": None,
        "creation_date": None,
        "registrar": None,
        "is_new_domain": None,
        "check_success": False,
        "signal": None,
        "weight": 0,
    }

    # Skip WHOIS for known verified domains
    if domain in KNOWN_COMPANY_DOMAINS:
        result["check_success"] = True
        result["is_new_domain"] = False
        result["signal"] = ("positive", f"'{domain}' is a known verified company domain", 0.6)
        return result

    # Skip for generic email domains
    if domain in GENERIC_EMAIL_DOMAINS:
        return result

    # Check cache first
    now = time.time()
    if domain in _whois_cache:
        cached_result, cached_time = _whois_cache[domain]
        if now - cached_time < WHOIS_CACHE_TTL:
            return cached_result

    try:
        import whois
        w = whois.whois(domain)

        if w and w.creation_date:
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if created:
                age_days = (datetime.now() - created).days
                result["age_days"] = age_days
                result["creation_date"] = str(created)
                result["registrar"] = str(w.registrar) if w.registrar else None
                result["check_success"] = True

                if age_days < 90:
                    result["is_new_domain"] = True
                    result["signal"] = ("red_flag", f"Domain '{domain}' is only {age_days} days old (very new)", 0.7)
                elif age_days < 180:
                    result["is_new_domain"] = True
                    result["signal"] = ("warning", f"Domain '{domain}' is {age_days} days old (relatively new)", 0.4)
                elif age_days < 365:
                    result["is_new_domain"] = False
                    result["signal"] = ("info", f"Domain '{domain}' is {age_days} days old (< 1 year)", 0.15)
                else:
                    years = round(age_days / 365, 1)
                    result["is_new_domain"] = False
                    result["signal"] = ("positive", f"Domain '{domain}' is {years} years old (established)", 0.4)
        else:
            # Could not determine age — neutral, zero weight
            result["signal"] = None  # No signal at all

    except Exception as e:
        # WHOIS failed — completely ignore, no signal, no penalty
        print(f"WHOIS FAILED for {domain} (ignored): {e}")
        result["signal"] = None  # No signal — neutral

    # Cache the result
    _whois_cache[domain] = (result, now)

    return result


# =====================================================
# 5. CONTEXT-BASED EMAIL ANALYSIS (FIX #3)
# =====================================================

def analyze_domains_in_text(text: str) -> dict:
    """
    Smart email analysis:
    - Big company + Gmail → red flag (weight 0.6)
    - Unknown/startup + Gmail → neutral (weight 0.15)
    - Known domain verified → strong positive
    - Unknown custom domain → check age
    """
    text_lower = text.lower()
    result = {
        "emails_found": [], "domains_found": [], "urls_found": [],
        "domain_signals": [], "domain_age_results": [],
        "is_known_company": False, "is_startup_likely": False,
    }

    emails = list(set(re.findall(r'[\w.-]+@[\w.-]+\.\w{2,}', text_lower)))
    result["emails_found"] = emails

    # Detect if this looks like a big company or startup
    big_company_signals = bool(re.search(
        r'(pvt\s*ltd|private\s*limited|limited|ltd\.|inc\.|corporation|'
        r'cin[\s:]+[A-Z]|gstin|registered\s*office|corporate\s*office|'
        r'group\s*of\s*companies|fortune\s*500|mnc)',
        text_lower
    ))
    startup_signals = bool(re.search(
        r'(startup|start-up|early\s*stage|seed\s*fund|bootstrap|'
        r'co-?founder|founding\s*team|series\s*[a-d]|angel\s*invest|'
        r'stealth|pre-?revenue)',
        text_lower
    ))

    result["is_known_company"] = big_company_signals
    result["is_startup_likely"] = startup_signals

    for email in emails:
        domain = email.split('@')[1]
        result["domains_found"].append(domain)

        if domain in KNOWN_COMPANY_DOMAINS:
            result["domain_signals"].append({
                "type": "green_flag", "weight": 0.7,
                "detail_en": f"Verified company domain: {domain}",
                "detail_hi": f"सत्यापित कंपनी डोमेन: {domain}",
            })
            result["is_known_company"] = True

        elif domain in GENERIC_EMAIL_DOMAINS:
            # FIX #3: Context-aware Gmail scoring
            if big_company_signals and not startup_signals:
                # Big company claiming Gmail = suspicious
                result["domain_signals"].append({
                    "type": "red_flag", "weight": 0.6,
                    "detail_en": f"Large company using generic email: {email}",
                    "detail_hi": f"बड़ी कंपनी सामान्य ईमेल इस्तेमाल कर रही: {email}",
                })
            elif startup_signals:
                # Startup using Gmail = totally normal
                result["domain_signals"].append({
                    "type": "neutral", "weight": 0.1,
                    "detail_en": f"Startup using {domain} (common for early-stage)",
                    "detail_hi": f"स्टार्टअप {domain} इस्तेमाल कर रहा (शुरुआती चरण में सामान्य)",
                })
            else:
                # Unknown context + Gmail = mild concern
                result["domain_signals"].append({
                    "type": "warning", "weight": 0.25,
                    "detail_en": f"Generic email used: {email} (not necessarily a scam for small firms)",
                    "detail_hi": f"सामान्य ईमेल: {email} (छोटी फर्मों के लिए ज़रूरी नहीं कि scam हो)",
                })
        else:
            # Unknown custom domain → check age externally
            age_result = check_domain_age(domain)
            result["domain_age_results"].append(age_result)
            if age_result["signal"]:
                sig_type, sig_text, sig_weight = age_result["signal"]
                result["domain_signals"].append({
                    "type": sig_type, "weight": sig_weight,
                    "detail_en": sig_text,
                    "detail_hi": sig_text,
                })

    # URLs
    urls = list(set(re.findall(r'https?://[\w./\-?=&]+', text_lower)))
    # Also catch www.xyz.com without http
    www_urls = list(set(re.findall(r'(?:www\.)([\w.\-]+\.\w{2,})', text_lower)))
    result["urls_found"] = urls

    for url in urls:
        if any(s in url for s in ["bit.ly", "tinyurl", "goo.gl", "t.co", "shorturl", "rebrand.ly"]):
            result["domain_signals"].append({
                "type": "red_flag", "weight": 0.4,
                "detail_en": f"Shortened URL: {url}",
                "detail_hi": f"छोटा URL: {url}",
            })

    # Extract domains from URLs and www references for WHOIS check
    url_domains = set()
    for url in urls:
        match = re.search(r'https?://(?:www\.)?([\w.\-]+\.\w{2,})', url)
        if match:
            url_domains.add(match.group(1))
    for wd in www_urls:
        url_domains.add(wd)

    # Run WHOIS on URL domains (if not already checked via email)
    checked_domains = set(result["domains_found"])
    for ud in url_domains:
        if ud not in checked_domains and ud not in GENERIC_EMAIL_DOMAINS:
            age_result = check_domain_age(ud)
            result["domain_age_results"].append(age_result)
            if age_result["signal"]:
                sig_type, sig_text, sig_weight = age_result["signal"]
                result["domain_signals"].append({
                    "type": sig_type, "weight": sig_weight,
                    "detail_en": sig_text,
                    "detail_hi": sig_text,
                })
            result["domains_found"].append(ud)

    if not emails:
        result["domain_signals"].append({
            "type": "warning", "weight": 0.2,
            "detail_en": "No email found in offer letter",
            "detail_hi": "ऑफ़र लेटर में कोई ईमेल नहीं",
        })

    return result


# =====================================================
# 5B. COMPANY ONLINE PRESENCE CHECK (LinkedIn + Google)
# =====================================================

# Cache for company presence checks
_company_presence_cache = {}
COMPANY_PRESENCE_CACHE_TTL = 3600  # 1 hour


def extract_company_name(text: str) -> str:
    """
    Try to extract company name from offer letter text.
    Looks for common patterns in Indian offer letters.
    """
    text_clean = text.strip()

    # Company suffix pattern (reusable) — covers Indian + international formats
    suffix = (r'(?:Ltd\.?|Limited|Pvt\.?\s*Ltd\.?|Private\s+Limited|'
              r'Inc\.?|Corporation|LLP|Solutions|Technologies|'
              r'Services|Consulting|Systems|Infra|Group|India|'
              r'Foods?|Industries|Enterprises?|International|'
              r'Pharma|Chemicals|Motors|Auto|Textiles|'
              r'Communications|Logistics|Construction|Builders|'
              r'Healthcare|Hospital|Labs|Academy|Institute|'
              r'Foundation|Trust|Associates|Partners|Co\.?\s*Ltd\.?|'
              r'Company|Ventures|Capital|Studios?|Digital|'
              r'Global|Worldwide|Overseas|Export|Import)')

    # Pattern 1: "at/in/with/for <Company Name ending with suffix>"
    match = re.search(
        r'\b(?:at|in|with|from|to|for|into)\s+'
        r'(?:the\s+)?'
        r'([A-Z][A-Za-z0-9\s&\'-]{2,50}' + suffix + r')',
        text_clean
    )
    if match:
        name = match.group(1).strip().rstrip('.,')
        name = re.sub(r'^(?:position|role|post|designation|offer|job)\s+(?:of|at|in|with|for)\s+', '', name, flags=re.IGNORECASE).strip()
        if len(name) > 3:
            return name

    # Pattern 1B: ALL CAPS company name like "CEDENCO FOOD" or "CEDENCO FOODS New Zealand"
    caps_match = re.search(
        r'\b([A-Z]{3,}(?:\s+[A-Z]{2,})*(?:\s+' + suffix + r')?(?:\s+(?:New\s+Zealand|India|Australia|UK|USA|Dubai|Singapore|Canada|Global))?)\b',
        text_clean
    )
    if caps_match:
        name = caps_match.group(1).strip()
        # Filter out common non-company all-caps words
        skip_words = {'OFFER', 'LETTER', 'DEAR', 'ACCEPTANCE', 'WORK', 'PERMIT', 'DATE', 'THE', 'MR', 'MRS', 'MS', 'PASSPORT', 'EDUCATION', 'TERMINATION'}
        words = name.split()
        if len(words) >= 2 and words[0] not in skip_words:
            return name

    # Pattern 2: Standalone company name in first 500 chars
    header = text_clean[:500]
    match2 = re.search(
        r'([A-Z][A-Za-z0-9\s&\'-]{2,40}' + suffix + r')',
        header
    )
    if match2:
        return match2.group(1).strip().rstrip('.,')

    # Pattern 3: CIN line
    cin_match = re.search(r'([A-Z][\w\s&\'-]{3,40}?)[\s]*CIN[\s:]+[A-Z0-9]', text_clean)
    if cin_match:
        name = cin_match.group(1).strip()
        if len(name) > 3:
            return name.rstrip('.,')

    # Pattern 4: Website domain as fallback company name (e.g. www.cedenco.co.nz → Cedenco)
    website_match = re.search(r'(?:website|www)\s*[:\s]*(?:www\.)?([a-zA-Z0-9-]+)\.', text_clean, re.IGNORECASE)
    if website_match:
        domain_name = website_match.group(1).strip()
        if len(domain_name) > 2 and domain_name.lower() not in {'com', 'org', 'net', 'co', 'in'}:
            return domain_name.capitalize()
    return ""


def check_company_online_presence(company_name: str) -> dict:
    """
    Check if company has LinkedIn presence via Google Custom Search API.
    Falls back to requests-based Google search if API key not configured.

    Env vars needed (optional):
      GOOGLE_CSE_API_KEY — Google Custom Search API key
      GOOGLE_CSE_CX — Custom Search Engine ID

    If not configured, uses requests to do a basic Google search (less reliable).
    Fails gracefully — if check fails, returns neutral (no signal).
    """
    import time

    result = {
        "company_name": company_name,
        "linkedin_found": False,
        "linkedin_url": None,
        "google_results_found": False,
        "check_success": False,
        "signal": None,
    }

    if not company_name or len(company_name) < 3:
        return result

    # Normalize company name for search
    search_name = company_name.strip()

    # Check cache
    cache_key = search_name.lower()
    now = time.time()
    if cache_key in _company_presence_cache:
        cached, cached_time = _company_presence_cache[cache_key]
        if now - cached_time < COMPANY_PRESENCE_CACHE_TTL:
            return cached

    # Known companies — skip search
    known_names = {
        "tata consultancy services", "tcs", "infosys", "wipro", "hcl",
        "tech mahindra", "cognizant", "accenture", "deloitte", "ibm",
        "google", "microsoft", "amazon", "flipkart", "zomato", "swiggy",
        "paytm", "razorpay", "phonepe", "reliance", "adani", "godrej",
        "mahindra", "bajaj", "hdfc", "icici", "axis bank", "sbi",
        "capgemini", "oracle", "zoho", "freshworks", "byju",
    }
    if any(kn in search_name.lower() for kn in known_names):
        result["linkedin_found"] = True
        result["check_success"] = True
        result["signal"] = ("positive", f"'{search_name}' is a well-known company with verified online presence", 0.5)
        _company_presence_cache[cache_key] = (result, now)
        return result

    # Try Google Custom Search API first
    api_key = os.getenv("GOOGLE_CSE_API_KEY")
    cse_cx = os.getenv("GOOGLE_CSE_CX")

    if api_key and cse_cx:
        try:
            import httpx
            query = f"{search_name} linkedin company"
            url = "https://www.googleapis.com/customsearch/v1"
            params = {"key": api_key, "cx": cse_cx, "q": query, "num": 5}

            with httpx.Client(timeout=5) as http_client:
                resp = http_client.get(url, params=params)

            if resp.status_code == 200:
                data = resp.json()
                items = data.get("items", [])
                result["google_results_found"] = len(items) > 0
                result["check_success"] = True

                for item in items:
                    link = item.get("link", "")
                    if "linkedin.com/company/" in link:
                        result["linkedin_found"] = True
                        result["linkedin_url"] = link
                        break

                if result["linkedin_found"]:
                    result["signal"] = ("positive", f"'{search_name}' has a LinkedIn company page", 0.4)
                else:
                    # No LinkedIn but Google results exist
                    if result["google_results_found"]:
                        result["signal"] = ("info", f"'{search_name}' found on Google but no LinkedIn page", 0.0)
                    else:
                        result["signal"] = ("warning", f"'{search_name}' has very low online presence", 0.2)

        except Exception as e:
            print(f"GOOGLE CSE ERROR for '{search_name}': {e}")
            result["signal"] = None  # Fail = neutral
    else:
        # Fallback: basic Google search via requests
        try:
            import httpx
            query = f"{search_name} site:linkedin.com/company"
            search_url = f"https://www.google.com/search?q={query}&num=3"
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }

            with httpx.Client(timeout=5, follow_redirects=True) as http_client:
                resp = http_client.get(search_url, headers=headers)

            if resp.status_code == 200:
                body = resp.text
                result["check_success"] = True

                # Check if LinkedIn company URL appears in results
                linkedin_matches = re.findall(r'linkedin\.com/company/[\w-]+', body)
                if linkedin_matches:
                    result["linkedin_found"] = True
                    result["linkedin_url"] = f"https://www.{linkedin_matches[0]}"
                    result["signal"] = ("positive", f"'{search_name}' has a LinkedIn company page", 0.4)
                else:
                    result["signal"] = ("warning", f"No LinkedIn company page found for '{search_name}'", 0.2)
            else:
                result["signal"] = None  # Fail = neutral

        except Exception as e:
            print(f"GOOGLE SEARCH ERROR for '{search_name}': {e}")
            result["signal"] = None  # Fail = neutral

    # Cache result
    _company_presence_cache[cache_key] = (result, now)
    return result


# =====================================================
# 6. CONTEXT-BASED SALARY CHECK (FIX #2)
# =====================================================

def analyze_salary_context(text: str) -> dict:
    """
    Detect role from text, then judge if salary is realistic.
    Returns salary analysis with context-aware scoring.
    """
    text_lower = text.lower()
    result = {
        "detected_roles": [],
        "detected_salaries": [],
        "salary_signals": [],
        "is_salary_realistic": None,
    }

    # Detect roles
    for role_key, (min_lpa, max_lpa) in ROLE_SALARY_RANGES.items():
        if re.search(r'\b' + re.escape(role_key) + r'\b', text_lower):
            result["detected_roles"].append({
                "role": role_key,
                "expected_range": f"{min_lpa}-{max_lpa} LPA"
            })

    # Detect salaries (LPA format)
    for match in re.finditer(r'(\d+(?:\.\d+)?)\s*(?:lpa|lakh|lac)\s*(?:per\s*annum|p\.?a\.?)?', text_lower):
        sal_val = float(match.group(1))
        result["detected_salaries"].append(sal_val)

    # Also detect monthly salary
    for match in re.finditer(r'(?:rs\.?|inr|₹)\s*(\d[\d,]*)\s*(?:per\s*month|p\.?m\.?|/\s*month)', text_lower):
        monthly = float(match.group(1).replace(",", ""))
        annual_lpa = (monthly * 12) / 100000
        result["detected_salaries"].append(round(annual_lpa, 1))

    if not result["detected_salaries"]:
        result["salary_signals"].append({
            "type": "warning", "weight": 0.15,
            "detail_en": "No clear salary/CTC found in offer",
            "detail_hi": "ऑफ़र में स्पष्ट सैलरी/CTC नहीं मिली",
        })
        return result

    # Compare salary against detected roles
    for sal in result["detected_salaries"]:
        if result["detected_roles"]:
            # Find the best matching role
            best_match = None
            for role_info in result["detected_roles"]:
                role_key = role_info["role"]
                min_lpa, max_lpa = ROLE_SALARY_RANGES[role_key]
                if best_match is None or abs(sal - (min_lpa + max_lpa) / 2) < abs(sal - best_match[1]):
                    best_match = (role_key, (min_lpa + max_lpa) / 2, min_lpa, max_lpa)

            if best_match:
                role_name, _, min_lpa, max_lpa = best_match
                if sal < min_lpa * 0.5:
                    result["salary_signals"].append({
                        "type": "warning", "weight": 0.2,
                        "detail_en": f"Salary {sal} LPA seems low for '{role_name}' (expected {min_lpa}-{max_lpa} LPA)",
                        "detail_hi": f"सैलरी {sal} LPA '{role_name}' के लिए कम लगती है",
                    })
                elif sal > max_lpa * 1.5:
                    # Significantly above range
                    overshoot = sal / max_lpa
                    weight = min(0.6, 0.2 + (overshoot - 1.5) * 0.15)
                    result["salary_signals"].append({
                        "type": "red_flag", "weight": weight,
                        "detail_en": f"Salary {sal} LPA is unusually high for '{role_name}' (expected max ~{max_lpa} LPA)",
                        "detail_hi": f"सैलरी {sal} LPA '{role_name}' के लिए असामान्य रूप से अधिक है",
                    })
                    result["is_salary_realistic"] = False
                else:
                    result["salary_signals"].append({
                        "type": "green_flag", "weight": 0.3,
                        "detail_en": f"Salary {sal} LPA is realistic for '{role_name}' (range {min_lpa}-{max_lpa} LPA)",
                        "detail_hi": f"सैलरी {sal} LPA '{role_name}' के लिए वास्तविक है",
                    })
                    result["is_salary_realistic"] = True
        else:
            # No role detected — use general ranges
            if sal > 50:
                result["salary_signals"].append({
                    "type": "warning", "weight": 0.35,
                    "detail_en": f"High salary ({sal} LPA) without clear senior role context",
                    "detail_hi": f"बिना स्पष्ट वरिष्ठ पद के अधिक सैलरी ({sal} LPA)",
                })
            elif sal > 100:
                result["salary_signals"].append({
                    "type": "red_flag", "weight": 0.5,
                    "detail_en": f"Extremely high salary ({sal} LPA) with no role context",
                    "detail_hi": f"बिना पद संदर्भ के अत्यधिक सैलरी ({sal} LPA)",
                })
            elif 2 <= sal <= 50:
                result["salary_signals"].append({
                    "type": "green_flag", "weight": 0.2,
                    "detail_en": f"Salary {sal} LPA appears within normal Indian range",
                    "detail_hi": f"सैलरी {sal} LPA सामान्य भारतीय रेंज में है",
                })
                result["is_salary_realistic"] = True

    return result


# =====================================================
# 7. COMPREHENSIVE SIGNAL DETECTION
# =====================================================

def detect_all_signals(text: str, pdf_meta: dict = None) -> dict:
    text_lower = text.lower()
    text_length = len(text.strip())

    signals = {
        "red_flags": [], "green_flags": [], "info_flags": [],
        "warnings": [],
        "fee_demands": [], "urgency_signals": [], "mlm_signals": [],
        "legitimate_components": [],
        # FIX #1: Soft scores (0-1 weights) per category
        "soft_scores": {
            "company_legitimacy": {"positive": 0, "negative": 0, "signals": 0},
            "salary_realism": {"positive": 0, "negative": 0, "signals": 0},
            "document_authenticity": {"positive": 0, "negative": 0, "signals": 0},
            "contact_info": {"positive": 0, "negative": 0, "signals": 0},
            "legal_compliance": {"positive": 0, "negative": 0, "signals": 0},
            "payment_demands": {"positive": 0, "negative": 0, "signals": 0},
            "hiring_process": {"positive": 0, "negative": 0, "signals": 0},
            "content_quality": {"positive": 0, "negative": 0, "signals": 0},
        }
    }

    def add_negative(category, weight, flag_en, flag_hi, flag_type="red_flag"):
        signals["soft_scores"][category]["negative"] += weight
        signals["soft_scores"][category]["signals"] += 1
        flag_list = signals["red_flags"] if flag_type == "red_flag" else signals["warnings"]
        flag_list.append({"en": flag_en, "hi": flag_hi, "weight": weight, "category": category})

    def add_positive(category, weight, flag_en, flag_hi):
        signals["soft_scores"][category]["positive"] += weight
        signals["soft_scores"][category]["signals"] += 1
        signals["green_flags"].append({"en": flag_en, "hi": flag_hi, "weight": weight, "category": category})

    def add_info(flag_en, flag_hi, category=None):
        signals["info_flags"].append({"en": flag_en, "hi": flag_hi, "category": category})

    # --- FEE DEMANDS ---
    for pattern, weight, label in SCAM_FEE_PATTERNS:
        if re.search(pattern, text_lower):
            signals["fee_demands"].append(label)
            add_negative("payment_demands", weight, f"Payment demand: {label}", f"भुगतान की मांग: {label}")

    # --- URGENCY ---
    for pattern, weight, label in URGENCY_PATTERNS:
        if re.search(pattern, text_lower):
            signals["urgency_signals"].append(label)
            add_negative("hiring_process", weight, f"Urgency: {label}", f"जल्दबाज़ी: {label}")

    # --- MLM ---
    for pattern, weight, label in MLM_PATTERNS:
        if re.search(pattern, text_lower):
            signals["mlm_signals"].append(label)
            add_negative("company_legitimacy", weight, f"MLM indicator: {label}", f"MLM संकेत: {label}")

    # --- LEGITIMATE COMPONENTS ---
    for pattern, weight, label in LEGITIMATE_COMPONENTS:
        if re.search(pattern, text_lower):
            signals["legitimate_components"].append(label)
            add_positive("legal_compliance", weight, label, label)

    # --- WHATSAPP/TELEGRAM ---
    if re.search(r'(?:contact|reach|call).*(?:whatsapp|telegram)|(?:whatsapp|telegram).*(?:number|no\.?|id)', text_lower):
        add_negative("contact_info", 0.5, "WhatsApp/Telegram as official contact", "WhatsApp/Telegram आधिकारिक संपर्क", "warning")

    # --- ADDRESS ---
    has_address = bool(re.search(r'(registered\s*office|corporate\s*office|head\s*office|floor|tower|building|road|street|sector|plot|nagar|colony|pin\s*code|\d{6})', text_lower))
    if has_address:
        add_positive("company_legitimacy", 0.3, "Company address present", "कंपनी का पता मौजूद")
    else:
        add_negative("company_legitimacy", 0.25, "No company address", "कंपनी का पता नहीं", "warning")

    # --- DOCUMENT LENGTH ---
    if text_length < 200:
        add_negative("document_authenticity", 0.4, "Very short offer letter", "बहुत छोटा ऑफ़र लेटर", "warning")
    elif text_length < 500:
        add_negative("document_authenticity", 0.15, "Short offer letter", "छोटा ऑफ़र लेटर", "warning")
    elif text_length > 800:
        add_positive("document_authenticity", 0.3, "Detailed offer letter", "विस्तृत ऑफ़र लेटर")

    # --- GRAMMAR QUALITY ---
    excl_count = text.count('!')
    caps_words = len(re.findall(r'\b[A-Z]{4,}\b', text))
    if excl_count > 8:
        add_negative("content_quality", 0.4, f"Excessive exclamation marks ({excl_count})", f"अत्यधिक विस्मयादिबोधक चिह्न ({excl_count})")
    elif excl_count > 4:
        add_negative("content_quality", 0.2, f"Many exclamation marks ({excl_count})", f"कई विस्मयादिबोधक चिह्न ({excl_count})", "warning")
    if caps_words > 10:
        add_negative("content_quality", 0.3, f"Excessive ALL CAPS ({caps_words} words)", f"बहुत ज़्यादा बड़े अक्षर ({caps_words})")

    # --- SELECTION PROCESS ---
    has_selection = bool(re.search(r'(interview|selection\s*process|assessment|test|aptitude|hr\s*round|technical\s*round|shortlisted|selected)', text_lower))
    if has_selection:
        add_positive("hiring_process", 0.3, "Interview/selection process mentioned", "साक्षात्कार/चयन प्रक्रिया का उल्लेख")
    else:
        add_info("No interview/selection process mentioned", "साक्षात्कार प्रक्रिया का उल्लेख नहीं", "hiring_process")

    # --- AADHAAR/PAN URGENCY ---
    if re.search(r'(send|submit|share|provide).{0,30}(aadhaar|aadhar|pan\s*card|bank\s*account)', text_lower):
        if re.search(r'(before\s*joining|immediately|right\s*now|within\s*\d+\s*hour)', text_lower):
            add_negative("hiring_process", 0.5, "Urgent document demand before joining", "जॉइनिंग से पहले तुरंत दस्तावेज़ मांगे")

    # --- SIGNATURE ---
    has_sig = bool(re.search(r'(signature|signed|authorized\s*signatory|for\s*and\s*on\s*behalf|sd/\-|digitally\s*signed|regards|sincerely)', text_lower))
    if has_sig:
        add_positive("document_authenticity", 0.2, "Signature/sign-off present", "हस्ताक्षर मौजूद")
    else:
        add_info("No signature found", "हस्ताक्षर नहीं मिला", "document_authenticity")

    # --- BOND (neutral) ---
    if re.search(r'(service\s*bond|service\s*agreement|bond\s*period)', text_lower):
        add_info("Service bond mentioned (normal in Indian IT)", "सर्विस बॉन्ड (IT में सामान्य)", "legal_compliance")

    # --- CRYPTO/WEB3 ---
    if re.search(r'(crypto|web3|blockchain|defi|nft|token)', text_lower):
        if not re.search(r'(cin|registration|incorporated|llp|pvt\s*ltd|private\s*limited)', text_lower):
            add_negative("company_legitimacy", 0.45, "Crypto/Web3 without registration", "क्रिप्टो/Web3 बिना पंजीकरण")

    # --- GOVT JOB SCAM ---
    if re.search(r'(sarkari|government\s*job|govt\s*job|psu.*recruitment|central\s*govt)', text_lower):
        if not re.search(r'(upsc|ssc|ibps|rrb|nta|staff\s*selection|public\s*service)', text_lower):
            add_negative("company_legitimacy", 0.6, "Govt job claim without exam/board", "सरकारी नौकरी बिना परीक्षा/बोर्ड")

    # --- FOREIGN JOB SCAM PATTERNS ---
    foreign_scam_total = 0
    for pattern, weight, label in FOREIGN_JOB_SCAM_PATTERNS:
        if re.search(pattern, text_lower):
            foreign_scam_total += weight
            add_negative("hiring_process", weight, f"Foreign job scam signal: {label}", f"विदेशी नौकरी धोखाधड़ी संकेत: {label}")

    # If multiple foreign scam signals found, compound the effect
    if foreign_scam_total >= 1.5:
        add_negative("company_legitimacy", 0.5, "Multiple foreign job scam indicators detected", "कई विदेशी नौकरी धोखाधड़ी संकेत मिले")
        add_negative("payment_demands", 0.4, "Foreign job with expense demands pattern", "विदेशी नौकरी खर्च मांग पैटर्न")

    # --- PDF METADATA ---
    if pdf_meta:
        for sig_tuple in pdf_meta.get("signals", []):
            sig_type, sig_text, sig_weight = sig_tuple
            if sig_type == "warning":
                add_negative("document_authenticity", sig_weight, sig_text, sig_text, "warning")
            elif sig_type == "positive":
                add_positive("document_authenticity", sig_weight, sig_text, sig_text)
            else:
                add_info(sig_text, sig_text, "document_authenticity")

    return signals


# =====================================================
# 8. SOFT TRUST SCORE CALCULATOR (FIX #1)
# =====================================================

# Category weights for final trust score
CATEGORY_WEIGHTS = {
    "payment_demands": 0.25,
    "company_legitimacy": 0.20,
    "contact_info": 0.15,
    "salary_realism": 0.12,
    "hiring_process": 0.10,
    "legal_compliance": 0.08,
    "document_authenticity": 0.05,
    "content_quality": 0.05,
}


def calculate_trust_score(
    ai_analysis: dict,
    rule_signals: dict,
    domain_analysis: dict,
    salary_analysis: dict,
    pdf_meta: dict = None,
) -> dict:
    """
    FIX #1: Soft scoring — no hard caps.
    Each category gets a 0-100 score based on weighted positive/negative signals.
    Final trust score is a weighted average across categories.

    FIX #4: Returns confidence level too.
    """

    category_scores = {}

    for cat, weight in CATEGORY_WEIGHTS.items():
        soft = rule_signals["soft_scores"].get(cat, {"positive": 0, "negative": 0, "signals": 0})
        pos = soft["positive"]
        neg = soft["negative"]

        # Base score starts at 65 (slight benefit of doubt)
        base = 65

        # Apply positive signals (boost trust)
        trust_boost = min(pos * 30, 35)  # Cap boost at +35

        # Apply negative signals (reduce trust)
        trust_penalty = min(neg * 35, 65)  # Cap penalty at -65

        cat_score = max(0, min(100, base + trust_boost - trust_penalty))
        category_scores[cat] = round(cat_score)

    # Integrate domain analysis into contact_info
    for ds in domain_analysis.get("domain_signals", []):
        w = ds.get("weight", 0)
        if ds["type"] == "green_flag":
            category_scores["contact_info"] = min(100, category_scores["contact_info"] + round(w * 25))
            category_scores["company_legitimacy"] = min(100, category_scores["company_legitimacy"] + round(w * 20))
        elif ds["type"] == "red_flag":
            category_scores["contact_info"] = max(0, category_scores["contact_info"] - round(w * 30))
        elif ds["type"] == "warning":
            category_scores["contact_info"] = max(0, category_scores["contact_info"] - round(w * 15))

    # Integrate salary analysis
    for ss in salary_analysis.get("salary_signals", []):
        w = ss.get("weight", 0)
        if ss["type"] == "green_flag":
            category_scores["salary_realism"] = min(100, category_scores["salary_realism"] + round(w * 25))
        elif ss["type"] == "red_flag":
            category_scores["salary_realism"] = max(0, category_scores["salary_realism"] - round(w * 35))
        elif ss["type"] == "warning":
            category_scores["salary_realism"] = max(0, category_scores["salary_realism"] - round(w * 20))

    # Integrate AI analysis (blend AI scores with rule scores)
    ai_cats = ai_analysis.get("categories", {})
    for cat in category_scores:
        ai_cat = ai_cats.get(cat, {})
        ai_score = ai_cat.get("score", None)
        if ai_score is not None:
            # 55% AI, 45% Rules
            category_scores[cat] = round(ai_score * 0.55 + category_scores[cat] * 0.45)

    # Clamp all
    for cat in category_scores:
        category_scores[cat] = max(0, min(100, category_scores[cat]))

    # Calculate weighted trust score
    trust_score = 0
    for cat, weight in CATEGORY_WEIGHTS.items():
        trust_score += category_scores.get(cat, 50) * weight
    trust_score = round(trust_score)

    # FIX #4: Calculate confidence
    total_signals = sum(
        rule_signals["soft_scores"][cat]["signals"]
        for cat in rule_signals["soft_scores"]
    )
    total_signals += len(domain_analysis.get("domain_signals", []))
    total_signals += len(salary_analysis.get("salary_signals", []))
    has_domain_check = any(d.get("check_success") for d in domain_analysis.get("domain_age_results", []))
    has_pdf_meta = pdf_meta is not None and pdf_meta.get("creator") is not None

    # Confidence calculation
    if total_signals >= 10 and (has_domain_check or has_pdf_meta):
        confidence = "high"
    elif total_signals >= 5:
        confidence = "medium"
    else:
        confidence = "low"

    return {
        "trust_score": max(0, min(100, trust_score)),
        "category_scores": category_scores,
        "confidence": confidence,
        "total_signals_analyzed": total_signals,
    }


# =====================================================
# 9. AI SYSTEM PROMPT
# =====================================================

TRUST_SCORE_SYSTEM_PROMPT = """
You are an expert document forensics engine for Indian job offer letters.

You receive: letter text + pre-detected signals from rule engine + domain checks + salary analysis + PDF metadata.

Return ONLY valid JSON:
{
  "scam_probability": 0-100,
  "categories": {
    "company_legitimacy": {"score": 0-100, "reason": {"en": "...", "hi": "..."}},
    "salary_realism": {"score": 0-100, "reason": {"en": "...", "hi": "..."}},
    "document_authenticity": {"score": 0-100, "reason": {"en": "...", "hi": "..."}},
    "contact_info": {"score": 0-100, "reason": {"en": "...", "hi": "..."}},
    "legal_compliance": {"score": 0-100, "reason": {"en": "...", "hi": "..."}},
    "payment_demands": {"score": 0-100, "reason": {"en": "...", "hi": "..."}},
    "hiring_process": {"score": 0-100, "reason": {"en": "...", "hi": "..."}},
    "content_quality": {"score": 0-100, "reason": {"en": "...", "hi": "..."}}
  },
  "verdict": {"en": "Verdict sentence", "hi": "Hindi verdict"},
  "red_flags": [{"en": "...", "hi": "..."}],
  "safe_signals": [{"en": "...", "hi": "..."}],
  "what_to_do": [{"en": "...", "hi": "..."}]
}

CATEGORY SCORES = TRUST (higher = more trustworthy):
- payment_demands: Fee demand → 5-15. No demand → 85-95.
- company_legitimacy: Known company → 85+. Unknown → 45-60. Suspicious → 15-35.
- salary_realism: Realistic for role → 80+. Slightly off → 50-65. Way off → 15-35.
- contact_info: Official email + address → 85+. Gmail startup → 50-65. Gmail big co → 20-40.
- legal_compliance: Full CTC/PF/leave → 85+. Partial → 50-65. None → 25-40.
- hiring_process: Proper interview → 80+. Unclear → 45-60. Urgency → 15-35.
- document_authenticity: Proper format → 80+. Simple → 50-65. Very short → 20-40.
- content_quality: Professional → 80+. Minor issues → 50-65. Poor → 20-40.

IMPORTANT RULES:
- DEFAULT IS GENUINE. Only flag scam with clear evidence.
- Gmail for startups is normal. Gmail for TCS/Infosys is suspicious.
- Salary must be judged against role + experience context provided.
- Service bonds are NORMAL in Indian IT (not a red flag).
- Third-party recruiters using different domains is NORMAL.
- CTC breakup with components = STRONG genuine signal.
- Red flags ONLY if scam_probability >= 50. Safe signals ONLY if < 50.
- Use the pre-detected signals seriously — they are from verified rules.
"""


# =====================================================
# 10. AI ANALYSIS
# =====================================================

def analyze_offer_letter_ai(
    extracted_text: str,
    rule_signals: dict,
    domain_analysis: dict,
    salary_analysis: dict,
    pdf_meta: dict = None,
) -> dict:
    try:
        parts = []

        # Red flags
        if rule_signals["red_flags"]:
            flags = "\n".join(f"- [{rf.get('category','?')}] (w={rf.get('weight',0)}) {rf['en']}" for rf in rule_signals["red_flags"])
            parts.append(f"RED FLAGS:\n{flags}")

        # Warnings
        if rule_signals["warnings"]:
            flags = "\n".join(f"- [{w.get('category','?')}] (w={w.get('weight',0)}) {w['en']}" for w in rule_signals["warnings"])
            parts.append(f"WARNINGS:\n{flags}")

        # Green flags
        if rule_signals["green_flags"]:
            flags = "\n".join(f"- [{gf.get('category','?')}] (w={gf.get('weight',0)}) {gf['en']}" for gf in rule_signals["green_flags"])
            parts.append(f"GREEN FLAGS:\n{flags}")

        # Legitimate components
        if rule_signals["legitimate_components"]:
            parts.append(f"LEGIT COMPONENTS ({len(rule_signals['legitimate_components'])}): {', '.join(rule_signals['legitimate_components'])}")

        # Domain analysis
        if domain_analysis["domain_signals"]:
            ds_str = "\n".join(f"- [{d['type']}] (w={d.get('weight',0)}) {d['detail_en']}" for d in domain_analysis["domain_signals"])
            parts.append(f"DOMAIN ANALYSIS:\n{ds_str}")

        # Domain age
        for da in domain_analysis.get("domain_age_results", []):
            if da.get("check_success"):
                parts.append(f"DOMAIN AGE: {da['domain']} — {da.get('age_days', '?')} days old, registrar: {da.get('registrar', '?')}")

        # Salary context
        if salary_analysis.get("detected_roles"):
            roles_str = ", ".join(f"{r['role']} ({r['expected_range']})" for r in salary_analysis["detected_roles"])
            parts.append(f"DETECTED ROLES: {roles_str}")
        if salary_analysis.get("salary_signals"):
            sal_str = "\n".join(f"- [{s['type']}] (w={s.get('weight',0)}) {s['detail_en']}" for s in salary_analysis["salary_signals"])
            parts.append(f"SALARY ANALYSIS:\n{sal_str}")

        # Company context
        parts.append(f"COMPANY CONTEXT: known_company={domain_analysis.get('is_known_company')}, startup_likely={domain_analysis.get('is_startup_likely')}")

        # PDF meta
        if pdf_meta:
            parts.append(f"PDF: Creator={pdf_meta.get('creator')}, Editable={pdf_meta.get('is_editable')}, Logo={pdf_meta.get('has_images')}, Pages={pdf_meta.get('page_count')}, Size={pdf_meta.get('file_size_kb')}KB")

        context = "\n\n".join(parts) if parts else "No pre-detected signals."

        prompt = f"""Analyze this Indian job offer letter.

CONTENT:
{extracted_text[:6000]}

ANALYSIS CONTEXT:
{context}

Use ALL context to give accurate category scores. Pay attention to signal weights."""

        response = client.chat.completions.create(
            model=os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
            messages=[
                {"role": "system", "content": TRUST_SCORE_SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.1,
        )
        return json.loads(response.choices[0].message.content)

    except Exception as e:
        print(f"AI ERROR: {e}\n{traceback.format_exc()}")
        return _empty_ai_result()


def analyze_offer_letter_pdf_vision(file_bytes: bytes) -> dict:
    try:
        import fitz
        doc = fitz.open(stream=file_bytes, filetype="pdf")
        all_results = []
        for i, page in enumerate(doc):
            if i >= 3:
                break
            pix = page.get_pixmap(dpi=150)
            img_b64 = base64.b64encode(pix.tobytes("png")).decode()
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": TRUST_SCORE_SYSTEM_PROMPT},
                    {"role": "user", "content": [
                        {"type": "text", "text": f"Analyze page {i+1} visually. Check letterhead, formatting, logos, stamps, signatures, and content."},
                        {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{img_b64}"}}
                    ]}
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
            )
            all_results.append(json.loads(response.choices[0].message.content))
        return max(all_results, key=lambda x: x.get("scam_probability", 0)) if all_results else _empty_ai_result()
    except Exception as e:
        print(f"VISION ERROR: {e}")
        return _empty_ai_result()


# =====================================================
# 11. FULL PIPELINE
# =====================================================

def run_full_analysis(extracted_text: str, file_bytes: bytes = None, file_type: str = "pdf") -> dict:
    """Single entry point. Returns complete Trust Score response."""

    # Layer 1: PDF metadata
    pdf_meta = extract_pdf_metadata(file_bytes) if file_bytes and file_type == "pdf" else None

    # Layer 2: Domain & email analysis (with external WHOIS)
    domain_analysis = analyze_domains_in_text(extracted_text)

    # Layer 3: Company online presence (LinkedIn + Google)
    company_name = extract_company_name(extracted_text)
    company_presence = check_company_online_presence(company_name) if company_name else {
        "company_name": "", "linkedin_found": False, "check_success": False, "signal": None
    }

    # Inject company presence signal into domain analysis
    if company_presence.get("signal"):
        sig_type, sig_text, sig_weight = company_presence["signal"]
        domain_analysis["domain_signals"].append({
            "type": sig_type, "weight": sig_weight,
            "detail_en": sig_text,
            "detail_hi": sig_text,
        })

    # Layer 4: Context-based salary check
    salary_analysis = analyze_salary_context(extracted_text)

    # Layer 5: Rule-based signals
    rule_signals = detect_all_signals(extracted_text, pdf_meta)

    # Layer 6: AI analysis (gets all context)
    ai_result = analyze_offer_letter_ai(extracted_text, rule_signals, domain_analysis, salary_analysis, pdf_meta)

    # Layer 7: Calculate soft trust score
    score_result = calculate_trust_score(ai_result, rule_signals, domain_analysis, salary_analysis, pdf_meta)

    trust_score = score_result["trust_score"]
    confidence = score_result["confidence"]

    # Verdict
    if trust_score >= 70:
        verdict = "LIKELY GENUINE"
    elif trust_score >= 50:
        verdict = "NEEDS VERIFICATION"
    else:
        verdict = "HIGH RISK SCAM"

    # Merge flags (deduplicated)
    seen = set()
    all_red, all_safe = [], []

    if trust_score < 50:
        for rf in rule_signals.get("red_flags", []) + rule_signals.get("warnings", []) + ai_result.get("red_flags", []):
            key = rf.get("en", "")
            if key and key not in seen:
                all_red.append({"en": key, "hi": rf.get("hi", key)})
                seen.add(key)
    if trust_score >= 50:
        for sf in rule_signals.get("green_flags", []) + ai_result.get("safe_signals", []):
            key = sf.get("en", "")
            if key and key not in seen:
                all_safe.append({"en": key, "hi": sf.get("hi", key)})
                seen.add(key)

    # Build category details
    categories = {}
    ai_cats = ai_result.get("categories", {})
    for cat in CATEGORY_WEIGHTS:
        ai_cat = ai_cats.get(cat, {})
        reason = ai_cat.get("reason", {"en": "Analysis not available", "hi": "विश्लेषण उपलब्ध नहीं"}) if isinstance(ai_cat, dict) else {"en": "Analysis not available", "hi": "विश्लेषण उपलब्ध नहीं"}
        categories[cat] = {
            "score": score_result["category_scores"].get(cat, 50),
            "reason": reason,
        }

    return {
        "trust_score": trust_score,
        "confidence": confidence,
        "verdict": verdict,
        "verdict_detail": ai_result.get("verdict", {}),
        "categories": categories,
        "red_flags": all_red,
        "safe_signals": all_safe,
        "info_flags": [{"en": i["en"], "hi": i["hi"]} for i in rule_signals.get("info_flags", [])],
        "what_to_do": ai_result.get("what_to_do", []),
        "analysis_info": {
            "engine": "TRUST SCORE v3.0",
            "file_type": file_type.upper(),
            "confidence": confidence,
            "total_signals": score_result["total_signals_analyzed"],
            "layers": ["pdf_metadata", "domain_whois", "company_presence", "salary_context", "rule_engine", "ai_analysis", "soft_scoring"],
            "signals_summary": {
                "red_flags": len(rule_signals["red_flags"]),
                "warnings": len(rule_signals["warnings"]),
                "green_flags": len(rule_signals["green_flags"]),
                "fee_demands": len(rule_signals["fee_demands"]),
                "legit_components": len(rule_signals["legitimate_components"]),
                "emails": domain_analysis["emails_found"],
                "detected_roles": [r["role"] for r in salary_analysis.get("detected_roles", [])],
                "detected_salaries": salary_analysis.get("detected_salaries", []),
                "domain_age_checked": any(d.get("check_success") for d in domain_analysis.get("domain_age_results", [])),
                "company_name_detected": company_name or None,
                "linkedin_found": company_presence.get("linkedin_found", False),
                "linkedin_url": company_presence.get("linkedin_url"),
            },
            "pdf_meta": {
                "creator": pdf_meta.get("creator"),
                "editable": pdf_meta.get("is_editable"),
                "has_logo": pdf_meta.get("has_images"),
                "pages": pdf_meta.get("page_count"),
            } if pdf_meta else None,
        }
    }


def run_vision_analysis(file_bytes: bytes) -> dict:
    ai_result = analyze_offer_letter_pdf_vision(file_bytes)
    scam_prob = int(ai_result.get("scam_probability", 50))
    trust_score = max(0, min(100, 100 - scam_prob))

    if trust_score >= 70:
        verdict = "LIKELY GENUINE"
    elif trust_score >= 50:
        verdict = "NEEDS VERIFICATION"
    else:
        verdict = "HIGH RISK SCAM"

    return {
        "trust_score": trust_score,
        "confidence": "low",  # Vision-only = low confidence
        "verdict": verdict,
        "verdict_detail": ai_result.get("verdict", {}),
        "categories": ai_result.get("categories", {}),
        "red_flags": ai_result.get("red_flags", []) if trust_score < 50 else [],
        "safe_signals": ai_result.get("safe_signals", []) if trust_score >= 50 else [],
        "info_flags": [],
        "what_to_do": ai_result.get("what_to_do", []),
        "analysis_info": {
            "engine": "VISION TRUST SCORE v3.0",
            "confidence": "low",
            "layers": ["vision_ai", "soft_scoring"],
        }
    }


def _empty_ai_result():
    return {
        "scam_probability": 50, "categories": {},
        "verdict": {"en": "Analysis could not be completed.", "hi": "विश्लेषण पूरा नहीं हो सका।"},
        "red_flags": [], "safe_signals": [], "what_to_do": [],
    }

import re
from app.services.ai_engine import call_ai_analysis
from app.services.db_service import save_scan
from app.core.database import db

# ======================================
# KNOWN BANK HANDLES
# ======================================
VALID_BANK_HANDLES = {
    # ===== UPI APPS =====
    "ybl": "PhonePe",
    "ibl": "PhonePe",
    "axl": "PhonePe",
    "okaxis": "Google Pay",
    "okicici": "Google Pay",
    "oksbi": "Google Pay",
    "okhdfcbank": "Google Pay",
    "paytm": "Paytm",
    "ptyes": "Paytm",
    "ptsbi": "Paytm",
    "pthdfc": "Paytm",
    "ptaxis": "Paytm",
    "upi": "BHIM UPI",
    "bhim": "BHIM",
    "apl": "Amazon Pay",
    "yapl": "Amazon Pay",
    "amazon": "Amazon Pay",
    "jupiteraxis": "Jupiter",
    "fifederal": "Fi Money",
    "fi": "Fi Money",
    "slicepay": "Slice",
    "slice": "Slice",
    "freecharge": "FreeCharge",
    "fc": "FreeCharge",
    "mobikwik": "MobiKwik",
    "mbk": "MobiKwik",
    "ikwik": "MobiKwik",
    "niyoicici": "Niyo",
    "niyo": "Niyo",
    "cred": "CRED",
    "credpay": "CRED",
    "navi": "Navi",
    "naviaxis": "Navi",
    "bajaj": "Bajaj Pay",
    "bjaj": "Bajaj Pay",
    "zoho": "Zoho",
    "zohopay": "Zoho",
    "supersbi": "Super Money",
    "super": "Super Money",
    "tapicici": "Tata Pay",
    "tapaxis": "Tata Pay",
    "tata": "Tata Pay",
    "tataneu": "Tata Neu",
    "postpay": "India Post Payments Bank",
    "ippbonline": "India Post Payments Bank",

    # ===== PUBLIC SECTOR BANKS =====
    "sbi": "State Bank of India",
    "sbipay": "SBI",
    "upisbi": "SBI",
    "centralbank": "Central Bank of India",
    "cbin": "Central Bank of India",
    "cnrb": "Canara Bank",
    "canarabank": "Canara Bank",
    "punb": "Punjab National Bank",
    "pnb": "Punjab National Bank",
    "uboi": "Union Bank of India",
    "unionbank": "Union Bank of India",
    "boi": "Bank of India",
    "bankofindia": "Bank of India",
    "bob": "Bank of Baroda",
    "bankofbaroda": "Bank of Baroda",
    "barodampay": "Bank of Baroda",
    "mahb": "Bank of Maharashtra",
    "bankofmaharashtra": "Bank of Maharashtra",
    "iob": "Indian Overseas Bank",
    "indianoverseas": "Indian Overseas Bank",
    "andb": "Andhra Bank",
    "syndicatebank": "Syndicate Bank",
    "allbank": "Allahabad Bank",
    "ucobibank": "UCO Bank",
    "uco": "UCO Bank",
    "denabank": "Dena Bank",
    "vijayabank": "Vijaya Bank",
    "idbi": "IDBI Bank",
    "idbipay": "IDBI Bank",
    "psb": "Punjab & Sind Bank",

    # ===== PRIVATE SECTOR BANKS =====
    "icici": "ICICI Bank",
    "pticicici": "ICICI (Paytm)",
    "icicibank": "ICICI Bank",
    "icicipay": "ICICI Bank",
    "hdfc": "HDFC Bank",
    "hdfcbank": "HDFC Bank",
    "axisbank": "Axis Bank",
    "axis": "Axis Bank",
    "axisgo": "Axis Bank",
    "kotak": "Kotak Mahindra Bank",
    "kotakbank": "Kotak Mahindra Bank",
    "kmbl": "Kotak Mahindra Bank",
    "indus": "IndusInd Bank",
    "indusind": "IndusInd Bank",
    "yesbank": "Yes Bank",
    "yesbankltd": "Yes Bank",
    "rbl": "RBL Bank",
    "rblbank": "RBL Bank",
    "fbl": "Federal Bank",
    "federalbank": "Federal Bank",
    "federal": "Federal Bank",
    "dcb": "DCB Bank",
    "dcbbank": "DCB Bank",
    "csb": "CSB Bank",
    "dlb": "Dhanlaxmi Bank",
    "karnataka": "Karnataka Bank",
    "kbl": "Karnataka Bank",
    "kvb": "Karur Vysya Bank",
    "kvbbank": "Karur Vysya Bank",
    "cityunion": "City Union Bank",
    "cubbank": "City Union Bank",
    "tmb": "Tamilnad Mercantile Bank",
    "nkgsb": "NKGSB Bank",
    "saraswat": "Saraswat Bank",
    "jsb": "Janata Sahakari Bank",
    "scb": "Standard Chartered Bank",
    "hsbc": "HSBC Bank",
    "citibank": "Citi Bank",
    "dbs": "DBS Bank",
    "dbsbank": "DBS Bank",
    "rzoicici": "Razorpay",
    "rzaxis": "Razorpay",

    # ===== SMALL FINANCE BANKS =====
    "aubank": "AU Small Finance Bank",
    "au": "AU Small Finance Bank",
    "equitas": "Equitas Small Finance Bank",
    "essfb": "Equitas Small Finance Bank",
    "ujjivan": "Ujjivan Small Finance Bank",
    "ujjivansfb": "Ujjivan Small Finance Bank",
    "suryoday": "Suryoday Small Finance Bank",
    "utkarsh": "Utkarsh Small Finance Bank",
    "fincare": "Fincare Small Finance Bank",
    "jana": "Jana Small Finance Bank",
    "janabank": "Jana Small Finance Bank",
    "northeastsfb": "North East Small Finance Bank",
    "esafbank": "ESAF Small Finance Bank",
    "capitalsfb": "Capital Small Finance Bank",

    # ===== PAYMENTS BANKS =====
    "airtel": "Airtel Payments Bank",
    "airtelpaymentsbank": "Airtel Payments Bank",
    "paytmbank": "Paytm Payments Bank",
    "postbank": "India Post Payments Bank",
    "ippb": "India Post Payments Bank",
    "fino": "Fino Payments Bank",
    "finobank": "Fino Payments Bank",
    "jio": "Jio Payments Bank",
    "jiopay": "Jio Payments Bank",
    "nsdl": "NSDL Payments Bank",

    # ===== COOPERATIVE BANKS =====
    "tjsb": "TJSB Sahakari Bank",
    "apgvbank": "AP Grameena Vikas Bank",
    "mahagramin": "Maharashtra Gramin Bank",
    "baroda": "Baroda UP Bank",
}

# ======================================
# SCAM PATTERNS
# ======================================
SCAM_PATTERNS = [
    ("kyc", 40, "KYC fraud — banks never ask for KYC via UPI"),
    ("kycupdate", 45, "KYC update fraud pattern"),
    ("refund", 35, "Refund fraud — scammers pose as refund agents"),
    ("helpdesk", 35, "Fake helpdesk — official support never asks for UPI payment"),
    ("helpline", 35, "Fake helpline pattern"),
    ("support", 30, "Fake support pattern"),
    ("customercare", 40, "Fake customer care pattern"),
    ("care", 25, "Possible fake care pattern"),
    ("prize", 40, "Lottery/prize fraud"),
    ("winner", 40, "Lottery winner fraud"),
    ("lucky", 30, "Lucky draw scam pattern"),
    ("reward", 35, "Fake reward pattern"),
    ("cashback", 30, "Fake cashback pattern"),
    ("claim", 35, "Fake claim pattern"),
    ("pmrelief", 50, "Government impersonation — PM Relief fraud"),
    ("pmcare", 50, "Government impersonation — PM Care fraud"),
    ("covid", 30, "COVID relief fraud pattern"),
    ("relief", 30, "Fake relief fund pattern"),
    ("sbihelp", 40, "SBI impersonation"),
    ("sbicare", 40, "SBI impersonation"),
    ("hdfchelp", 40, "HDFC impersonation"),
    ("paytmkyc", 50, "Paytm KYC fraud — very common scam"),
    ("paytmcare", 40, "Paytm impersonation"),
    ("googlepay", 40, "Google Pay impersonation"),
    ("phonepehelp", 40, "PhonePe impersonation"),
    ("amazon", 35, "Amazon impersonation"),
    ("flipkart", 35, "Flipkart impersonation"),
    ("irctc", 35, "IRCTC impersonation"),
    ("incometax", 40, "Income tax fraud"),
    ("taxrefund", 45, "Tax refund fraud"),
    ("uidai", 40, "UIDAI/Aadhaar impersonation"),
    ("aadhar", 35, "Aadhaar fraud pattern"),
    ("kbc", 40, "KBC lottery fraud"),
    ("jio", 30, "Jio impersonation"),
    ("airtelhelp", 35, "Airtel impersonation"),
]


# ======================================
# UPI TECHNICAL ANALYSIS
# ======================================
def analyze_upi(upi_id: str) -> dict:
    upi_id = upi_id.strip().lower()
    score = 0
    signals = []

    # Format check
    if "@" not in upi_id:
        return {
            "score": 100,
            "signals": ["Invalid UPI format — missing @"],
            "bank_name": "Unknown",
            "bank_valid": False,
            "format_valid": False
        }

    parts = upi_id.split("@")
    if len(parts) != 2:
        return {
            "score": 100,
            "signals": ["Invalid UPI format"],
            "bank_name": "Unknown",
            "bank_valid": False,
            "format_valid": False
        }

    username = parts[0]
    handle = parts[1]

    # Bank handle check
    bank_name = VALID_BANK_HANDLES.get(handle)
    if not bank_name:
        score += 30
        signals.append(f"Unknown bank handle '@{handle}' — not a recognized Indian bank")
        bank_valid = False
    else:
        bank_valid = True
        signals.append(f"Bank: {bank_name} (@{handle})")

    # Username length
    if len(username) < 3:
        score += 20
        signals.append("Very short username — suspicious")
    elif len(username) > 50:
        score += 15
        signals.append("Very long username — suspicious")

    # Scam pattern check
    for pattern, pattern_score, reason in SCAM_PATTERNS:
        if pattern in username:
            score += pattern_score
            signals.append(f"Scam pattern detected: '{pattern}' — {reason}")
            break

    # Numbers only username — possible temp account
    if username.isdigit() and len(username) < 10:
        score += 10
        signals.append("Numeric only username — possible temporary account")

    return {
        "score": min(score, 100),
        "signals": signals,
        "bank_name": bank_name or "Unknown",
        "bank_valid": bank_valid,
        "format_valid": True
    }


# ======================================
# COMMUNITY DB CHECK
# ======================================
async def check_community_reports(upi_id: str) -> dict:
    try:
        doc = await db.reported_upis.find_one({"upi_id": upi_id.lower()})
        if doc:
            return {
                "found": True,
                "reports": doc.get("reports", 0),
                "first_reported": str(doc.get("first_reported", "")),
            }
        return {"found": False, "reports": 0}
    except Exception:
        return {"found": False, "reports": 0}


# ======================================
# MAIN UPI ANALYSIS FUNCTION
# ======================================
async def analyze_upi_full(upi_id: str) -> dict:
    # Technical analysis
    tech = analyze_upi(upi_id)

    # Community reports
    community = await check_community_reports(upi_id)

    # Build technical report for AI
    community_note = (
        f"Community reported {community['reports']} times as scam"
        if community["found"]
        else "No community reports found"
    )

    technical_report = f"""
UPI ID: {upi_id}
Bank Handle: @{upi_id.split('@')[1] if '@' in upi_id else 'unknown'}
Bank Name: {tech['bank_name']}
Bank Handle Valid: {tech['bank_valid']}
Format Valid: {tech['format_valid']}
Technical Risk Score: {tech['score']}/100

PATTERN ANALYSIS:
{chr(10).join(f'- {s}' for s in tech['signals'])}

COMMUNITY REPORTS:
- {community_note}
""".strip()

    return {
        "technical_report": technical_report,
        "tech_score": tech["score"],
        "community_reports": community["reports"],
        "bank_name": tech["bank_name"],
        "bank_valid": tech["bank_valid"],
    }

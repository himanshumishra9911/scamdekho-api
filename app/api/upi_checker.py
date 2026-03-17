import re
from app.services.ai_engine import call_ai_analysis
from app.services.db_service import save_scan
from app.core.database import db

# ======================================
# KNOWN BANK HANDLES
# ======================================
VALID_BANK_HANDLES = {
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
    "upi": "Generic UPI",
    "apl": "Amazon Pay",
    "yapl": "Amazon Pay",
    "rajgovind": "BHIM",
    "sbi": "SBI",
    "icici": "ICICI",
    "hdfc": "HDFC",
    "axisbank": "Axis Bank",
    "kotak": "Kotak",
    "indus": "IndusInd",
    "fbl": "Federal Bank",
    "rbl": "RBL Bank",
    "jsb": "Janata Sahakari",
    "boi": "Bank of India",
    "centralbank": "Central Bank",
    "cbin": "Central Bank",
    "cnrb": "Canara Bank",
    "punb": "Punjab National Bank",
    "uboi": "Union Bank",
    "mahb": "Bank of Maharashtra",
    "idbi": "IDBI",
    "airtel": "Airtel Payments Bank",
    "jupiteraxis": "Jupiter",
    "fifederal": "Fi Money",
    "slicepay": "Slice",
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

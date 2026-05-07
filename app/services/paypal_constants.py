"""
PayPal Scam Detection - Shared Constants
All known scam patterns, keywords, and reference data
"""

# ═══════════════════════════════════════════════════
# OFFICIAL PAYPAL DOMAINS (Whitelist)
# ═══════════════════════════════════════════════════
OFFICIAL_PAYPAL_DOMAINS = {
    "paypal.com",
    "paypal.co.uk",
    "paypal.com.au",
    "paypal.ca",
    "paypal.de",
    "paypal.fr",
    "paypal.it",
    "paypal.es",
    "paypal.in",
    "paypal-corp.com",  # Corporate communications
    "paypalobjects.com",  # Static assets/images
    "paypal-community.com",  # Community forum
    "paypal-prepaid.com",  # Prepaid cards
    "paypal-brasil.com.br",
    "venmo.com",  # Owned by PayPal
    "xoom.com",   # Owned by PayPal
}

# ═══════════════════════════════════════════════════
# KNOWN PHISHING DOMAINS (Blacklist Pattern)
# ═══════════════════════════════════════════════════
SUSPICIOUS_DOMAIN_PATTERNS = [
    # Common typosquatting
    r"paypa1[\.-]",          # paypa1.com
    r"payp[ae]l[\.-]",       # paypel.com
    r"paypall[\.-]",         # paypall.com
    r"pay-pal[\.-]",         # pay-pal.com
    r"payp[a@]l[\.-]",       # payp@l.com
    
    # Subdomain tricks
    r"paypal[\.-].*\.(xyz|top|info|club|online|site)",
    r"paypal-.*\.(com|net|org)",
    
    # Suspicious TLDs
    r"paypal\..*\.(tk|ml|ga|cf|gq|xyz)",
    
    # Numbers/special chars in domain
    r"paypal\d+",
    r"\d+paypal",
    r"paypal-secure",
    r"paypal-verify",
    r"paypal-account",
    r"paypal-login",
    r"paypal-update",
    r"paypal-confirm",
    r"paypal-support",
    r"paypal-resolution",
    r"paypal-billing",
]

# ═══════════════════════════════════════════════════
# PHISHING KEYWORDS (Email/Message Content)
# ═══════════════════════════════════════════════════
HIGH_RISK_KEYWORDS = [
    # Urgency
    "act immediately",
    "urgent action required",
    "account will be suspended",
    "account suspended",
    "account locked",
    "account limited",
    "account on hold",
    "verify within 24 hours",
    "verify within 48 hours",
    "immediate action",
    "final notice",
    "last warning",
    
    # Threat
    "permanently closed",
    "permanently suspended",
    "legal action",
    "report to authorities",
    "frozen account",
    
    # Action requests (suspicious)
    "click here to verify",
    "click here to confirm",
    "click below to update",
    "verify your account",
    "confirm your identity",
    "update your information",
    "update your payment",
    "reactivate your account",
    "unlock your account",
    "restore access",
    
    # Money lures
    "you have received",
    "you have a payment",
    "payment pending",
    "payment received",
    "refund pending",
    "refund available",
    "claim your refund",
    "unclaimed funds",
]

MEDIUM_RISK_KEYWORDS = [
    "unusual activity",
    "suspicious activity",
    "security alert",
    "login attempt",
    "new device",
    "verify your email",
    "confirm your email",
    "billing issue",
    "payment failed",
    "transaction declined",
    "limited account access",
]

# ═══════════════════════════════════════════════════
# COMMON SCAM AMOUNTS (Invoice Scams)
# ═══════════════════════════════════════════════════
COMMON_SCAM_AMOUNTS = [
    299.99, 399.99, 499.99, 599.99, 699.99, 799.99, 899.99, 999.99,
    300.00, 400.00, 500.00, 600.00, 700.00, 800.00, 900.00, 1000.00,
    349.00, 449.00, 549.00, 649.00, 749.00, 849.00,
    # Antivirus/Tech scam amounts
    199.99, 249.99, 279.99,
    # Crypto scam amounts
    1500.00, 2000.00, 2500.00, 3000.00, 5000.00,
]

# ═══════════════════════════════════════════════════
# SUSPICIOUS PHONE NUMBER PATTERNS
# ═══════════════════════════════════════════════════
SUSPICIOUS_PHONE_PATTERNS = [
    # Toll-free numbers commonly used in scams
    r"\+?1[\s\-]?8\d{2}[\s\-]?\d{3}[\s\-]?\d{4}",  # 1-8XX numbers
    r"\+?1[\s\-]?\(?8\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{4}",
    
    # International scam numbers (common origins)
    r"\+91[\s\-]?\d{10}",   # India
    r"\+92[\s\-]?\d{10}",   # Pakistan
    r"\+234[\s\-]?\d{10}",  # Nigeria
    r"\+44[\s\-]?7\d{9}",   # UK mobile (suspicious for support)
]

# ═══════════════════════════════════════════════════
# REAL PAYPAL CONTACT INFO (For comparison)
# ═══════════════════════════════════════════════════
OFFICIAL_PAYPAL_PHONES = {
    "US": ["1-888-221-1161", "1-402-935-2050"],
    "UK": ["0800-358-7911", "0203-901-7000"],
    "AU": ["1800-073-263"],
    "CA": ["1-877-569-1116"],
}

OFFICIAL_PAYPAL_EMAILS = {
    "service@paypal.com",
    "service@intl.paypal.com",
    "donotreply@paypal.com",
    "paypal@e.paypal.com",
    "noreply@paypal.com",
    "phishing@paypal.com",  # For reporting
}

# ═══════════════════════════════════════════════════
# SCAM TYPES & DESCRIPTIONS
# ═══════════════════════════════════════════════════
SCAM_TYPES = {
    "phishing": {
        "name": "PayPal Phishing Scam",
        "description": "Fake email/website pretending to be PayPal to steal login credentials",
        "color": "red",
    },
    "fake_payment": {
        "name": "Fake Payment Notification",
        "description": "Fake email claiming you received money to lure you to fake site",
        "color": "red",
    },
    "invoice_scam": {
        "name": "PayPal Invoice Scam",
        "description": "Real PayPal invoice with fake support number for tech support scam",
        "color": "red",
    },
    "account_suspended": {
        "name": "Account Suspension Scam",
        "description": "Fake suspension threat to panic users into clicking malicious links",
        "color": "red",
    },
    "refund_scam": {
        "name": "PayPal Refund Scam",
        "description": "Fake refund offer to steal banking info or install remote access",
        "color": "orange",
    },
    "friends_family_scam": {
        "name": "Friends & Family Payment Scam",
        "description": "Scammer asks for F&F payment to bypass buyer protection",
        "color": "orange",
    },
    "overpayment_scam": {
        "name": "Overpayment Scam",
        "description": "Buyer 'accidentally' pays extra and asks for refund (chargeback fraud)",
        "color": "orange",
    },
    "shipping_scam": {
        "name": "Shipping Address Scam",
        "description": "Buyer wants you to ship to unverified address to claim non-delivery",
        "color": "orange",
    },
    "tech_support": {
        "name": "Fake Tech Support Scam",
        "description": "Fake PayPal support number leading to remote access scam",
        "color": "red",
    },
    "unknown": {
        "name": "Unknown/Suspicious",
        "description": "Pattern doesn't match known scams but shows suspicious indicators",
        "color": "yellow",
    },
}

# ═══════════════════════════════════════════════════
# RISK LEVELS
# ═══════════════════════════════════════════════════
def get_risk_level(score: float) -> dict:
    """
    Convert score 0-100 to 3-tier risk level
    Simple and clear for users
    """
    if score >= 66:
        return {
            "tier": 3,
            "level": "likely_scam",
            "label": "Likely Scam",
            "emoji": "🚨",
            "color": "red",
            "color_hex": "#DC2626",
            "bg_color_hex": "#FEE2E2",
            "border_color_hex": "#DC2626",
            "short_message": "High risk - Do NOT engage",
            "detailed_message": (
                "This shows strong indicators of being a scam. "
                "Multiple red flags detected. Avoid all interaction "
                "and report to authorities."
            ),
            "user_action": "🚫 DO NOT click links, call numbers, or share any information",
            "icon": "🚨",
        }
    elif score >= 36:
        return {
            "tier": 2,
            "level": "suspicious",
            "label": "Suspicious",
            "emoji": "⚠️",
            "color": "yellow",
            "color_hex": "#D97706",
            "bg_color_hex": "#FEF3C7",
            "border_color_hex": "#D97706",
            "short_message": "Be cautious - Verify before action",
            "detailed_message": (
                "Some red flags detected but not conclusive. "
                "Could be legitimate or a sophisticated scam. "
                "Verify through official PayPal channels before any action."
            ),
            "user_action": "⚠️ Verify by logging into PayPal directly (paypal.com)",
            "icon": "⚠️",
        }
    else:
        return {
            "tier": 1,
            "level": "likely_safe",
            "label": "Likely Safe",
            "emoji": "✅",
            "color": "green",
            "color_hex": "#059669",
            "bg_color_hex": "#D1FAE5",
            "border_color_hex": "#059669",
            "short_message": "Appears legitimate - Low risk",
            "detailed_message": (
                "No major red flags detected. This appears to be "
                "legitimate. However, always stay cautious and verify "
                "important transactions through official channels."
            ),
            "user_action": "✅ Looks safe, but stay alert as always",
            "icon": "✅",
        }


# ═══════════════════════════════════════════════════
# TIER STATISTICS (For Dashboard/Analytics)
# ═══════════════════════════════════════════════════
TIER_INFO = {
    "likely_safe": {
        "tier": 1,
        "label": "Likely Safe",
        "color": "green",
        "score_range": "0-35",
        "description": "Low risk, appears legitimate",
    },
    "suspicious": {
        "tier": 2,
        "label": "Suspicious",
        "color": "yellow",
        "score_range": "36-65",
        "description": "Some red flags, verify carefully",
    },
    "likely_scam": {
        "tier": 3,
        "label": "Likely Scam",
        "color": "red",
        "score_range": "66-100",
        "description": "High risk, do not engage",
    },
}

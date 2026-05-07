"""
PayPal Email Scam Detection Engine
Multi-layer detection for fake PayPal emails
"""
import re
from urllib.parse import urlparse
from app.services.paypal_constants import (
    OFFICIAL_PAYPAL_DOMAINS,
    OFFICIAL_PAYPAL_EMAILS,
    HIGH_RISK_KEYWORDS,
    MEDIUM_RISK_KEYWORDS,
    SUSPICIOUS_DOMAIN_PATTERNS,
    SUSPICIOUS_PHONE_PATTERNS,
)


class PayPalEmailEngine:
    """Detects fake PayPal phishing emails"""

    def analyze(
        self, email_content: str, sender: str = "", subject: str = ""
    ) -> dict:
        """
        Main analysis function
        Returns: rule-based score (0-100) + red flags + extracted data
        """
        score = 0
        red_flags = []
        analysis = {
            "sender_analysis": {},
            "content_analysis": {},
            "links_found": [],
            "phones_found": [],
            "urgency_score": 0,
        }

        # ═══════════════ Layer 1: Sender Analysis ═══════════════
        sender_score, sender_flags, sender_data = self._analyze_sender(sender)
        score += sender_score
        red_flags.extend(sender_flags)
        analysis["sender_analysis"] = sender_data

        # ═══════════════ Layer 2: Subject Analysis ═══════════════
        subject_score, subject_flags = self._analyze_subject(subject)
        score += subject_score
        red_flags.extend(subject_flags)

        # ═══════════════ Layer 3: Content Analysis ═══════════════
        content_score, content_flags, content_data = self._analyze_content(
            email_content
        )
        score += content_score
        red_flags.extend(content_flags)
        analysis["content_analysis"] = content_data

        # ═══════════════ Layer 4: Links Analysis ═══════════════
        links_score, links_flags, links_data = self._analyze_links(
            email_content
        )
        score += links_score
        red_flags.extend(links_flags)
        analysis["links_found"] = links_data

        # ═══════════════ Layer 5: Phone Numbers ═══════════════
        phone_score, phone_flags, phones = self._analyze_phones(email_content)
        score += phone_score
        red_flags.extend(phone_flags)
        analysis["phones_found"] = phones

        # ═══════════════ Layer 6: Urgency Detection ═══════════════
        urgency_score = self._detect_urgency(email_content)
        score += urgency_score * 0.5  # 50% weight
        analysis["urgency_score"] = urgency_score

        # Cap score at 100
        score = min(score, 100)

        return {
            "rule_score": round(score, 1),
            "red_flags": red_flags,
            "analysis": analysis,
        }

    # ═══════════════════════════════════════════════════
    # SENDER ANALYSIS
    # ═══════════════════════════════════════════════════
    def _analyze_sender(self, sender: str) -> tuple:
        """Analyze sender email address"""
        score = 0
        flags = []
        data = {
            "email": sender,
            "domain": "",
            "is_official_paypal": False,
            "is_known_scam_pattern": False,
        }

        if not sender:
            flags.append("⚠️ No sender information provided")
            return 10, flags, data

        # Extract domain from sender
        match = re.search(r"@([\w.-]+)", sender.lower())
        if not match:
            flags.append("❌ Invalid sender email format")
            return 30, flags, data

        domain = match.group(1)
        data["domain"] = domain

        # Check if sender claims to be PayPal
        sender_lower = sender.lower()
        claims_paypal = "paypal" in sender_lower

        # Check official PayPal emails
        if sender_lower in [e.lower() for e in OFFICIAL_PAYPAL_EMAILS]:
            data["is_official_paypal"] = True
            return 0, [], data

        # Check official PayPal domains
        is_official_domain = any(
            domain == d or domain.endswith("." + d)
            for d in OFFICIAL_PAYPAL_DOMAINS
        )

        if is_official_domain:
            data["is_official_paypal"] = True
            return 0, [], data

        # Check for typosquatting
        for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
            if re.search(pattern, domain, re.IGNORECASE):
                data["is_known_scam_pattern"] = True
                flags.append(f"🚨 Typosquatting detected: '{domain}' mimics PayPal")
                return 50, flags, data

        # Claims to be PayPal but not from PayPal domain
        if claims_paypal and not is_official_domain:
            flags.append(
                f"🚨 CRITICAL: Sender '{domain}' claims to be PayPal but is NOT an official domain"
            )
            score += 45

        # Free email service impersonating
        free_email_providers = [
            "gmail.com", "yahoo.com", "hotmail.com",
            "outlook.com", "aol.com", "mail.com", "protonmail.com"
        ]
        if domain in free_email_providers and claims_paypal:
            flags.append(
                f"🚨 Real PayPal NEVER sends from {domain}"
            )
            score += 30

        return score, flags, data

    # ═══════════════════════════════════════════════════
    # SUBJECT ANALYSIS
    # ═══════════════════════════════════════════════════
    def _analyze_subject(self, subject: str) -> tuple:
        """Analyze email subject line"""
        if not subject:
            return 0, []

        score = 0
        flags = []
        subject_lower = subject.lower()

        # High-risk subject keywords
        critical_subjects = [
            "account suspended", "account locked", "verify account",
            "unusual activity", "payment received", "you have a payment",
            "action required", "limited account", "confirm identity",
        ]

        for phrase in critical_subjects:
            if phrase in subject_lower:
                flags.append(f"⚠️ Suspicious subject: '{phrase}'")
                score += 8

        # ALL CAPS = scammy
        if subject.isupper() and len(subject) > 10:
            flags.append("⚠️ Subject in ALL CAPS (common scam tactic)")
            score += 5

        # Excessive punctuation
        if subject.count("!") >= 2 or subject.count("?") >= 2:
            flags.append("⚠️ Excessive punctuation in subject")
            score += 3

        return min(score, 25), flags

    # ═══════════════════════════════════════════════════
    # CONTENT ANALYSIS
    # ═══════════════════════════════════════════════════
    def _analyze_content(self, content: str) -> tuple:
        """Analyze email body content"""
        if not content:
            return 0, [], {}

        score = 0
        flags = []
        content_lower = content.lower()
        data = {
            "high_risk_keyword_count": 0,
            "medium_risk_keyword_count": 0,
            "matched_keywords": [],
            "has_personal_greeting": False,
            "asks_for_credentials": False,
        }

        # High-risk keywords
        for keyword in HIGH_RISK_KEYWORDS:
            if keyword in content_lower:
                data["high_risk_keyword_count"] += 1
                data["matched_keywords"].append(keyword)
                if data["high_risk_keyword_count"] <= 3:
                    flags.append(f"🚨 High-risk phrase: '{keyword}'")

        # Medium-risk keywords
        for keyword in MEDIUM_RISK_KEYWORDS:
            if keyword in content_lower:
                data["medium_risk_keyword_count"] += 1

        # Score based on keyword count
        score += min(data["high_risk_keyword_count"] * 8, 40)
        score += min(data["medium_risk_keyword_count"] * 3, 15)

        # Check for personal greeting (real PayPal uses your name)
        generic_greetings = [
            "dear customer", "dear user", "dear client",
            "dear paypal user", "dear member", "valued customer",
        ]
        for greeting in generic_greetings:
            if greeting in content_lower:
                data["has_personal_greeting"] = False
                flags.append(
                    f"⚠️ Generic greeting '{greeting}' (PayPal uses your real name)"
                )
                score += 8
                break

        # Asks for sensitive info
        sensitive_requests = [
            "ssn", "social security", "credit card number",
            "password", "pin", "mother's maiden name",
            "date of birth", "full address",
        ]
        for term in sensitive_requests:
            if term in content_lower:
                data["asks_for_credentials"] = True
                flags.append(f"🚨 CRITICAL: Asks for sensitive info ({term})")
                score += 15
                break

        # Poor grammar/spelling indicators (common in scams)
        grammar_red_flags = [
            "kindly", "do the needful", "revert back",
            "your account is on hold", "validate your account",
        ]
        for phrase in grammar_red_flags:
            if phrase in content_lower:
                flags.append(f"⚠️ Common scam phrasing: '{phrase}'")
                score += 5
                break

        return min(score, 60), flags, data

    # ═══════════════════════════════════════════════════
    # LINKS ANALYSIS
    # ═══════════════════════════════════════════════════
    def _analyze_links(self, content: str) -> tuple:
        """Find and analyze all links in email"""
        score = 0
        flags = []
        links_data = []

        # Extract URLs
        url_pattern = r'https?://[^\s<>"\'\)]+|www\.[^\s<>"\'\)]+'
        urls = re.findall(url_pattern, content)

        for url in urls[:10]:  # Limit to 10 links
            link_info = self._check_single_link(url)
            links_data.append(link_info)

            if link_info["is_suspicious"]:
                flags.append(
                    f"🚨 Suspicious link: {link_info['domain']} - {link_info['reason']}"
                )
                score += 20

        # Multiple suspicious links = higher score
        suspicious_count = sum(1 for l in links_data if l["is_suspicious"])
        if suspicious_count >= 2:
            flags.append(f"🚨 Multiple suspicious links ({suspicious_count}) detected")
            score += 10

        return min(score, 40), flags, links_data

    def _check_single_link(self, url: str) -> dict:
        """Check if single URL is suspicious"""
        try:
            if not url.startswith("http"):
                url = "http://" + url

            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove www.
            if domain.startswith("www."):
                domain = domain[4:]

            # Check official domains
            is_official = any(
                domain == d or domain.endswith("." + d)
                for d in OFFICIAL_PAYPAL_DOMAINS
            )

            if is_official:
                return {
                    "url": url,
                    "domain": domain,
                    "is_suspicious": False,
                    "reason": "Official PayPal domain",
                }

            # Check suspicious patterns
            for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
                if re.search(pattern, domain, re.IGNORECASE):
                    return {
                        "url": url,
                        "domain": domain,
                        "is_suspicious": True,
                        "reason": "Typosquatting/Fake PayPal domain",
                    }

            # Contains "paypal" but not official
            if "paypal" in domain:
                return {
                    "url": url,
                    "domain": domain,
                    "is_suspicious": True,
                    "reason": "Claims PayPal but not official domain",
                }

            # URL shorteners (often used in scams)
            shorteners = ["bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly"]
            if domain in shorteners:
                return {
                    "url": url,
                    "domain": domain,
                    "is_suspicious": True,
                    "reason": "URL shortener (hides destination)",
                }

            return {
                "url": url,
                "domain": domain,
                "is_suspicious": False,
                "reason": "External link (not PayPal)",
            }

        except Exception:
            return {
                "url": url,
                "domain": "unknown",
                "is_suspicious": True,
                "reason": "Malformed URL",
            }

    # ═══════════════════════════════════════════════════
    # PHONE ANALYSIS
    # ═══════════════════════════════════════════════════
    def _analyze_phones(self, content: str) -> tuple:
        """Detect suspicious phone numbers"""
        score = 0
        flags = []
        phones = []

        for pattern in SUSPICIOUS_PHONE_PATTERNS:
            matches = re.findall(pattern, content)
            for match in matches:
                phones.append(match)

        if phones:
            flags.append(
                f"🚨 CRITICAL: Phone number(s) found in email - "
                f"Real PayPal NEVER includes phone numbers in emails"
            )
            score = 25
            phones = list(set(phones))[:5]  # Unique, max 5

        return score, flags, phones

    # ═══════════════════════════════════════════════════
    # URGENCY DETECTION
    # ═══════════════════════════════════════════════════
    def _detect_urgency(self, content: str) -> int:
        """Detect urgency tactics"""
        urgency_phrases = [
            "immediately", "urgent", "right now", "asap",
            "within 24 hours", "within 48 hours", "today only",
            "expires", "deadline", "act now", "limited time",
            "final notice", "last chance",
        ]

        content_lower = content.lower()
        urgency_count = sum(
            1 for phrase in urgency_phrases if phrase in content_lower
        )

        if urgency_count >= 3:
            return 30
        elif urgency_count >= 2:
            return 20
        elif urgency_count >= 1:
            return 10
        return 0

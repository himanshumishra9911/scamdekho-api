"""
PayPal Invoice Scam Detection Engine
Detects fake PayPal invoices with tech support scams
"""
import re
from app.services.paypal_constants import (
    OFFICIAL_PAYPAL_DOMAINS,
    OFFICIAL_PAYPAL_EMAILS,
    OFFICIAL_PAYPAL_PHONES,
    SUSPICIOUS_PHONE_PATTERNS,
    COMMON_SCAM_AMOUNTS,
)


class PayPalInvoiceEngine:
    """Detects fake/scam PayPal invoices"""

    # Fake support keywords (scammers use these)
    FAKE_SUPPORT_KEYWORDS = [
        "call to dispute",
        "call for refund",
        "call us at",
        "contact support at",
        "call our support",
        "dispute this charge",
        "if you didn't authorize",
        "to cancel call",
        "to refund call",
        "for any query call",
        "customer support number",
        "helpline number",
        "toll free number",
        "24/7 support",
        "for assistance call",
        "billing department",
        "fraud department",
        "security department",
    ]

    # Common scam product/service descriptions
    SUSPICIOUS_DESCRIPTIONS = [
        # Antivirus/Tech scams
        "norton", "mcafee", "kaspersky", "antivirus subscription",
        "windows defender", "computer security", "pc protection",
        "malware removal", "virus protection", "security suite",
        
        # Crypto scams
        "bitcoin purchase", "crypto trading", "ethereum",
        "cryptocurrency investment", "btc transfer",
        
        # Generic scams
        "amazon prime", "amazon order", "ebay purchase",
        "geek squad", "best buy", "tech support",
        "computer repair", "technical assistance",
        "software license", "premium membership",
        
        # Subscription scams
        "annual subscription", "yearly renewal", "auto-renewal",
        "premium service", "lifetime access",
    ]

    # Generic/vague descriptions (red flag)
    GENERIC_DESCRIPTIONS = [
        "service", "subscription", "renewal", "membership",
        "premium", "annual", "yearly", "license",
        "for security", "protection", "support",
    ]

    def analyze(
        self,
        sender: str,
        amount: float,
        message: str,
        sender_name: str = "",
        invoice_number: str = "",
    ) -> dict:
        """
        Main analysis function
        Returns: rule_score (0-100) + red_flags + detailed analysis
        """
        score = 0
        red_flags = []
        analysis = {
            "sender_check": {},
            "amount_check": {},
            "description_check": {},
            "phone_check": {},
            "scam_indicators": [],
        }

        # Clean inputs
        sender = sender.strip().lower() if sender else ""
        message = message.strip() if message else ""
        sender_name = sender_name.strip() if sender_name else ""

        # ═══════════ Layer 1: Sender Analysis ═══════════
        sender_score, sender_flags, sender_data = self._analyze_sender(
            sender, sender_name
        )
        score += sender_score
        red_flags.extend(sender_flags)
        analysis["sender_check"] = sender_data

        # ═══════════ Layer 2: Amount Analysis ═══════════
        amount_score, amount_flags, amount_data = self._analyze_amount(amount)
        score += amount_score
        red_flags.extend(amount_flags)
        analysis["amount_check"] = amount_data

        # ═══════════ Layer 3: Phone Number in Message ═══════════
        phone_score, phone_flags, phone_data = self._analyze_phone_in_message(
            message
        )
        score += phone_score
        red_flags.extend(phone_flags)
        analysis["phone_check"] = phone_data

        # ═══════════ Layer 4: Description Analysis ═══════════
        desc_score, desc_flags, desc_data = self._analyze_description(message)
        score += desc_score
        red_flags.extend(desc_flags)
        analysis["description_check"] = desc_data

        # ═══════════ Layer 5: Scam Pattern Indicators ═══════════
        pattern_score, pattern_flags, indicators = self._detect_scam_patterns(
            message, amount, sender
        )
        score += pattern_score
        red_flags.extend(pattern_flags)
        analysis["scam_indicators"] = indicators

        # ═══════════ Layer 6: Combined Suspicious Behavior ═══════════
        # If phone + suspicious description + scam amount = HIGHLY suspicious
        combo_score = self._check_combo_indicators(
            phone_data, desc_data, amount_data
        )
        score += combo_score

        if combo_score > 0:
            red_flags.append(
                "🚨 CRITICAL: Multiple scam indicators combined "
                "(phone + suspicious description + scam amount)"
            )

        # Cap at 100
        score = min(score, 100)

        return {
            "rule_score": round(score, 1),
            "red_flags": red_flags,
            "analysis": analysis,
        }

    # ═══════════════════════════════════════════════════
    # SENDER ANALYSIS
    # ═══════════════════════════════════════════════════
    def _analyze_sender(self, sender: str, sender_name: str) -> tuple:
        """Analyze invoice sender"""
        score = 0
        flags = []
        data = {
            "email": sender,
            "name": sender_name,
            "domain": "",
            "is_known_scammer": False,
            "is_business": False,
            "is_random_email": False,
        }

        if not sender:
            flags.append("⚠️ No sender information")
            return 5, flags, data

        # Extract domain
        match = re.search(r"@([\w.-]+)", sender)
        if not match:
            flags.append("❌ Invalid sender email")
            return 15, flags, data

        domain = match.group(1).lower()
        data["domain"] = domain

        # Check if from PayPal (the invoice itself comes from paypal.com)
        # But the SENDER is who created the invoice
        is_paypal_email = sender in [e.lower() for e in OFFICIAL_PAYPAL_EMAILS]
        if is_paypal_email:
            return 0, [], data

        # Free email providers (suspicious for business invoices)
        free_email_providers = {
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
            "aol.com", "mail.com", "protonmail.com", "icloud.com",
            "yandex.com", "live.com", "msn.com",
        }

        if domain in free_email_providers:
            data["is_random_email"] = True
            flags.append(
                f"⚠️ Invoice sender uses free email ({domain}) - "
                "Real businesses use company email"
            )
            score += 15

        # Suspicious sender name patterns
        if sender_name:
            sender_name_lower = sender_name.lower()
            
            # Generic/suspicious names
            suspicious_names = [
                "support", "billing", "service", "customer service",
                "technical support", "tech support", "security team",
                "fraud department", "refund department", "norton support",
                "mcafee support", "amazon support", "paypal support",
                "geek squad", "windows support",
            ]
            
            for sus_name in suspicious_names:
                if sus_name in sender_name_lower:
                    flags.append(
                        f"🚨 Suspicious sender name: '{sender_name}' - "
                        "Common scam pattern"
                    )
                    score += 25
                    data["is_known_scammer"] = True
                    break

            # Random characters/numbers in name
            if re.search(r"\d{3,}", sender_name):
                flags.append(
                    f"⚠️ Sender name contains random numbers - suspicious"
                )
                score += 8

        # Check for business indicator (legit invoices usually have)
        business_indicators = [
            "ltd", "llc", "inc", "company", "corp", "limited",
            "enterprises", "solutions", "services", "group",
        ]
        if any(ind in sender_name.lower() for ind in business_indicators):
            data["is_business"] = True

        return min(score, 40), flags, data

    # ═══════════════════════════════════════════════════
    # AMOUNT ANALYSIS
    # ═══════════════════════════════════════════════════
    def _analyze_amount(self, amount: float) -> tuple:
        """Analyze invoice amount for scam patterns"""
        score = 0
        flags = []
        data = {
            "amount": amount,
            "is_common_scam_amount": False,
            "is_round_number": False,
            "is_premium_amount": False,
        }

        if amount <= 0:
            flags.append("❌ Invalid amount")
            return 5, flags, data

        # Check if amount matches common scam amounts
        # Scammers use specific amounts to seem "official"
        for scam_amount in COMMON_SCAM_AMOUNTS:
            if abs(amount - scam_amount) < 0.50:  # Within 50 cents
                data["is_common_scam_amount"] = True
                flags.append(
                    f"🚨 Amount ${amount} matches common scam pattern "
                    f"(scammers often use ${scam_amount})"
                )
                score += 15
                break

        # Round numbers ($300, $500, $1000) - suspicious
        if amount == int(amount) and amount % 100 == 0:
            data["is_round_number"] = True
            if 200 <= amount <= 5000:
                flags.append(
                    f"⚠️ Round amount ${amount} - common in scams"
                )
                score += 8

        # Premium amounts (typical scam range)
        if 199 <= amount <= 999:
            data["is_premium_amount"] = True
            score += 5

        # Very high amounts (urgency tactic)
        if amount > 1500:
            flags.append(
                f"⚠️ High amount ${amount} - creates urgency to call"
            )
            score += 10

        return min(score, 30), flags, data

    # ═══════════════════════════════════════════════════
    # PHONE NUMBER IN MESSAGE
    # ═══════════════════════════════════════════════════
    def _analyze_phone_in_message(self, message: str) -> tuple:
        """
        CRITICAL: PayPal NEVER includes phone numbers in invoices
        Any phone number = MAJOR red flag
        """
        score = 0
        flags = []
        phones_found = []
        data = {
            "phones_found": [],
            "is_real_paypal_phone": False,
            "is_suspicious_phone": False,
            "phone_country": "",
        }

        if not message:
            return 0, flags, data

        # Find ALL phone numbers (multiple patterns)
        phone_patterns = [
            r"\+?1[\s\-\.]?\(?\d{3}\)?[\s\-\.]?\d{3}[\s\-\.]?\d{4}",  # US/Canada
            r"\+?44[\s\-\.]?\d{2,4}[\s\-\.]?\d{3,4}[\s\-\.]?\d{3,4}",  # UK
            r"\+?91[\s\-\.]?\d{10}",  # India
            r"\+?\d{1,3}[\s\-\.]?\d{3,4}[\s\-\.]?\d{3,4}[\s\-\.]?\d{3,4}",  # Generic
            r"1[\s\-\.]?8\d{2}[\s\-\.]?\d{3}[\s\-\.]?\d{4}",  # 1-8XX toll-free
            r"\(\d{3}\)\s?\d{3}[\s\-]?\d{4}",  # (XXX) XXX-XXXX
        ]

        for pattern in phone_patterns:
            matches = re.findall(pattern, message)
            phones_found.extend(matches)

        # Remove duplicates and clean
        phones_found = list(set([p.strip() for p in phones_found if p.strip()]))
        data["phones_found"] = phones_found[:5]

        if phones_found:
            # ANY phone in invoice = MAJOR red flag
            flags.append(
                f"🚨 CRITICAL: {len(phones_found)} phone number(s) in invoice - "
                "PayPal NEVER includes phone numbers!"
            )
            score += 50

            # Check if it's a real PayPal phone
            all_real_phones = []
            for country_phones in OFFICIAL_PAYPAL_PHONES.values():
                all_real_phones.extend(country_phones)

            for phone in phones_found:
                clean_phone = re.sub(r"[\s\-\.\(\)]", "", phone)
                
                # Check against real PayPal phones
                for real_phone in all_real_phones:
                    real_clean = re.sub(r"[\s\-\.\(\)]", "", real_phone)
                    if clean_phone in real_clean or real_clean in clean_phone:
                        data["is_real_paypal_phone"] = True
                        break

            if not data["is_real_paypal_phone"]:
                flags.append(
                    "🚨 Phone number is NOT an official PayPal number"
                )
                score += 15
                data["is_suspicious_phone"] = True

            # Check for international suspicious patterns
            for phone in phones_found:
                if "+91" in phone:
                    data["phone_country"] = "India"
                    flags.append(
                        "⚠️ Indian phone number - common origin of tech support scams"
                    )
                    score += 10
                    break
                elif "+92" in phone:
                    data["phone_country"] = "Pakistan"
                    flags.append(
                        "⚠️ Pakistani phone number - common scam origin"
                    )
                    score += 10
                    break
                elif "+234" in phone:
                    data["phone_country"] = "Nigeria"
                    flags.append(
                        "⚠️ Nigerian phone number - high scam risk"
                    )
                    score += 15
                    break

        return min(score, 70), flags, data

    # ═══════════════════════════════════════════════════
    # DESCRIPTION ANALYSIS
    # ═══════════════════════════════════════════════════
    def _analyze_description(self, message: str) -> tuple:
        """Analyze invoice description/notes"""
        score = 0
        flags = []
        data = {
            "has_fake_support_text": False,
            "has_suspicious_product": False,
            "has_generic_description": False,
            "matched_keywords": [],
            "matched_products": [],
        }

        if not message:
            return 0, flags, data

        message_lower = message.lower()

        # Check for fake support keywords
        fake_support_count = 0
        for keyword in self.FAKE_SUPPORT_KEYWORDS:
            if keyword in message_lower:
                fake_support_count += 1
                data["matched_keywords"].append(keyword)
                if fake_support_count <= 3:
                    flags.append(
                        f"🚨 Fake support language: '{keyword}'"
                    )

        if fake_support_count > 0:
            data["has_fake_support_text"] = True
            score += min(fake_support_count * 12, 35)

        # Check for suspicious products
        suspicious_count = 0
        for product in self.SUSPICIOUS_DESCRIPTIONS:
            if product in message_lower:
                suspicious_count += 1
                data["matched_products"].append(product)
                if suspicious_count <= 2:
                    flags.append(
                        f"⚠️ Suspicious product/service: '{product}' "
                        "(common in invoice scams)"
                    )

        if suspicious_count > 0:
            data["has_suspicious_product"] = True
            score += min(suspicious_count * 10, 25)

        # Check for generic/vague descriptions
        if len(message.split()) < 5:
            data["has_generic_description"] = True
            flags.append(
                "⚠️ Very short/vague description - real invoices have details"
            )
            score += 10

        # Check for urgency in description
        urgency_words = [
            "immediately", "urgent", "asap", "right now",
            "expires today", "act fast", "limited time",
        ]
        for word in urgency_words:
            if word in message_lower:
                flags.append(
                    f"⚠️ Urgency tactic in description: '{word}'"
                )
                score += 5
                break

        return min(score, 50), flags, data

    # ═══════════════════════════════════════════════════
    # SCAM PATTERN DETECTION
    # ═══════════════════════════════════════════════════
    def _detect_scam_patterns(
        self, message: str, amount: float, sender: str
    ) -> tuple:
        """Detect specific scam patterns"""
        score = 0
        flags = []
        indicators = []

        if not message:
            return 0, [], []

        message_lower = message.lower()

        # Pattern 1: Classic Tech Support Scam
        tech_support_keywords = [
            "antivirus", "virus protection", "malware",
            "computer security", "norton", "mcafee",
        ]
        if any(kw in message_lower for kw in tech_support_keywords):
            if any(
                phone_kw in message_lower
                for phone_kw in ["call", "phone", "support number"]
            ):
                indicators.append("tech_support_scam")
                flags.append(
                    "🚨 PATTERN DETECTED: Classic Tech Support Scam"
                )
                score += 20

        # Pattern 2: Subscription Scam
        if any(
            kw in message_lower
            for kw in ["subscription", "renewal", "auto-renew"]
        ):
            if amount in COMMON_SCAM_AMOUNTS:
                indicators.append("subscription_scam")
                flags.append(
                    "🚨 PATTERN DETECTED: Fake Subscription Renewal Scam"
                )
                score += 18

        # Pattern 3: Crypto Scam
        crypto_keywords = ["bitcoin", "btc", "ethereum", "crypto"]
        if any(kw in message_lower for kw in crypto_keywords):
            indicators.append("crypto_scam")
            flags.append(
                "🚨 PATTERN DETECTED: Crypto Purchase Scam"
            )
            score += 15

        # Pattern 4: Amazon/Big Brand Impersonation
        brand_keywords = [
            "amazon prime", "amazon order", "ebay purchase",
            "geek squad", "best buy", "walmart",
        ]
        for brand in brand_keywords:
            if brand in message_lower:
                indicators.append("brand_impersonation")
                flags.append(
                    f"🚨 PATTERN DETECTED: {brand.title()} Impersonation Scam"
                )
                score += 18
                break

        # Pattern 5: Refund Scam Setup
        refund_keywords = [
            "if you didn't make this purchase",
            "to cancel this order",
            "for refund",
            "to dispute",
            "did not authorize",
        ]
        for keyword in refund_keywords:
            if keyword in message_lower:
                indicators.append("refund_scam_setup")
                flags.append(
                    f"🚨 PATTERN DETECTED: Refund Scam Setup ('{keyword}')"
                )
                score += 12
                break

        return min(score, 40), flags, indicators

    # ═══════════════════════════════════════════════════
    # COMBO INDICATORS
    # ═══════════════════════════════════════════════════
    def _check_combo_indicators(
        self, phone_data: dict, desc_data: dict, amount_data: dict
    ) -> int:
        """
        If multiple red flags combine = MUCH more likely scam
        """
        combo_count = 0

        if phone_data.get("phones_found"):
            combo_count += 1
        if desc_data.get("has_fake_support_text"):
            combo_count += 1
        if desc_data.get("has_suspicious_product"):
            combo_count += 1
        if amount_data.get("is_common_scam_amount"):
            combo_count += 1

        # Bonus score for combinations
        if combo_count >= 3:
            return 25  # Very strong indicator
        elif combo_count >= 2:
            return 15
        return 0

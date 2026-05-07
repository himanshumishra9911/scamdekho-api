"""
PayPal GPT-4o-mini Analyzer
Shared GPT layer for all 4 PayPal tools
"""
import json
import os
from openai import AsyncOpenAI

client = AsyncOpenAI(api_key=os.getenv("OPENAI_API_KEY"))


class PayPalGPTAnalyzer:
    """GPT-powered analysis for PayPal scam detection"""

    @staticmethod
    async def analyze_email(
        email_content: str,
        sender: str,
        subject: str,
        rule_score: float,
        red_flags: list,
    ) -> dict:
        """Analyze PayPal email with GPT"""
        
        prompt = f"""You are a PayPal scam detection expert. Analyze this email.

## Email Details:
**Sender:** {sender or "Unknown"}
**Subject:** {subject or "No subject"}
**Content:**
{email_content[:2000]}

## Initial Analysis:
- Rule-based score: {rule_score}/100
- Red flags found: {len(red_flags)}
{chr(10).join([f"  - {flag}" for flag in red_flags[:5]])}

## Your Task:
Analyze if this is a PayPal scam. Return JSON with:

{{
    "is_scam": true/false,
    "confidence": 0-100,
    "scam_type": "phishing|fake_payment|invoice_scam|account_suspended|refund_scam|tech_support|unknown",
    "explanation": "2-3 sentence explanation in simple English",
    "key_red_flags": ["flag 1", "flag 2", "flag 3"],
    "user_recommendations": ["action 1", "action 2", "action 3", "action 4"],
    "verdict": "One clear sentence verdict"
}}

Be decisive. PayPal NEVER:
- Asks to verify account via email links
- Sends emails from non-paypal.com domains
- Includes phone numbers in transaction emails
- Threatens immediate account closure
- Asks for password/SSN via email"""

        try:
            response = await client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert specializing in PayPal scams. Respond ONLY in valid JSON.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=600,
                response_format={"type": "json_object"},
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            print(f"GPT error: {e}")
            return PayPalGPTAnalyzer._fallback_email(rule_score)

    @staticmethod
    async def analyze_link(
        url: str,
        domain: str,
        is_paypal_domain: bool,
        rule_score: float,
        red_flags: list,
    ) -> dict:
        """Analyze suspicious PayPal link"""
        
        prompt = f"""You are a URL security expert. Analyze this PayPal-related link.

## Link Details:
**Full URL:** {url}
**Domain:** {domain}
**Is Real PayPal Domain:** {is_paypal_domain}

## Initial Analysis:
- Rule-based score: {rule_score}/100
- Red flags: {', '.join(red_flags[:5])}

## Your Task:
Analyze if this link is dangerous. Return JSON:

{{
    "is_scam": true/false,
    "confidence": 0-100,
    "scam_type": "phishing|typosquatting|fake_paypal|redirect_scam|safe|unknown",
    "explanation": "2-3 sentences",
    "key_red_flags": ["flag 1", "flag 2"],
    "user_recommendations": ["action 1", "action 2", "action 3"],
    "verdict": "One sentence verdict",
    "real_paypal_url": "https://www.paypal.com" (if user should go to real site)
}}

Real PayPal domains: paypal.com, paypal.co.uk, paypal.com.au, etc.
Anything else claiming to be PayPal is FAKE."""

        try:
            response = await client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a URL security expert. Respond ONLY in valid JSON.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=500,
                response_format={"type": "json_object"},
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            print(f"GPT error: {e}")
            return PayPalGPTAnalyzer._fallback_link(rule_score, is_paypal_domain)

    @staticmethod
    async def analyze_invoice(
        sender: str,
        amount: float,
        message: str,
        contains_phone: bool,
        rule_score: float,
        red_flags: list,
    ) -> dict:
        """Analyze PayPal invoice for scam"""
        
        prompt = f"""You are a PayPal invoice scam expert. Analyze this invoice.

## Invoice Details:
**Sender:** {sender}
**Amount:** ${amount}
**Message/Description:** {message[:1000]}
**Contains Phone Number:** {contains_phone}

## Initial Analysis:
- Rule-based score: {rule_score}/100
- Red flags: {', '.join(red_flags[:5])}

## Context:
Many scammers send REAL PayPal invoices but with fake "support" numbers.
When users call, scammers run tech support scams.

## Your Task:
Return JSON:

{{
    "is_scam": true/false,
    "confidence": 0-100,
    "scam_type": "invoice_scam|tech_support|legitimate|unknown",
    "explanation": "2-3 sentences",
    "key_red_flags": ["flag 1", "flag 2"],
    "user_recommendations": ["action 1", "action 2", "action 3", "action 4"],
    "verdict": "One sentence verdict",
    "important_note": "Specific warning if needed"
}}

RED FLAGS for invoice scams:
- Phone number in invoice description
- Generic "for security" or "antivirus" descriptions
- Unknown sender
- Round amounts (299, 499, 999)
- "Call to dispute" language"""

        try:
            response = await client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a PayPal invoice scam expert. Respond ONLY in valid JSON.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=600,
                response_format={"type": "json_object"},
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            print(f"GPT error: {e}")
            return PayPalGPTAnalyzer._fallback_invoice(rule_score)

    @staticmethod
    async def analyze_conversation(
        conversation: str,
        platform: str,
        user_role: str,
        rule_score: float,
        red_flags: list,
    ) -> dict:
        """Analyze buyer/seller conversation"""
        
        prompt = f"""You are an expert at detecting PayPal buyer/seller scams.

## Conversation Details:
**Platform:** {platform}
**User Role:** {user_role} (buyer or seller)
**Conversation:**
{conversation[:3000]}

## Initial Analysis:
- Rule-based score: {rule_score}/100
- Red flags detected: {', '.join(red_flags[:5])}

## Common Scam Patterns to Detect:
1. **Friends & Family Request** (bypasses buyer protection)
2. **Overpayment Scam** (asks for refund of "extra")
3. **Shipping Address Scam** (different/unverified address)
4. **Fake Payment Confirmation** (claims to have paid)
5. **Urgency Pressure** (rush shipping/payment)
6. **Off-Platform Communication** (move to email/SMS)
7. **Sob Stories** (emotional manipulation)
8. **Too Good Deals** (suspiciously low prices)

## Your Task:
Return JSON:

{{
    "is_scam": true/false,
    "confidence": 0-100,
    "scam_type": "friends_family_scam|overpayment_scam|shipping_scam|fake_payment|legitimate|unknown",
    "scam_stage": "initial_contact|negotiation|payment_phase|post_transaction",
    "explanation": "3-4 sentences explaining the analysis",
    "key_red_flags": ["specific quote/behavior 1", "behavior 2", "behavior 3"],
    "user_recommendations": ["action 1", "action 2", "action 3", "action 4"],
    "verdict": "One sentence verdict",
    "what_scammer_likely_wants": "Brief explanation of scammer's goal"
}}"""

        try:
            response = await client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a PayPal scam detection expert. Respond ONLY in valid JSON.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=800,
                response_format={"type": "json_object"},
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            print(f"GPT error: {e}")
            return PayPalGPTAnalyzer._fallback_conversation(rule_score)

    # ═══════════════ FALLBACKS ═══════════════
    @staticmethod
    def _fallback_email(score: float) -> dict:
        is_scam = score >= 50
        return {
            "is_scam": is_scam,
            "confidence": int(score),
            "scam_type": "phishing" if is_scam else "unknown",
            "explanation": "Analysis based on pattern matching only. AI service temporarily unavailable.",
            "key_red_flags": ["Pattern-based detection used"],
            "user_recommendations": [
                "Login to PayPal directly to verify (paypal.com)",
                "Do not click any links in the email",
                "Forward suspicious emails to phishing@paypal.com",
                "Enable 2FA on your PayPal account",
            ],
            "verdict": "Likely scam" if is_scam else "Cannot verify - check directly",
        }

    @staticmethod
    def _fallback_link(score: float, is_paypal: bool) -> dict:
        return {
            "is_scam": not is_paypal,
            "confidence": int(score),
            "scam_type": "phishing" if not is_paypal else "safe",
            "explanation": "Domain analysis completed. AI service unavailable.",
            "key_red_flags": ["Not official PayPal domain"] if not is_paypal else [],
            "user_recommendations": [
                "Always type paypal.com manually in browser",
                "Never click PayPal links in emails",
                "Verify suspicious links at safebrowsing.google.com",
            ],
            "verdict": "Suspicious link" if not is_paypal else "Appears legitimate",
            "real_paypal_url": "https://www.paypal.com",
        }

    @staticmethod
    def _fallback_invoice(score: float) -> dict:
        is_scam = score >= 50
        return {
            "is_scam": is_scam,
            "confidence": int(score),
            "scam_type": "invoice_scam" if is_scam else "unknown",
            "explanation": "Pattern-based analysis. AI service unavailable.",
            "key_red_flags": ["Suspicious patterns detected"] if is_scam else [],
            "user_recommendations": [
                "Do NOT call any phone number in the invoice",
                "Login to PayPal.com directly to view invoices",
                "Decline suspicious invoices",
                "Report to PayPal: phishing@paypal.com",
            ],
            "verdict": "Likely scam invoice" if is_scam else "Verify via PayPal directly",
            "important_note": "Real PayPal never includes phone numbers in invoices",
        }

    @staticmethod
    def _fallback_conversation(score: float) -> dict:
        is_scam = score >= 50
        return {
            "is_scam": is_scam,
            "confidence": int(score),
            "scam_type": "unknown",
            "scam_stage": "unknown",
            "explanation": "Pattern-based analysis only. AI unavailable.",
            "key_red_flags": ["Suspicious patterns detected"] if is_scam else [],
            "user_recommendations": [
                "Only use PayPal Goods & Services (never Friends & Family for purchases)",
                "Verify shipping addresses before sending items",
                "Don't ship before payment fully clears",
                "Keep all communication on the platform",
            ],
            "verdict": "Possible scam" if is_scam else "Inconclusive",
            "what_scammer_likely_wants": "Unknown - manual review recommended",
        }

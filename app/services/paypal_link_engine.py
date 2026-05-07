"""
PayPal Link/URL Scam Detection Engine
Detects fake PayPal URLs and phishing links
"""
import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse, parse_qs, unquote
from app.services.paypal_constants import (
    OFFICIAL_PAYPAL_DOMAINS,
    SUSPICIOUS_DOMAIN_PATTERNS,
)


class PayPalLinkEngine:
    """Detects fake PayPal links and phishing URLs"""

    # Common URL shorteners (often used in scams)
    URL_SHORTENERS = {
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly",
        "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
        "rb.gy", "tiny.cc", "bl.ink", "shorte.st",
    }

    # Suspicious TLDs (often used in phishing)
    SUSPICIOUS_TLDS = {
        ".xyz", ".top", ".club", ".online", ".site", ".info",
        ".tk", ".ml", ".ga", ".cf", ".gq", ".cn", ".ru",
        ".pw", ".cc", ".biz", ".loan", ".click", ".download",
        ".stream", ".racing", ".bid", ".trade", ".date",
    }

    # Known dangerous URL patterns
    DANGEROUS_PATTERNS = [
        r"paypal[\.-]?(login|signin|verify|secure|account|update|confirm|support)",
        r"paypal\.com[\.-]\w+",  # paypal.com.something
        r"\w+[\.-]paypal\.\w+",  # something-paypal.xyz
        r"paypal\d+",
        r"login[\.-]paypal",
        r"secure[\.-]paypal",
        r"my[\.-]paypal[\.-]\w+",
    ]

    def analyze(self, url: str) -> dict:
        """
        Main analysis function for a single URL
        Returns: rule_score (0-100) + red_flags + detailed analysis
        """
        score = 0
        red_flags = []
        analysis = {
            "url_info": {},
            "domain_info": {},
            "ssl_info": {},
            "redirect_info": {},
            "phishing_indicators": [],
        }

        # Clean and validate URL
        url = url.strip()
        if not url:
            return self._empty_result("Empty URL")

        # Add protocol if missing
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Remove www. prefix
            if domain.startswith("www."):
                domain = domain[4:]

            # Remove port if present
            domain = domain.split(":")[0]

        except Exception as e:
            return self._empty_result(f"Invalid URL: {str(e)}")

        analysis["url_info"] = {
            "original_url": url,
            "scheme": parsed.scheme,
            "domain": domain,
            "path": parsed.path,
            "query": parsed.query,
            "fragment": parsed.fragment,
        }

        # ═══════════ Check 1: Official Domain ═══════════
        is_official, official_check = self._check_official_domain(domain)
        analysis["domain_info"]["is_official_paypal"] = is_official

        if is_official:
            # Official domain - very likely safe
            return {
                "rule_score": 5.0,
                "red_flags": [],
                "is_paypal_domain": True,
                "analysis": {
                    **analysis,
                    "verdict_reason": "Official PayPal domain verified",
                },
            }

        # ═══════════ Check 2: HTTPS ═══════════
        if parsed.scheme != "https":
            red_flags.append(f"⚠️ Uses HTTP (not HTTPS) - insecure connection")
            score += 15

        # ═══════════ Check 3: Domain Mimics PayPal ═══════════
        mimic_score, mimic_flags = self._check_domain_mimicry(domain)
        score += mimic_score
        red_flags.extend(mimic_flags)
        analysis["domain_info"]["mimics_paypal"] = mimic_score > 0

        # ═══════════ Check 4: Dangerous Patterns ═══════════
        pattern_score, pattern_flags = self._check_dangerous_patterns(url)
        score += pattern_score
        red_flags.extend(pattern_flags)

        # ═══════════ Check 5: URL Shortener ═══════════
        if domain in self.URL_SHORTENERS:
            red_flags.append(
                f"🚨 URL shortener detected ({domain}) - hides real destination"
            )
            score += 25
            analysis["url_info"]["is_shortened"] = True

        # ═══════════ Check 6: Suspicious TLD ═══════════
        tld_score, tld_flag = self._check_suspicious_tld(domain)
        score += tld_score
        if tld_flag:
            red_flags.append(tld_flag)

        # ═══════════ Check 7: Subdomain Tricks ═══════════
        subdomain_score, subdomain_flags = self._check_subdomain_tricks(domain)
        score += subdomain_score
        red_flags.extend(subdomain_flags)

        # ═══════════ Check 8: Special Characters ═══════════
        char_score, char_flags = self._check_special_characters(domain, url)
        score += char_score
        red_flags.extend(char_flags)

        # ═══════════ Check 9: IP Address Instead of Domain ═══════════
        if self._is_ip_address(domain):
            red_flags.append(
                f"🚨 CRITICAL: Uses IP address instead of domain name"
            )
            score += 40

        # ═══════════ Check 10: URL Length ═══════════
        if len(url) > 100:
            red_flags.append(
                f"⚠️ Unusually long URL ({len(url)} chars) - common in phishing"
            )
            score += 8

        # ═══════════ Check 11: Encoded Characters ═══════════
        if "%" in parsed.path or "%" in parsed.query:
            decoded = unquote(url)
            if "paypal" in decoded.lower() and "paypal" not in url.lower():
                red_flags.append(
                    "🚨 Hides 'paypal' using URL encoding (deceptive)"
                )
                score += 30

        # ═══════════ Check 12: Domain Age (basic heuristic) ═══════════
        # Note: For real domain age check, you'd need WHOIS API
        # We'll use a basic check
        domain_parts = domain.split(".")
        if len(domain_parts[0]) > 25:  # Very long subdomain
            red_flags.append(
                "⚠️ Suspiciously long domain name"
            )
            score += 10

        # ═══════════ Check 13: Login/Verify Keywords in Path ═══════════
        path_score, path_flags = self._check_path_keywords(parsed.path)
        score += path_score
        red_flags.extend(path_flags)

        # ═══════════ Check 14: Query Parameters ═══════════
        query_score, query_flags = self._check_query_params(parsed.query)
        score += query_score
        red_flags.extend(query_flags)

        # Cap at 100
        score = min(score, 100)

        return {
            "rule_score": round(score, 1),
            "red_flags": red_flags,
            "is_paypal_domain": False,
            "analysis": analysis,
        }

    # ═══════════════════════════════════════════════════
    # CHECK FUNCTIONS
    # ═══════════════════════════════════════════════════
    def _check_official_domain(self, domain: str) -> tuple:
        """Check if domain is official PayPal"""
        for official in OFFICIAL_PAYPAL_DOMAINS:
            if domain == official or domain.endswith("." + official):
                return True, official
        return False, None

    def _check_domain_mimicry(self, domain: str) -> tuple:
        """Check if domain mimics PayPal"""
        score = 0
        flags = []

        # Direct PayPal mention but not official
        if "paypal" in domain:
            flags.append(
                f"🚨 CRITICAL: Domain '{domain}' contains 'paypal' but is NOT official"
            )
            score += 50

        # Check typosquatting patterns
        for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
            if re.search(pattern, domain, re.IGNORECASE):
                flags.append(
                    f"🚨 Typosquatting detected: '{domain}' mimics PayPal"
                )
                score += 30
                break

        # Levenshtein-like check (simple version)
        # paypa1, paypall, payp@l, etc.
        suspicious_substitutions = [
            ("paypa1", "paypal"),
            ("paypall", "paypal"),
            ("payp@l", "paypal"),
            ("payp4l", "paypal"),
            ("p4ypal", "paypal"),
            ("paypaI", "paypal"),  # Capital I instead of l
            ("paypaI", "paypal"),
        ]

        for fake, real in suspicious_substitutions:
            if fake in domain.lower():
                flags.append(
                    f"🚨 Character substitution: '{fake}' mimics 'paypal'"
                )
                score += 35
                break

        return min(score, 50), flags

    def _check_dangerous_patterns(self, url: str) -> tuple:
        """Check URL against dangerous patterns"""
        score = 0
        flags = []

        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                flags.append(
                    "🚨 URL matches known phishing pattern"
                )
                score += 25
                break

        return min(score, 30), flags

    def _check_suspicious_tld(self, domain: str) -> tuple:
        """Check if domain uses suspicious TLD"""
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                return 15, f"⚠️ Suspicious TLD '{tld}' - commonly used in phishing"
        return 0, None

    def _check_subdomain_tricks(self, domain: str) -> tuple:
        """Detect subdomain manipulation tricks"""
        score = 0
        flags = []
        parts = domain.split(".")

        # Too many subdomains
        if len(parts) > 4:
            flags.append(
                f"⚠️ Excessive subdomains ({len(parts)}) - possible phishing"
            )
            score += 10

        # PayPal as subdomain (e.g., paypal.example.com)
        if "paypal" in parts[:-2] and parts[-2] not in ["paypal"]:
            flags.append(
                f"🚨 'paypal' used as subdomain (not the actual domain) - SCAM"
            )
            score += 40

        # Numbers in unexpected places
        if any(re.match(r".*\d{3,}.*", part) for part in parts[:-1]):
            flags.append(
                "⚠️ Suspicious numbers in domain"
            )
            score += 8

        return min(score, 50), flags

    def _check_special_characters(self, domain: str, url: str) -> tuple:
        """Check for suspicious special characters"""
        score = 0
        flags = []

        # Hyphens (more than 2 = suspicious)
        hyphen_count = domain.count("-")
        if hyphen_count >= 3:
            flags.append(
                f"⚠️ Excessive hyphens in domain ({hyphen_count}) - phishing indicator"
            )
            score += 12

        # @ symbol in URL (used to hide real domain)
        if "@" in url and url.index("@") < url.index("/", 8) if "/" in url[8:] else True:
            flags.append(
                "🚨 CRITICAL: '@' symbol in URL hides real destination"
            )
            score += 40

        # Unicode/Punycode (xn--)
        if "xn--" in domain:
            flags.append(
                "🚨 CRITICAL: Punycode detected - may use lookalike characters"
            )
            score += 35

        return min(score, 50), flags

    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is actually an IP address"""
        ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
        return bool(re.match(ip_pattern, domain))

    def _check_path_keywords(self, path: str) -> tuple:
        """Check URL path for suspicious keywords"""
        score = 0
        flags = []

        if not path:
            return 0, []

        path_lower = path.lower()
        suspicious_paths = [
            "login", "signin", "verify", "secure", "account",
            "update", "confirm", "validate", "authenticate",
            "billing", "payment", "suspended",
        ]

        matches = [kw for kw in suspicious_paths if kw in path_lower]
        if matches:
            flags.append(
                f"⚠️ Suspicious keywords in URL path: {', '.join(matches[:3])}"
            )
            score += min(len(matches) * 5, 15)

        return score, flags

    def _check_query_params(self, query: str) -> tuple:
        """Check query parameters for suspicious data"""
        score = 0
        flags = []

        if not query:
            return 0, []

        query_lower = query.lower()
        
        # Sensitive params in URL (very bad)
        sensitive_params = ["password", "pwd", "ssn", "credit_card", "cvv"]
        for param in sensitive_params:
            if param in query_lower:
                flags.append(
                    f"🚨 CRITICAL: Sensitive parameter in URL ({param})"
                )
                score += 30

        # Email/login in query
        if "email=" in query_lower or "user=" in query_lower:
            flags.append(
                "⚠️ User credentials in URL (privacy risk)"
            )
            score += 10

        return min(score, 40), flags

    def _empty_result(self, reason: str) -> dict:
        """Return empty result for invalid URLs"""
        return {
            "rule_score": 0,
            "red_flags": [f"❌ {reason}"],
            "is_paypal_domain": False,
            "analysis": {"error": reason},
        }

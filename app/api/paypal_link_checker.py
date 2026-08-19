"""
PayPal Link Checker API - 3-Tier Scoring
"""
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from typing import List

from app.services.paypal_link_engine import PayPalLinkEngine
from app.services.paypal_gpt_analyzer import PayPalGPTAnalyzer
from app.services.paypal_constants import get_risk_level
from app.services.cache_service import get_cached_scan, set_cached_scan
from app.services.db_service import save_scan
from app.services.security import request_meta

router = APIRouter(
    prefix="/api/v1/paypal/link",
    tags=["PayPal Link Checker"]
)

link_engine = PayPalLinkEngine()


class LinkCheckRequest(BaseModel):
    url: str = Field(..., min_length=4, max_length=2000)


class BulkLinkCheckRequest(BaseModel):
    urls: List[str] = Field(..., min_length=1, max_length=10)


@router.post("/check")
async def check_paypal_link(data: LinkCheckRequest, request: Request):
    """🔗 Check PayPal link - Returns: Likely Safe / Suspicious / Likely Scam"""
    try:
        cache_payload = {"url": data.url}
        cached = await get_cached_scan("paypal_link", cache_payload)
        if cached:
            cached["from_cache"] = True
            return cached

        # Rule-based analysis
        rule_analysis = link_engine.analyze(data.url)
        rule_score = rule_analysis["rule_score"]
        red_flags = rule_analysis["red_flags"]
        analysis_data = rule_analysis["analysis"]
        is_paypal_domain = rule_analysis["is_paypal_domain"]

        # GPT analysis
        domain = analysis_data.get("url_info", {}).get("domain", "unknown")
        gpt_result = await PayPalGPTAnalyzer.analyze_link(
            url=data.url,
            domain=domain,
            is_paypal_domain=is_paypal_domain,
            rule_score=rule_score,
            red_flags=red_flags,
        )

        # Combined score
        gpt_score = gpt_result.get("confidence", 50)
        if is_paypal_domain:
            final_score = 5.0
        elif gpt_result.get("is_scam"):
            final_score = (rule_score * 0.4) + (gpt_score * 0.6)
        else:
            final_score = (rule_score * 0.6) + ((100 - gpt_score) * 0.4)
            final_score = min(final_score, max(rule_score, 50))

        final_score = round(min(final_score, 100), 1)

        # Get 3-tier risk
        risk = get_risk_level(final_score)

        response = {
            "status": "success",
            "tool": "PayPal Link Checker",

            # ═══════════ MAIN RESULT (3-Tier) ═══════════
            "result": {
                "tier": risk["tier"],
                "level": risk["level"],
                "label": risk["label"],
                "emoji": risk["emoji"],
                "color": risk["color"],
                "color_hex": risk["color_hex"],
                "bg_color_hex": risk["bg_color_hex"],
                "border_color_hex": risk["border_color_hex"],
                "score": final_score,
                "icon": risk["icon"],
                "short_message": risk["short_message"],
                "detailed_message": risk["detailed_message"],
                "user_action": risk["user_action"],
            },

            "summary": gpt_result.get("verdict", "Analysis complete"),
            "explanation": gpt_result.get("explanation", "URL analysis completed"),

            "is_official_paypal": is_paypal_domain,

            # ═══════════ URL ANALYSIS ═══════════
            "url_analysis": {
                "checked_url": data.url,
                "domain": domain,
                "uses_https": analysis_data.get("url_info", {}).get("scheme") == "https",
                "is_shortened": analysis_data.get("url_info", {}).get("is_shortened", False),
                "verdict": (
                    "✅ Official PayPal Domain" if is_paypal_domain
                    else "🚨 NOT a PayPal domain"
                ),
            },

            # ═══════════ RED FLAGS ═══════════
            "red_flags": {
                "count": len(red_flags),
                "critical": gpt_result.get("key_red_flags", [])[:5],
                "all": red_flags[:10],
            },

            # ═══════════ SCAM TYPE ═══════════
            "scam_type": {
                "type": gpt_result.get("scam_type", "unknown"),
                "label": (
                    "Phishing Link" if gpt_result.get("scam_type") == "phishing"
                    else "Typosquatting" if gpt_result.get("scam_type") == "typosquatting"
                    else "Fake PayPal Site" if gpt_result.get("scam_type") == "fake_paypal"
                    else "Safe Link" if is_paypal_domain
                    else "Unknown"
                ),
            },

            # ═══════════ RECOMMENDATIONS ═══════════
            "recommendations": gpt_result.get("user_recommendations", [
                "Do NOT enter login credentials on this page",
                "Always type paypal.com manually in browser",
                "If you entered details, change password immediately",
            ]),

            "safe_alternatives": {
                "real_paypal_login": "https://www.paypal.com/signin",
                "real_paypal_home": "https://www.paypal.com",
                "report_phishing": "phishing@paypal.com",
            },

            # ═══════════ SAFETY TIPS ═══════════
            "safety_tips": [
                "🔒 Always check the URL bar - should say paypal.com",
                "🔒 Look for HTTPS lock icon in browser",
                "🔒 Never login via email links",
                "🔒 Bookmark real PayPal.com",
                "🔒 Enable 2FA on your account",
            ],
        }
        await save_scan(
            "paypal_link",
            data.url,
            risk["label"],
            final_score,
            request_meta(request),
        )
        await set_cached_scan("paypal_link", cache_payload, response)
        return response

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@router.post("/bulk-check")
async def bulk_check_links(data: BulkLinkCheckRequest):
    """📦 Check multiple URLs (max 10)"""
    if len(data.urls) > 10:
        raise HTTPException(status_code=400, detail="Maximum 10 URLs allowed")

    results = []
    tier_counts = {"likely_safe": 0, "suspicious": 0, "likely_scam": 0}

    for url in data.urls:
        try:
            rule_analysis = link_engine.analyze(url)
            score = rule_analysis["rule_score"]
            risk = get_risk_level(score)

            tier_counts[risk["level"]] += 1

            results.append({
                "url": url,
                "result": {
                    "tier": risk["tier"],
                    "level": risk["level"],
                    "label": risk["label"],
                    "emoji": risk["emoji"],
                    "color": risk["color"],
                    "score": score,
                    "short_message": risk["short_message"],
                },
                "is_paypal_domain": rule_analysis["is_paypal_domain"],
                "red_flags_count": len(rule_analysis["red_flags"]),
                "top_flags": rule_analysis["red_flags"][:2],
            })
        except Exception as e:
            results.append({
                "url": url,
                "error": str(e),
            })

    return {
        "status": "success",
        "summary": {
            "total_checked": len(results),
            "likely_safe": tier_counts["likely_safe"],
            "suspicious": tier_counts["suspicious"],
            "likely_scam": tier_counts["likely_scam"],
        },
        "results": results,
    }


@router.post("/quick-check")
async def quick_check_link(data: LinkCheckRequest):
    """⚡ Quick check without GPT"""
    try:
        rule_analysis = link_engine.analyze(data.url)
        score = rule_analysis["rule_score"]
        risk = get_risk_level(score)

        return {
            "status": "success",
            "url": data.url,
            "result": {
                "tier": risk["tier"],
                "level": risk["level"],
                "label": risk["label"],
                "emoji": risk["emoji"],
                "color": risk["color"],
                "color_hex": risk["color_hex"],
                "score": score,
                "short_message": risk["short_message"],
                "user_action": risk["user_action"],
            },
            "is_paypal_domain": rule_analysis["is_paypal_domain"],
            "red_flags": rule_analysis["red_flags"][:5],
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
async def health_check():
    return {
        "status": "ok",
        "service": "PayPal Link Checker",
        "version": "2.0.0",
        "scoring_system": "3-tier (Likely Safe / Suspicious / Likely Scam)",
    }

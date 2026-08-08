# -*- coding: utf-8 -*-
"""Evidence-based payment screenshot authenticity analysis.

The model observes the screenshot; deterministic code owns the public verdict.
This separation prevents missing fields, an unfamiliar app, or suspicious payment
content from being treated as proof that the pixels were manipulated.
"""

from __future__ import annotations

import asyncio
import base64
import io
import logging
import os
from statistics import mean
from typing import Literal

from dotenv import load_dotenv
from openai import OpenAI
from PIL import Image, ImageOps, UnidentifiedImageError
from pydantic import BaseModel, Field

try:
    from pillow_heif import register_heif_opener

    register_heif_opener()
except ImportError:  # pragma: no cover - dependency is present in production
    pass

load_dotenv()
logger = logging.getLogger(__name__)

ANALYSIS_VERSION = "payment-vision-v4"
PRIMARY_MODEL = os.getenv("PAYMENT_SCREENSHOT_MODEL", "gpt-5.6-sol")
REVIEW_MODEL = os.getenv("PAYMENT_SCREENSHOT_REVIEW_MODEL", "gpt-5.6-sol")
ADJUDICATOR_MODEL = os.getenv("PAYMENT_SCREENSHOT_ADJUDICATOR_MODEL", "gpt-5.6-sol")
REVIEW_MODE = os.getenv("PAYMENT_SCREENSHOT_REVIEW_MODE", "always").strip().lower()
ADJUDICATOR_MODE = os.getenv("PAYMENT_SCREENSHOT_ADJUDICATOR_MODE", "adaptive").strip().lower()
BASE_REASONING_EFFORT = os.getenv("PAYMENT_SCREENSHOT_REASONING_EFFORT", "high")
PRIMARY_REASONING_EFFORT = os.getenv(
    "PAYMENT_SCREENSHOT_PRIMARY_REASONING_EFFORT", BASE_REASONING_EFFORT
)
REVIEW_REASONING_EFFORT = os.getenv(
    "PAYMENT_SCREENSHOT_REVIEW_REASONING_EFFORT", BASE_REASONING_EFFORT
)
ADJUDICATOR_REASONING_EFFORT = os.getenv(
    "PAYMENT_SCREENSHOT_ADJUDICATOR_REASONING_EFFORT", "xhigh"
)
ADJUDICATOR_REASONING_MODE = os.getenv(
    "PAYMENT_SCREENSHOT_ADJUDICATOR_REASONING_MODE", "standard"
).strip().lower()
IMAGE_DETAIL = os.getenv("PAYMENT_SCREENSHOT_IMAGE_DETAIL", "original")
MODEL_TIMEOUT_SECONDS = float(os.getenv("PAYMENT_SCREENSHOT_MODEL_TIMEOUT", "75"))
MAX_IMAGE_PIXELS = int(os.getenv("PAYMENT_SCREENSHOT_MAX_PIXELS", "40000000"))
MAX_ANALYSIS_VIEWS = max(1, min(3, int(os.getenv("PAYMENT_SCREENSHOT_MAX_VIEWS", "3"))))


class ExtractedFields(BaseModel):
    amount: str | None
    transaction_id: str | None
    upi_id: str | None
    recipient_name: str | None
    sender_name: str | None
    bank_name: str | None
    timestamp: str | None
    status_text: str | None


class VisualEvidence(BaseModel):
    category: Literal[
        "overlay",
        "typography",
        "alignment",
        "branding",
        "pixel_artifact",
        "replica_app",
        "transaction_data",
        "other",
    ]
    strength: Literal["weak", "moderate", "strong"]
    description: str
    location: str | None
    observed_text: str | None


class PaymentObservation(BaseModel):
    app_name: str
    app_key: str
    app_confidence: int = Field(ge=0, le=100)
    screenshot_kind: Literal[
        "payment_success",
        "payment_pending",
        "payment_failed",
        "payment_request",
        "receipt_or_history",
        "other",
        "unreadable",
    ]
    readability: Literal["clear", "partial", "unreadable"]
    payment_state: Literal["success", "pending", "failed", "request", "unknown"]
    fields: ExtractedFields
    tampering_evidence: list[VisualEvidence]
    impossible_inconsistencies: list[str]
    benign_limitations: list[str]
    content_risk_signals: list[str]
    authenticity_assessment: Literal[
        "no_evidence_of_manipulation", "uncertain", "clear_manipulation"
    ]
    fake_probability: int = Field(ge=0, le=100)
    confidence: Literal["low", "medium", "high"]
    reasons: list[str]


SYSTEM_PROMPT = """You assess whether an Indian payment screenshot was fabricated or edited. This includes a coherent screen rendered by a fake or clone payment app, not only a pasted value in a real-app screenshot.

The task is screenshot authenticity, not confirmation that money reached an account. A visually genuine screenshot can still show a failed, pending, requested, reversed, old, or fraudulent transaction. Record those facts separately.

Use only visible evidence. Payment app layouts change by app version, OS, language, theme, device size, account type, merchant flow, and A/B test. Unknown or regional apps are normal. Never invent an official layout from memory.

These are NOT tampering evidence by themselves: crop; compression; blur; missing status bar; missing UPI ID, bank, sender, reference number, date, or time; a non-12-digit or alphanumeric reference; old or future date; dark mode; unusual font caused by OS accessibility; cross-app UPI handles or branding; merchant handles; suspicious words in a name or UPI ID; or a simple/clean design.

Treat normal presentation variants as benign unless there is independent, localized evidence of editing. Examples include masked identifiers, decorative receipts, minimal share receipts, large black or white viewer margins, OS/share-sheet chrome, ads, cashback or rewards panels, and receipts embedded inside another app or image viewer. A full transaction page and a shared receipt for the same payment can look substantially different. The status-bar time may reflect when the receipt was viewed rather than when the payment happened.

Strong evidence must be specific and visible, such as a localized paste boundary, inconsistent anti-aliasing around an edited value, an impossible internal contradiction visible in two fields, or a clearly composited logo/status element. Name its location. If a benign explanation is plausible, use weak/moderate evidence or no evidence.

A fake-app screen may be internally clean and have no paste boundary. Consider replica_app evidence only when at least two independent, visible inconsistencies occur inside the payment UI, for example a stable grammatical error in a system heading plus mixed branding/component styles, or mutually incompatible app identity elements. A single typo, unfamiliar layout, missing transaction details, absent reference number, or the recipient saying money was not received is not enough. Use moderate replica_app evidence and uncertain when the combination is concerning but not decisive; use strong only when the visible combination has no plausible app-version, theme, language, accessibility, crop, compression, or OCR explanation.

When a payment receipt is forwarded inside WhatsApp, SMS, a gallery, or another viewer, treat the surrounding wrapper as context rather than part of the payment app. Inspect the embedded receipt separately and do not mistake wrapper fonts, status bars, or compression for receipt tampering.

Populate every schema field. Put possible scam context in content_risk_signals, never in tampering_evidence unless it also supports visible screenshot fabrication or editing."""


ANALYST_PROMPT = """Inspect the whole screenshot at original detail.

1. Identify the app only when supported by visible branding; otherwise use Unknown.
2. Transcribe visible fields without guessing missing text.
3. Separate payment state from screenshot authenticity.
4. Look for localized editing artifacts, impossible internal contradictions, and combinations of replica-app signals.
5. List benign limitations so they are not reused as fraud evidence.
6. Estimate fake_probability for screenshot fabrication/editing only.

Use clear_manipulation only when at least one strong, specific item exists in tampering_evidence or an impossible contradiction is directly visible."""


REPLICA_REVIEW_PROMPT = """Inspect the screenshot independently as a fake/clone payment-app specialist.

Look for combinations of internally inconsistent app identity, system wording, component families, icon geometry, spacing, duplicated elements, and transaction fields. Then try to falsify every suspected signal using app-version, OS, language, theme, merchant-flow, accessibility, crop, and compression explanations. A single typo, missing field, unfamiliar layout, or non-receipt claim is not enough. Inspect an embedded receipt separately from any chat, gallery, or SMS wrapper.

Return no_evidence_of_manipulation when there is no specific visible evidence. Return uncertain for a concerning but non-decisive combination. Return clear_manipulation only for strong, specific visible evidence."""


ADJUDICATOR_PROMPT = """Perform a fresh, independent forensic adjudication of this payment screenshot. You have not seen any other reviewer report.

First search for evidence that a fake could have introduced. Then actively try to explain each anomaly through compression, crop, app/OS version, theme, language, accessibility, merchant flow, or unreadable text. Do not assume a popular app's remembered layout is current. Prefer uncertain over clear_manipulation when evidence cannot be localized. Populate every schema field."""


VERDICT_LABELS = {
    "SAFE": {
        "en": "No clear visual evidence of screenshot manipulation was found.",
        "hi": "Screenshot में बदलाव या छेड़छाड़ का कोई स्पष्ट visual evidence नहीं मिला।",
    },
    "SUSPICIOUS": {
        "en": "Inconclusive - verify the payment in your own account.",
        "hi": "नतीजा स्पष्ट नहीं है — payment को अपने account में verify करें।",
    },
    "SCAM": {
        "en": "High risk - clear signs of screenshot manipulation were found.",
        "hi": "High risk — screenshot में छेड़छाड़ के स्पष्ट संकेत मिले हैं।",
    },
}

WHAT_TO_DO = {
    "SAFE": [
        {
            "en": "Verify the credit in your own bank or UPI app before releasing goods.",
            "hi": "Goods देने से पहले अपने bank या UPI app में credit verify करें।",
        },
        {
            "en": "A visually genuine screenshot is not proof that the payment settled.",
            "hi": "Visually genuine screenshot भी payment settle होने का proof नहीं है।",
        },
    ],
    "SUSPICIOUS": [
        {
            "en": "Do not accept this screenshot as payment proof; check your own account.",
            "hi": "इसे payment proof न मानें; अपना account check करें।",
        },
        {
            "en": "Ask the sender to show the transaction live in their UPI app.",
            "hi": "Sender से अपने UPI app में live transaction दिखाने को कहें।",
        },
        {
            "en": "Do not release goods or services until the credit is visible to you.",
            "hi": "Credit दिखने तक goods या services न दें।",
        },
    ],
    "SCAM": [
        {
            "en": "Do not accept this screenshot as payment proof.",
            "hi": "इस screenshot को payment proof न मानें।",
        },
        {
            "en": "Check your own account and preserve the chat and screenshot as evidence.",
            "hi": "अपना account check करें और chat व screenshot को evidence के रूप में रखें।",
        },
        {
            "en": "If money or goods were lost, report at cybercrime.gov.in or call 1930.",
            "hi": "नुकसान हुआ हो तो cybercrime.gov.in पर report करें या 1930 call करें।",
        },
    ],
}

HOW_TO_AVOID = [
    {
        "en": "Always confirm incoming credit in your own UPI app, bank app, or statement.",
        "hi": "Incoming credit हमेशा अपने UPI app, bank app या statement में confirm करें।",
    },
    {
        "en": "Match the amount, payer, time, and reference with your own transaction history.",
        "hi": "Amount, payer, time और reference को अपनी transaction history से match करें।",
    },
    {
        "en": "Never release goods or services based only on a screenshot.",
        "hi": "सिर्फ screenshot देखकर goods या services कभी न दें।",
    },
]


def get_client() -> OpenAI:
    return OpenAI(
        api_key=os.getenv("OPENAI_API_KEY"),
        timeout=MODEL_TIMEOUT_SECONDS,
        max_retries=1,
    )


def _prepare_image(image_bytes: bytes) -> tuple[bytes, str, tuple[int, int]]:
    """Validate pixels and convert HEIC/HEIF to a model-supported JPEG."""
    try:
        image = Image.open(io.BytesIO(image_bytes))
        image.load()
    except (UnidentifiedImageError, OSError, ValueError) as exc:
        raise ValueError("Could not decode this image. Upload a clear PNG, JPEG, WebP or HEIC file.") from exc

    width, height = image.size
    if width < 200 or height < 200:
        raise ValueError("Image dimensions are too small. Upload the full payment screen.")
    if width * height > MAX_IMAGE_PIXELS:
        raise ValueError("Image resolution is too large. Upload an image under 40 megapixels.")

    image_format = (image.format or "").upper()
    media_types = {"PNG": "image/png", "JPEG": "image/jpeg", "WEBP": "image/webp"}
    if image_format in media_types:
        return image_bytes, media_types[image_format], (width, height)

    if image_format in {"HEIC", "HEIF", "AVIF"}:
        converted = ImageOps.exif_transpose(image).convert("RGB")
        output = io.BytesIO()
        converted.save(output, format="JPEG", quality=95, optimize=True)
        return output.getvalue(), "image/jpeg", (width, height)

    raise ValueError("Unsupported decoded image format. Upload PNG, JPEG, WebP or HEIC.")


def _image_data_url(image_bytes: bytes, media_type: str) -> str:
    encoded = base64.b64encode(image_bytes).decode("ascii")
    return f"data:{media_type};base64,{encoded}"


AnalysisView = tuple[str, bytes, str]


def _encode_png(image: Image.Image) -> bytes:
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=True)
    return output.getvalue()


def _make_analysis_views(image_bytes: bytes, media_type: str) -> list[AnalysisView]:
    """Keep the full image and add overlapping native-resolution crops for tiny text."""
    views: list[AnalysisView] = [("Full screenshot", image_bytes, media_type)]
    if MAX_ANALYSIS_VIEWS == 1:
        return views

    with Image.open(io.BytesIO(image_bytes)) as image:
        image.load()
        width, height = image.size
        if height >= width * 1.45:
            crop_height = round(height * 0.62)
            crops = [
                ("Upper payment area", image.crop((0, 0, width, crop_height))),
                ("Lower details area", image.crop((0, height - crop_height, width, height))),
            ]
        elif width >= height * 1.45:
            crop_width = round(width * 0.62)
            crops = [
                ("Left payment area", image.crop((0, 0, crop_width, height))),
                ("Right payment area", image.crop((width - crop_width, 0, width, height))),
            ]
        else:
            return views

        for label, crop in crops[: MAX_ANALYSIS_VIEWS - 1]:
            views.append((label, _encode_png(crop), "image/png"))
    return views


def _run_model(
    image_views: list[AnalysisView],
    prompt: str,
    model: str,
    reasoning_effort: str,
    reasoning_mode: str = "standard",
) -> PaymentObservation:
    content: list[dict] = [{"type": "input_text", "text": prompt}]
    for label, view_bytes, view_media_type in image_views:
        content.extend(
            [
                {"type": "input_text", "text": label},
                {
                    "type": "input_image",
                    "image_url": _image_data_url(view_bytes, view_media_type),
                    "detail": IMAGE_DETAIL,
                },
            ]
        )

    request_kwargs: dict = {
        "model": model,
        "instructions": SYSTEM_PROMPT,
        "input": [
            {
                "role": "user",
                "content": content,
            }
        ],
        "text_format": PaymentObservation,
        "max_output_tokens": 2600,
        "store": False,
    }
    if model.startswith("gpt-5"):
        reasoning = {"effort": reasoning_effort}
        if reasoning_mode == "pro":
            reasoning["mode"] = "pro"
        request_kwargs["reasoning"] = reasoning

    response = get_client().responses.parse(**request_kwargs)
    if response.output_parsed is None:
        raise ValueError("The vision model did not return a usable forensic report.")
    return response.output_parsed


def _needs_review(observation: PaymentObservation) -> bool:
    if REVIEW_MODE in {"off", "false", "0", "disabled"}:
        return False
    if REVIEW_MODE == "always":
        return True
    return any(
        (
            observation.authenticity_assessment != "no_evidence_of_manipulation",
            observation.fake_probability >= 30,
            bool(observation.tampering_evidence),
            bool(observation.impossible_inconsistencies),
            observation.readability != "clear",
            observation.app_confidence < 50,
        )
    )


def _is_clean_observation(observation: PaymentObservation) -> bool:
    material_evidence = any(
        item.strength in {"moderate", "strong"} for item in observation.tampering_evidence
    )
    return all(
        (
            observation.authenticity_assessment == "no_evidence_of_manipulation",
            observation.fake_probability <= 25,
            not material_evidence,
            not observation.impossible_inconsistencies,
            observation.readability != "unreadable",
        )
    )


def _needs_adjudication(observations: list[PaymentObservation]) -> bool:
    if ADJUDICATOR_MODE in {"off", "false", "0", "disabled"}:
        return False
    if ADJUDICATOR_MODE == "always":
        return True
    return len(observations) < 2 or not all(_is_clean_observation(item) for item in observations)


def _unique_strings(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        clean = " ".join(str(value).split()).strip()
        key = clean.casefold()
        if clean and key not in seen:
            seen.add(key)
            result.append(clean)
    return result


def _merge_fields(observations: list[PaymentObservation]) -> ExtractedFields:
    merged: dict[str, str | None] = {}
    for field_name in ExtractedFields.model_fields:
        candidates = [getattr(item.fields, field_name) for item in observations]
        merged[field_name] = next((value for value in candidates if value), None)
    return ExtractedFields(**merged)


def _has_confirmed_fake_evidence(observation: PaymentObservation) -> bool:
    strong_count = sum(item.strength == "strong" for item in observation.tampering_evidence)
    return (
        observation.authenticity_assessment == "clear_manipulation"
        and (strong_count > 0 or bool(observation.impossible_inconsistencies))
        and observation.fake_probability >= 65
    )


def calibrate_observations(observations: list[PaymentObservation]) -> dict:
    """Turn independent observations into an evidence-gated public verdict."""
    if not observations:
        raise ValueError("At least one forensic observation is required.")

    evidence = [item for obs in observations for item in obs.tampering_evidence]
    strong_count = sum(item.strength == "strong" for item in evidence)
    moderate_count = sum(item.strength == "moderate" for item in evidence)
    impossible = _unique_strings(
        [item for obs in observations for item in obs.impossible_inconsistencies]
    )
    probabilities = [obs.fake_probability for obs in observations]
    average_probability = round(mean(probabilities))
    confirmed_votes = sum(_has_confirmed_fake_evidence(obs) for obs in observations)
    clean_votes = sum(_is_clean_observation(obs) for obs in observations)
    required_votes = 1 if len(observations) == 1 else (len(observations) // 2) + 1
    replica_moderate_count = sum(
        item.category == "replica_app" and item.strength == "moderate" for item in evidence
    )
    confirmed_fake = confirmed_votes >= required_votes
    credible_dissent = bool(
        confirmed_votes
        or strong_count
        or impossible
        or replica_moderate_count
        or moderate_count >= 2
    )

    if confirmed_fake:
        verdict = "SCAM"
        risk = min(98, max(70, average_probability))
    elif clean_votes >= required_votes and not credible_dissent and average_probability <= 30:
        verdict = "SAFE"
        risk = min(30, max(5, average_probability))
    else:
        verdict = "SUSPICIOUS"
        risk = min(69, max(31, average_probability))

    best_app = max(observations, key=lambda item: item.app_confidence)
    fields = _merge_fields(observations)
    limitations = _unique_strings(
        [item for obs in observations for item in obs.benign_limitations]
    )
    content_risk = _unique_strings(
        [item for obs in observations for item in obs.content_risk_signals]
    )

    if verdict == "SCAM":
        reason_text = _unique_strings(
            [item.description for item in evidence if item.strength == "strong"] + impossible
        )
    elif verdict == "SUSPICIOUS":
        reason_text = _unique_strings(
            [item.description for item in evidence if item.strength != "weak"]
            + impossible
            + ["The available visual evidence is not conclusive enough for a genuine or fake verdict."]
        )
    else:
        reason_text = ["The independent reviews found no clear, specific evidence of screenshot fabrication or editing."]

    why = [{"en": item, "hi": ""} for item in reason_text[:6]]
    visual_forensics = [
        {
            "en": item.description,
            "hi": "",
            "strength": item.strength,
            "category": item.category,
            "location": item.location,
        }
        for item in evidence[:10]
    ]

    confidence_rank = {"low": 0, "medium": 1, "high": 2}
    confidence = min(observations, key=lambda item: confidence_rank[item.confidence]).confidence
    if len(observations) > 1 and len({obs.authenticity_assessment for obs in observations}) > 1:
        confidence = "low"

    return {
        "verdict": verdict,
        "risk_percentage": risk,
        "confidence": confidence,
        "verdict_label": VERDICT_LABELS[verdict],
        "detected_app": {
            "name": best_app.app_name or "Unknown",
            "app_key": (best_app.app_key or "unknown").lower(),
            "detection_confidence": best_app.app_confidence,
        },
        "extracted_fields": fields.model_dump(),
        "payment_state": observations[0].payment_state,
        "screenshot_kind": observations[0].screenshot_kind,
        "why": why,
        "reasons": why,
        "visual_forensics": visual_forensics,
        "visual_signals": visual_forensics,
        "benign_limitations": limitations[:8],
        "content_risk_signals": content_risk[:8],
        "evidence_summary": {
            "strong": strong_count,
            "moderate": moderate_count,
            "weak": sum(item.strength == "weak" for item in evidence),
            "replica_app_moderate": replica_moderate_count,
            "impossible_inconsistencies": len(impossible),
            "review_count": len(observations),
            "clean_votes": clean_votes,
            "confirmed_fake_votes": confirmed_votes,
            "required_consensus_votes": required_votes,
        },
        "pattern_match": {
            "found": bool(strong_count or impossible),
            "match_count": strong_count + len(impossible),
        },
        "what_to_do": WHAT_TO_DO[verdict],
        "how_to_avoid": HOW_TO_AVOID,
    }


async def analyze_payment_screenshot(image_bytes: bytes) -> dict:
    prepared_bytes, media_type, dimensions = _prepare_image(image_bytes)
    image_views = _make_analysis_views(prepared_bytes, media_type)
    loop = asyncio.get_running_loop()
    observations: list[PaymentObservation] = []
    failures: list[Exception] = []
    attempted_passes = 0
    review_disabled = REVIEW_MODE in {"off", "false", "0", "disabled"}

    async def execute_pass(
        prompt: str,
        model: str,
        effort: str,
        mode: str = "standard",
    ) -> PaymentObservation:
        return await loop.run_in_executor(
            None,
            _run_model,
            image_views,
            prompt,
            model,
            effort,
            mode,
        )

    if REVIEW_MODE == "always":
        attempted_passes += 2
        initial_results = await asyncio.gather(
            execute_pass(ANALYST_PROMPT, PRIMARY_MODEL, PRIMARY_REASONING_EFFORT),
            execute_pass(REPLICA_REVIEW_PROMPT, REVIEW_MODEL, REVIEW_REASONING_EFFORT),
            return_exceptions=True,
        )
        for item in initial_results:
            if isinstance(item, BaseException):
                logger.warning("Payment screenshot ensemble pass failed: %s", item)
                failures.append(item if isinstance(item, Exception) else RuntimeError(str(item)))
            else:
                observations.append(item)
    else:
        attempted_passes += 1
        try:
            primary = await execute_pass(
                ANALYST_PROMPT, PRIMARY_MODEL, PRIMARY_REASONING_EFFORT
            )
            observations.append(primary)
        except Exception as exc:
            logger.warning("Payment screenshot primary pass failed: %s", exc)
            failures.append(exc)

        review_required = not review_disabled and (
            not observations or _needs_review(observations[0])
        )
        if review_required:
            attempted_passes += 1
            try:
                observations.append(
                    await execute_pass(
                        REPLICA_REVIEW_PROMPT,
                        REVIEW_MODEL,
                        REVIEW_REASONING_EFFORT,
                    )
                )
            except Exception as exc:
                logger.warning("Payment screenshot replica-review pass failed: %s", exc)
                failures.append(exc)

    adjudicator_performed = False
    if not review_disabled and observations and _needs_adjudication(observations):
        attempted_passes += 1
        adjudicator_performed = True
        try:
            observations.append(
                await execute_pass(
                    ADJUDICATOR_PROMPT,
                    ADJUDICATOR_MODEL,
                    ADJUDICATOR_REASONING_EFFORT,
                    ADJUDICATOR_REASONING_MODE,
                )
            )
        except Exception as exc:
            logger.warning("Payment screenshot adjudicator pass failed: %s", exc)
            failures.append(exc)

    if not observations:
        raise RuntimeError("All payment screenshot forensic passes failed") from failures[0]

    result = calibrate_observations(observations)
    if len(observations) < 2 and result["verdict"] == "SCAM":
        # A high-risk verdict is never exposed from one model report alone.
        result.update(
            {
                "verdict": "SUSPICIOUS",
                "risk_percentage": 69,
                "confidence": "low",
                "verdict_label": VERDICT_LABELS["SUSPICIOUS"],
                "what_to_do": WHAT_TO_DO["SUSPICIOUS"],
            }
        )
        result["why"].append(
            {
                "en": "Independent forensic consensus was unavailable, so a high-risk verdict was not confirmed.",
                "hi": "",
            }
        )
        result["reasons"] = result["why"]
    if failures:
        result["confidence"] = "low"
    result.update(
        {
            "analysis_version": ANALYSIS_VERSION,
            "review_performed": len(observations) > 1,
            "review_status": (
                "failed"
                if failures
                else "completed"
                if attempted_passes > 1
                else "not_required"
            ),
            "ensemble": {
                "attempted_passes": attempted_passes,
                "successful_passes": len(observations),
                "failed_passes": len(failures),
                "adjudicator_performed": adjudicator_performed,
                "analysis_views": len(image_views),
            },
            "image_dimensions": {"width": dimensions[0], "height": dimensions[1]},
        }
    )
    return result
